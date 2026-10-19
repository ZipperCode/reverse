"""Frida persistent session worker process.

Speaks bidirectional NDJSON over stdin / stdout with the TypeScript FridaSessionTool.
Isolates the control channel on private duplicated file descriptors so that target
process prints or accidental Python output do not corrupt the JSON protocol.
"""
from __future__ import annotations

import atexit
import base64
import io
import json
import os
import re
import signal
import sys
import threading
import time
import traceback
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Control channel isolation
# ---------------------------------------------------------------------------
try:
    _FRAME_FD = os.dup(sys.__stdout__.fileno())
    _RAW_STDOUT = os.fdopen(_FRAME_FD, "w", encoding="utf-8", errors="backslashreplace")
    os.dup2(sys.__stderr__.fileno(), sys.__stdout__.fileno())
except Exception:
    _RAW_STDOUT = sys.__stdout__

try:
    _CONTROL_FD = os.dup(sys.__stdin__.fileno())
    _CONTROL_IN = os.fdopen(_CONTROL_FD, "r", encoding="utf-8")
    _devnull_fd = os.open(os.devnull, os.O_RDONLY)
    os.dup2(_devnull_fd, sys.__stdin__.fileno())
    os.close(_devnull_fd)
except Exception:
    _CONTROL_IN = sys.__stdin__

_OUT_LOCK = threading.Lock()

def _send_frame(frame: dict[str, Any]) -> None:
    line = json.dumps(frame, ensure_ascii=False)
    with _OUT_LOCK:
        try:
            _RAW_STDOUT.write(line + "\n")
            _RAW_STDOUT.flush()
        except Exception:
            pass

def _send_event(kind: str, channel: str, payload: Any, raw: str | None = None, metadata: dict[str, Any] | None = None) -> None:
    now = datetime.utcnow().isoformat() + "Z"
    if raw is None:
        if isinstance(payload, (dict, list)):
            s = json.dumps(payload, ensure_ascii=False)
            raw = s if len(s) <= 32768 else s[:32768] + " [truncated]"
        else:
            s = str(payload)
            raw = s if len(s) <= 32768 else s[:32768] + " [truncated]"
    elif len(raw) > 32768:
        raw = raw[:32768] + " [truncated]"

    frame: dict[str, Any] = {
        "type": "event",
        "kind": kind,
        "channel": channel,
        "payload": payload,
        "raw": raw,
        "timestamp": now,
    }
    if metadata:
        frame["metadata"] = metadata
    _send_frame(frame)

# ---------------------------------------------------------------------------
# Global session state
# ---------------------------------------------------------------------------
_device: Any = None
_session: Any = None
_script: Any = None
_is_spawned: bool = False
_is_resumed: bool = False
_target_pid: int | None = None
_is_detached: bool = False
_detach_reason: str | None = None

def _on_detached(reason: Any, crash: Any = None) -> None:
    global _is_detached, _detach_reason, _is_spawned, _target_pid
    _is_detached = True
    _detach_reason = str(reason)
    if str(reason) == "process-terminated":
        # Target process is dead; clear spawned ownership so stop doesn't kill a recycled PID
        _is_spawned = False
        _target_pid = None
    _send_event(
        kind="lifecycle",
        channel="detached",
        payload={"reason": str(reason), "crash": str(crash) if crash else None},
        raw=f"[lifecycle] target detached: {reason}",
    )
def _on_log(level: str, text: str) -> None:
    _send_event(
        kind="stdout",
        channel="console",
        payload={"text": text, "level": level},
        raw=f"[{level}] {text}",
    )

def _on_message(message: dict[str, Any], data: bytes | None) -> None:
    msg_type = message.get("type")
    metadata: dict[str, Any] = {}
    if data is not None and len(data) > 0:
        max_bytes = 65536
        chunk = data[:max_bytes]
        metadata["data"] = base64.b64encode(chunk).decode("ascii")
        metadata["data_encoding"] = "base64"
        metadata["data_length"] = len(data)
        if len(data) > max_bytes:
            metadata["data_truncated"] = True

    MAX_TELEMETRY_BYTES = 262144
    if msg_type == "send":
        payload = message.get("payload")
        if isinstance(payload, str) and len(payload) > MAX_TELEMETRY_BYTES:
            metadata["payload_truncated"] = True
            metadata["payload_length"] = len(payload)
            payload = payload[:MAX_TELEMETRY_BYTES] + " [truncated]"
        elif isinstance(payload, (dict, list)):
            try:
                s = json.dumps(payload, ensure_ascii=False)
                if len(s) > MAX_TELEMETRY_BYTES:
                    metadata["payload_truncated"] = True
                    metadata["payload_length"] = len(s)
                    payload = {"_truncated": True, "_preview": s[:MAX_TELEMETRY_BYTES]}
            except Exception:
                pass
        _send_event(
            kind="message",
            channel="send",
            payload=payload,
            metadata=metadata if metadata else None,
        )
    elif msg_type == "log":
        text = str(message.get("text", ""))
        level = str(message.get("level", "info"))
        _send_event(
            kind="stdout",
            channel="console",
            payload={"text": text, "level": level},
            raw=f"[{level}] {text}",
            metadata=metadata if metadata else None,
        )
    elif msg_type == "error":
        desc = str(message.get("description", ""))
        stack = str(message.get("stack", ""))
        _send_event(
            kind="error",
            channel="error",
            payload={"description": desc, "stack": stack},
            raw=f"[error] {desc}\n{stack}" if stack else f"[error] {desc}",
            metadata=metadata if metadata else None,
        )
    else:
        _send_event(
            kind="message",
            channel=str(msg_type),
            payload=message,
            metadata=metadata if metadata else None,
        )

# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------
def _handle_init(req: dict[str, Any]) -> dict[str, Any]:
    global _device, _session, _is_spawned, _is_resumed, _target_pid, _is_detached, _detach_reason
    import frida

    target = req.get("target", {})
    usb = bool(target.get("usb"))
    device_id = target.get("device")
    host = target.get("host")

    if usb:
        _device = frida.get_usb_device()
    elif device_id:
        _device = frida.get_device_manager().get_device(str(device_id))
    elif host:
        _device = frida.get_device_manager().add_remote_device(str(host))
    else:
        _device = frida.get_local_device()

    target_type = target.get("type")
    target_val = target.get("value")

    if target_type == "spawn":
        spawn_cmd = target.get("spawn") or target_val
        if isinstance(spawn_cmd, list):
            argv = [str(x) for x in spawn_cmd]
        else:
            argv = [str(spawn_cmd)]
        _target_pid = _device.spawn(argv)
        _is_spawned = True
        _is_resumed = False
        try:
            _session = _device.attach(_target_pid)
        except Exception:
            # Immediate rollback on attach failure to prevent leaking newly spawned process
            try:
                _device.kill(_target_pid)
            except Exception:
                pass
            _is_spawned = False
            _target_pid = None
            raise
        # Target remains suspended until initial script is loaded or resume is explicitly requested
    elif target_type == "pid":
        pid_val = target.get("pid") if target.get("pid") is not None else target_val
        _target_pid = int(pid_val)
        _session = _device.attach(_target_pid)
        _is_spawned = False
    else:
        proc_name = str(target.get("process") or target_val)
        _session = _device.attach(proc_name)
        _is_spawned = False
        _target_pid = None

    _is_detached = False
    _detach_reason = None
    _session.on("detached", _on_detached)

    device_name = getattr(_device, "name", str(_device))
    _send_event(
        kind="lifecycle",
        channel="session_create",
        payload={"targetType": target_type, "targetValue": target_val, "pid": _target_pid},
        raw=f"[lifecycle] attached to {target_type}:{target_val} (pid: {_target_pid})",
    )

    return {
        "status": "ok",
        "pid": _target_pid,
        "device": device_name,
    }

def _handle_resume(req: dict[str, Any]) -> dict[str, Any]:
    global _device, _target_pid, _is_spawned, _is_resumed
    if _is_spawned and _target_pid and not _is_resumed and _device:
        try:
            _device.resume(_target_pid)
            _is_resumed = True
            _send_event(
                kind="lifecycle",
                channel="resumed",
                payload={"pid": _target_pid},
                raw=f"[lifecycle] spawned target resumed (pid: {_target_pid})",
            )
        except Exception as e:
            raise RuntimeError(f"Failed to resume spawned target (pid: {_target_pid}): {e}")
    return {"status": "ok", "pid": _target_pid}

def _handle_load(req: dict[str, Any]) -> dict[str, Any]:
    global _script
    if _session is None or _is_detached:
        raise RuntimeError("No active attached session or session has detached")

    script_source = req.get("script", "")
    script_name = req.get("name", "worker_script")

    if _script is not None:
        try:
            _script.unload()
        except Exception:
            pass
        _script = None

    _script = _session.create_script(script_source, name=script_name)
    _script.on("message", _on_message)
    if hasattr(_script, "set_log_handler"):
        _script.set_log_handler(_on_log)
    _script.load()

    exports: list[str] = []
    try:
        if hasattr(_script, "list_exports_sync"):
            exports = list(_script.list_exports_sync())
        elif hasattr(_script, "list_exports"):
            exports = list(_script.list_exports())
    except Exception:
        pass

    _send_event(
        kind="lifecycle",
        channel="script_load",
        payload={"name": script_name, "exports": exports},
        raw=f"[lifecycle] script '{script_name}' loaded, exports: {exports}",
    )

    return {
        "status": "ok",
        "exports": exports,
    }

def _handle_unload(req: dict[str, Any]) -> dict[str, Any]:
    global _script
    if _script is not None:
        try:
            _script.unload()
        except Exception:
            pass
        _script = None

    _send_event(
        kind="lifecycle",
        channel="script_unload",
        payload={},
        raw="[lifecycle] script unloaded",
    )

    return {"status": "ok"}

def _handle_rpc(req: dict[str, Any]) -> dict[str, Any]:
    global _script
    if _script is None:
        raise RuntimeError("No script loaded in live session")
    if _is_detached:
        raise RuntimeError(f"Session is detached from target ({_detach_reason or 'unknown'})")

    method = req.get("method")
    if not method:
        raise ValueError("Must provide 'method' for RPC call")

    args = req.get("args")
    if args is None:
        args_list: list[Any] = []
    elif isinstance(args, list):
        args_list = args
    else:
        args_list = [args]

    if hasattr(_script, "_rpc_request"):
        result = _script._rpc_request(["call", method, args_list])
    else:
        api = getattr(_script, "exports_sync", _script.exports)
        fn = getattr(api, method)
        result = fn(*args_list)
    MAX_RPC_BYTES = 524288
    if isinstance(result, str) and len(result) > MAX_RPC_BYTES:
        raise ValueError(f"RPC result exceeded maximum supported size limit of 512KiB (got {len(result)} characters)")
    elif isinstance(result, (dict, list)):
        s = json.dumps(result, ensure_ascii=False)
        if len(s) > MAX_RPC_BYTES:
            raise ValueError(f"RPC serialized result exceeded maximum supported size limit of 512KiB (got {len(s)} bytes)")

    return {
        "status": "ok",
        "result": result,
    }

def _handle_status(req: dict[str, Any]) -> dict[str, Any]:
    global _session, _script, _is_detached, _detach_reason, _target_pid
    alive = (_session is not None) and (not _is_detached)
    exports: list[str] = []
    if _script is not None and alive:
        try:
            if hasattr(_script, "list_exports_sync"):
                exports = list(_script.list_exports_sync())
        except Exception:
            pass

    return {
        "status": "ok",
        "alive": alive,
        "detached": _is_detached,
        "detachReason": _detach_reason,
        "hasScript": _script is not None,
        "exports": exports,
        "pid": _target_pid,
    }

def _handle_stop(req: dict[str, Any]) -> dict[str, Any]:
    global _session, _script, _device, _target_pid, _is_spawned
    if _script is not None:
        try:
            _script.unload()
        except Exception:
            pass
        _script = None

    if _session is not None:
        try:
            _session.detach()
        except Exception:
            pass
        _session = None

    # Detach only by default; kill target only if we spawned it and ownership cleanup is requested
    kill_spawned = req.get("kill_spawned", False)
    if _is_spawned and _target_pid and _device and kill_spawned:
        pid_to_kill = _target_pid
        _is_spawned = False
        _target_pid = None
        try:
            _device.kill(pid_to_kill)
        except Exception:
            pass

    return {"status": "ok"}

def _cleanup_on_signal(signum: int | None = None, frame: Any = None) -> None:
    try:
        _handle_stop({"kill_spawned": True})
    except Exception:
        pass
    if signum is not None:
        os._exit(0)

try:
    signal.signal(signal.SIGTERM, _cleanup_on_signal)
    signal.signal(signal.SIGINT, _cleanup_on_signal)
except Exception:
    pass
atexit.register(lambda: _cleanup_on_signal(None, None))

# ---------------------------------------------------------------------------
# Main dispatch loop
# ---------------------------------------------------------------------------
def main() -> None:
    while True:
        try:
            line = _CONTROL_IN.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            try:
                req = json.loads(line)
            except Exception:
                # Malformed IPC fails safely without crashing
                continue

            req_id = req.get("id")
            req_type = req.get("type")

            if req_type == "exit":
                try:
                    _handle_stop({"kill_spawned": True})
                except Exception:
                    pass
                break

            try:
                if req_type == "init":
                    res = _handle_init(req)
                elif req_type == "resume":
                    res = _handle_resume(req)
                elif req_type == "load":
                    res = _handle_load(req)
                elif req_type == "unload":
                    res = _handle_unload(req)
                elif req_type == "rpc":
                    res = _handle_rpc(req)
                elif req_type == "status":
                    res = _handle_status(req)
                elif req_type == "stop":
                    res = _handle_stop(req)
                    _send_frame({"id": req_id, "type": "stop_ok", **res})
                    break
                else:
                    _send_frame({"id": req_id, "type": "error", "error": f"Unknown request type: {req_type}"})
                    continue

                _send_frame({"id": req_id, "type": f"{req_type}_ok", **res})
            except Exception as e:
                _send_frame({
                    "id": req_id,
                    "type": "error",
                    "error": str(e),
                    "details": traceback.format_exc(),
                })
        except (KeyboardInterrupt, SystemExit):
            break
        except Exception:
            pass

    try:
        _handle_stop({"kill_spawned": True})
    except Exception:
        pass

if __name__ == "__main__":
    main()
