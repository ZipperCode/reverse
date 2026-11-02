"""
受控 Kaitai Struct Python 解析 worker：
仅在 runReversePython 私有临时目录内加载经 SHA-256 校验的编译器生成模块，
提取 --read-pos 0基 [start, end) 偏移、子流层级、64位整数字符串、错误偏移与尾部残留字节。
进程隔离不构成安全沙箱；按平台能力如实应用并报告资源限额。
"""

import enum
import hashlib
import importlib
import io
import json
import math
import os
import stat
import sys


def _isolate_sys_path(staging_dir: str) -> None:
    """移除当前工作目录与项目路径，仅保留私有 staging 目录及 Python 标准库/site-packages。"""
    real_staging = os.path.realpath(staging_dir)
    try:
        real_cwd = os.path.realpath(os.getcwd())
    except OSError:
        real_cwd = ""
    real_prefix = os.path.realpath(sys.prefix)
    real_base_prefix = os.path.realpath(sys.base_prefix)
    cleaned = [staging_dir]
    for entry in sys.path:
        if not entry:
            continue
        try:
            real_entry = os.path.realpath(entry)
        except OSError:
            continue
        if real_entry == real_staging or (real_cwd and real_entry == real_cwd):
            continue
        # 仅保留 Python 运行时自身的 lib / site-packages 目录，排除项目工作目录
        if (
            "site-packages" in real_entry
            or "dist-packages" in real_entry
            or real_entry.startswith(real_prefix)
            or real_entry.startswith(real_base_prefix)
        ):
            cleaned.append(entry)
    sys.path[:] = cleaned


def _apply_resource_limits(timeout_ms: int) -> dict:
    """尝试设置 POSIX 进程资源上限并如实返回实际生效情况（不伪称安全沙箱）。"""
    report = {
        "isolation_model": "subprocess_staging_not_security_sandbox",
        "rlimit_cpu": {"enforced": False, "reason": "resource module unavailable on platform"},
        "rlimit_as": {"enforced": False, "reason": "resource module unavailable on platform"},
    }
    try:
        import resource
    except ImportError:
        return report

    cpu_seconds = max(1, int(math.ceil(max(timeout_ms, 100) / 1000.0)) + 2)
    try:
        _soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
        target_soft = cpu_seconds if hard == resource.RLIM_INFINITY or hard < 0 else min(cpu_seconds, hard)
        target_hard = hard if hard == resource.RLIM_INFINITY or hard < 0 else max(target_soft, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (target_soft, target_hard))
        report["rlimit_cpu"] = {"enforced": True, "seconds": target_soft}
    except (ValueError, OSError, AttributeError) as exc:
        report["rlimit_cpu"] = {"enforced": False, "reason": str(exc)}

    # macOS 内核通常拒绝在已映射 dyld 共享缓存的进程上降低 RLIMIT_AS，此处如实捕获并报告
    target_as_bytes = 1024 * 1024 * 1024  # 1 GiB
    try:
        _soft_as, hard_as = resource.getrlimit(resource.RLIMIT_AS)
        eff_soft = target_as_bytes if hard_as == resource.RLIM_INFINITY or hard_as < 0 else min(target_as_bytes, hard_as)
        resource.setrlimit(resource.RLIMIT_AS, (eff_soft, hard_as))
        report["rlimit_as"] = {"enforced": True, "bytes": eff_soft}
    except (ValueError, OSError, AttributeError) as exc:
        report["rlimit_as"] = {"enforced": False, "reason": str(exc)}

    return report


def _read_sample_bounded_nofollow(sample_path: str, max_input_bytes: int):
    """使用 lstat + O_NOFOLLOW 读取普通样本文件，拒绝符号链接、非普通文件与超限输入。"""
    try:
        st = os.lstat(sample_path)
    except OSError as exc:
        return None, "io_error", f"Failed to stat sample '{sample_path}': {exc}"

    if stat.S_ISLNK(st.st_mode):
        return None, "symlink_rejected", f"Symlink escape violation: sample '{sample_path}' is a symbolic link"
    if not stat.S_ISREG(st.st_mode):
        return None, "not_regular_file", f"Sample '{sample_path}' is not a regular file"
    if st.st_size > max_input_bytes:
        return (
            None,
            "input_limit_exceeded",
            f"Sample '{sample_path}' size ({st.st_size} bytes) exceeds max_input_bytes ({max_input_bytes} bytes)",
        )

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    try:
        fd = os.open(sample_path, flags)
    except OSError as exc:
        return None, "io_error", f"Failed to open sample '{sample_path}': {exc}"

    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            return None, "not_regular_file", f"Opened sample '{sample_path}' is not a regular file"
        if fst.st_size > max_input_bytes:
            return (
                None,
                "input_limit_exceeded",
                f"Sample '{sample_path}' size ({fst.st_size} bytes) exceeds max_input_bytes ({max_input_bytes} bytes)",
            )
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_input_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_input_bytes:
                return (
                    None,
                    "input_limit_exceeded",
                    f"Sample '{sample_path}' grew beyond max_input_bytes ({max_input_bytes} bytes) while reading",
                )
            chunks.append(chunk)
        return b"".join(chunks), None, None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _is_64bit_ksy_type(ksy_type):
    if not isinstance(ksy_type, str):
        return False
    norm = ksy_type.strip().lower()
    if norm in ("u8", "u8le", "u8be", "s8", "s8le", "s8be", "b64", "b64le", "b64be"):
        return True
    if norm.startswith("b"):
        bit_str = norm[1:-2] if (norm.endswith("le") or norm.endswith("be")) else norm[1:]
        if bit_str.isdigit():
            return int(bit_str) > 32
    return False


def _is_signed_64bit_ksy_type(ksy_type):
    if not isinstance(ksy_type, str):
        return False
    return ksy_type.strip().lower() in ("s8", "s8le", "s8be")


def _collect_skipped_lazy_instances(obj, KaitaiStruct):
    """仅通过类字典检查未求值的 @property 实例名，绝不触发 property getter。"""
    skipped = []
    seen = set()
    obj_dict = getattr(obj, "__dict__", {})
    for cls in type(obj).__mro__:
        if cls is KaitaiStruct or cls is object:
            continue
        for name, member in cls.__dict__.items():
            if name.startswith("_") or name in seen:
                continue
            if isinstance(member, property):
                seen.add(name)
                if f"_m_{name}" not in obj_dict:
                    skipped.append(name)
    skipped.sort()
    return skipped


def _compute_file_range(stream_info: dict, start, end, field_processed: bool):
    """
    仅当所在流未经变换（processed == False）、基准文件偏移确定且当前字段自身非变换后数据时，
    计算原始样本文件偏移；经过 xor/zlib/rol/ror 变换的数据绝不伪造文件偏移。
    """
    if (
        field_processed
        or stream_info.get("processed", False)
        or stream_info.get("base_file_offset") is None
        or not isinstance(start, int)
        or not isinstance(end, int)
    ):
        return None, None, None
    base = stream_info["base_file_offset"]
    f_start = base + start
    f_end = base + end
    return f_start, f_end, {"start": f_start, "end": f_end}


def _parse_single_sample(
    sample_path: str,
    entry_cls,
    KaitaiStruct,
    KaitaiStream,
    KaitaiStructError,
    ValidationFailedError,
    eof_error_types,
    field_type_hints: dict,
    processed_field_hints: dict,
    limits: dict,
) -> dict:
    max_input_bytes = int(limits["max_input_bytes"])
    max_depth = int(limits["max_depth"])
    max_fields = int(limits["max_fields"])
    max_byte_preview_len = int(limits.get("max_byte_preview_len", 64))

    sample_bytes, read_err_kind, read_err_msg = _read_sample_bounded_nofollow(sample_path, max_input_bytes)
    if sample_bytes is None:
        return {
            "sample_path": sample_path,
            "ok": False,
            "sample_size": 0,
            "consumed_bytes": 0,
            "trailing_bytes": 0,
            "trailing": {"count": 0, "start": 0, "end": 0, "preview_hex": "", "truncated_preview": False},
            "fields": [],
            "total_fields": 0,
            "truncated": False,
            "output_truncated": False,
            "truncation_reason": None,
            "error_kind": read_err_kind,
            "error": read_err_msg,
            "error_offset": None,
            "error_stream_pos": None,
            "error_field_start": None,
            "error_field_path": None,
            "error_stream_id": None,
            "error_file_offset": None,
            "error_src_path": None,
        }

    total_size = len(sample_bytes)
    raw_io = io.BytesIO(sample_bytes)
    root_stream = KaitaiStream(raw_io)

    root_obj = None
    failing_obj = None
    parse_exc = None

    try:
        root_obj = entry_cls(root_stream)
        # kaitai-struct-compiler --read-pos 默认关闭 auto-read：__init__ 仅初始化空的 _debug 字典，需显式调用 _read()
        root_dict = getattr(root_obj, "__dict__", {})
        if hasattr(root_obj, "_read") and "_debug" in root_dict and len(root_dict["_debug"]) == 0:
            root_obj._read()
    except Exception as exc:
        parse_exc = exc
        tb = exc.__traceback__
        while tb is not None:
            cand = tb.tb_frame.f_locals.get("self")
            if isinstance(cand, KaitaiStruct):
                if root_obj is None and getattr(cand, "_parent", None) is None:
                    root_obj = cand
                failing_obj = cand
            tb = tb.tb_next

        if root_obj is None and failing_obj is not None:
            cur = failing_obj
            guard = set()
            while isinstance(cur, KaitaiStruct) and id(cur) not in guard:
                guard.add(id(cur))
                parent = getattr(cur, "_parent", None)
                if parent is None:
                    root_obj = cur
                    break
                cur = parent
            if root_obj is None:
                root_obj = failing_obj

    fields = []
    truncated = False
    truncation_reason = None

    stream_info_by_io = {
        id(root_stream): {
            "stream_id": "root",
            "base_file_offset": 0,
            "processed": False,
        }
    }
    obj_path_by_id = {}
    if root_obj is not None:
        obj_path_by_id[id(root_obj)] = ""

    def emit_field(record: dict) -> bool:
        nonlocal truncated, truncation_reason
        if len(fields) >= max_fields:
            truncated = True
            if truncation_reason is None:
                truncation_reason = "max_fields_exceeded"
            return False
        fields.append(record)
        return True

    def format_scalar_or_leaf(
        val,
        field_path: str,
        ksy_type,
        stream_info: dict,
        start,
        end,
        field_processed: bool,
    ) -> dict:
        f_start, f_end, f_offset = _compute_file_range(stream_info, start, end, field_processed)
        base_rec = {
            "path": field_path,
            "stream_id": stream_info["stream_id"],
            "start": start if isinstance(start, int) else None,
            "end": end if isinstance(end, int) else None,
            "file_start": f_start,
            "file_end": f_end,
            "file_offset": f_offset,
            "processed": bool(field_processed or stream_info.get("processed", False)),
        }
        if ksy_type:
            base_rec["ksy_type"] = ksy_type

        if isinstance(val, bool):
            base_rec["type"] = "bool"
            base_rec["value"] = val
            return base_rec

        if isinstance(val, enum.Enum):
            raw_ev = val.value
            span_is_8 = isinstance(start, int) and isinstance(end, int) and (end - start) == 8
            is_64 = isinstance(raw_ev, int) and (
                _is_64bit_ksy_type(ksy_type)
                or span_is_8
                or raw_ev < -2147483648
                or raw_ev > 4294967295
            )
            base_rec["type"] = "enum"
            base_rec["value"] = val.name
            base_rec["enum_value"] = str(raw_ev) if is_64 else raw_ev
            return base_rec

        if isinstance(val, int):
            span_is_8 = isinstance(start, int) and isinstance(end, int) and (end - start) == 8
            is_64 = (
                _is_64bit_ksy_type(ksy_type)
                or span_is_8
                or val < -2147483648
                or val > 4294967295
            )
            if is_64:
                is_signed = val < 0 or _is_signed_64bit_ksy_type(ksy_type)
                base_rec["type"] = "int64" if is_signed else "uint64"
                base_rec["value"] = str(val)
            else:
                base_rec["type"] = "int"
                base_rec["value"] = val
            return base_rec

        if isinstance(val, float):
            base_rec["type"] = "float"
            if math.isnan(val) or math.isinf(val):
                base_rec["value"] = str(val)
            else:
                base_rec["value"] = val
            return base_rec

        if isinstance(val, (bytes, bytearray, memoryview)):
            b = bytes(val)
            preview = b[:max_byte_preview_len]
            base_rec["type"] = "bytes"
            base_rec["value"] = preview.hex()
            base_rec["byte_length"] = len(b)
            base_rec["bytes_sha256"] = hashlib.sha256(b).hexdigest()
            base_rec["preview_truncated"] = len(b) > max_byte_preview_len
            return base_rec

        if isinstance(val, str):
            encoded_len = len(val.encode("utf-8", errors="replace"))
            max_str_chars = max_byte_preview_len * 4
            if len(val) > max_str_chars:
                base_rec["type"] = "str"
                base_rec["value"] = val[:max_str_chars]
                base_rec["byte_length"] = encoded_len
                base_rec["preview_truncated"] = True
            else:
                base_rec["type"] = "str"
                base_rec["value"] = val
            return base_rec

        base_rec["type"] = type(val).__name__
        base_rec["value"] = str(val)
        return base_rec

    def resolve_child_stream_info(
        parent_obj,
        attr_name: str,
        child_obj,
        child_path: str,
        parent_stream_info: dict,
        elem_start,
        attr_processed_hint: bool,
    ) -> dict:
        parent_io = getattr(parent_obj, "_io", None)
        child_io = getattr(child_obj, "_io", None)
        if child_io is None or (parent_io is not None and id(child_io) == id(parent_io)):
            return parent_stream_info

        existing = stream_info_by_io.get(id(child_io))
        if existing is not None:
            return existing

        parent_dict = getattr(parent_obj, "__dict__", {})
        has_double_raw = f"_raw__raw_{attr_name}" in parent_dict
        is_processed = bool(
            parent_stream_info.get("processed", False)
            or has_double_raw
            or attr_processed_hint
        )
        if (
            not is_processed
            and parent_stream_info.get("base_file_offset") is not None
            and isinstance(elem_start, int)
        ):
            base_file_offset = parent_stream_info["base_file_offset"] + elem_start
        else:
            base_file_offset = None

        info = {
            "stream_id": f"substream:{child_path}",
            "base_file_offset": base_file_offset,
            "processed": is_processed,
        }
        stream_info_by_io[id(child_io)] = info
        return info

    def walk_struct(obj, prefix: str, stream_info: dict, depth: int, active_ids: set) -> None:
        nonlocal truncated, truncation_reason
        if obj is None or id(obj) in active_ids:
            return
        active_ids.add(id(obj))
        try:
            obj_dict = getattr(obj, "__dict__", {})
            debug_map = obj_dict.get("_debug")
            if not isinstance(debug_map, dict):
                debug_map = {}

            cls_qual = f"{type(obj).__module__}.{type(obj).__qualname__}"
            seq_fields = getattr(type(obj), "SEQ_FIELDS", None)
            if isinstance(seq_fields, (list, tuple)):
                attr_names = list(seq_fields)
            else:
                attr_names = [k for k in obj_dict.keys() if not k.startswith("_")]

            for attr_name in attr_names:
                if len(fields) >= max_fields:
                    truncated = True
                    if truncation_reason is None:
                        truncation_reason = "max_fields_exceeded"
                    return

                # 仅读取 __dict__ 中已完成解析的序列字段，避免触发未求值的 @property
                if attr_name not in obj_dict:
                    continue
                val = obj_dict[attr_name]
                if val is None and attr_name not in debug_map:
                    continue

                field_path = f"{prefix}.{attr_name}" if prefix else attr_name
                dbg = debug_map.get(attr_name)
                if not isinstance(dbg, dict):
                    dbg = {}
                start = dbg.get("start")
                end = dbg.get("end")

                hint_key = f"{cls_qual}.{attr_name}"
                ksy_type = field_type_hints.get(hint_key)
                attr_processed_hint = bool(processed_field_hints.get(hint_key, False))

                if isinstance(val, KaitaiStruct):
                    obj_path_by_id[id(val)] = field_path
                    has_double_raw = f"_raw__raw_{attr_name}" in obj_dict
                    struct_processed = bool(has_double_raw or attr_processed_hint)
                    # 若子流经过变换（xor/zlib/rol/ror），不暴露伪造原文件偏移
                    f_start, f_end, f_offset = _compute_file_range(
                        stream_info, start, end, struct_processed
                    )
                    skipped_lazy = _collect_skipped_lazy_instances(val, KaitaiStruct)
                    rec = {
                        "path": field_path,
                        "type": "struct",
                        "value": type(val).__name__,
                        "stream_id": stream_info["stream_id"],
                        "start": start if isinstance(start, int) else None,
                        "end": end if isinstance(end, int) else None,
                        "file_start": f_start,
                        "file_end": f_end,
                        "file_offset": f_offset,
                        "processed": bool(struct_processed or stream_info.get("processed", False)),
                    }
                    if ksy_type:
                        rec["ksy_type"] = ksy_type
                    if skipped_lazy:
                        rec["lazy_instances_skipped"] = skipped_lazy
                    if not emit_field(rec):
                        return

                    if id(val) in active_ids:
                        continue
                    if depth + 1 > max_depth:
                        truncated = True
                        if truncation_reason is None:
                            truncation_reason = "max_depth_exceeded"
                        continue

                    child_stream_info = resolve_child_stream_info(
                        obj,
                        attr_name,
                        val,
                        field_path,
                        stream_info,
                        start,
                        attr_processed_hint,
                    )
                    walk_struct(val, field_path, child_stream_info, depth + 1, active_ids)

                elif isinstance(val, list):
                    if id(val) in active_ids:
                        continue
                    f_start, f_end, f_offset = _compute_file_range(
                        stream_info, start, end, False
                    )
                    arr_rec = {
                        "path": field_path,
                        "type": "array",
                        "value": len(val),
                        "stream_id": stream_info["stream_id"],
                        "start": start if isinstance(start, int) else None,
                        "end": end if isinstance(end, int) else None,
                        "file_start": f_start,
                        "file_end": f_end,
                        "file_offset": f_offset,
                        "processed": bool(stream_info.get("processed", False)),
                    }
                    if ksy_type:
                        arr_rec["ksy_type"] = ksy_type
                    if not emit_field(arr_rec):
                        return

                    if depth + 1 > max_depth:
                        if len(val) > 0:
                            truncated = True
                            if truncation_reason is None:
                                truncation_reason = "max_depth_exceeded"
                        continue

                    arr_dbg = dbg.get("arr")
                    if not isinstance(arr_dbg, list):
                        arr_dbg = []

                    active_ids.add(id(val))
                    try:
                        for idx, elem in enumerate(val):
                            if len(fields) >= max_fields:
                                truncated = True
                                if truncation_reason is None:
                                    truncation_reason = "max_fields_exceeded"
                                return
                            elem_path = f"{field_path}[{idx}]"
                            e_dbg = arr_dbg[idx] if idx < len(arr_dbg) and isinstance(arr_dbg[idx], dict) else {}
                            e_start = e_dbg.get("start")
                            e_end = e_dbg.get("end")

                            if isinstance(elem, KaitaiStruct):
                                obj_path_by_id[id(elem)] = elem_path
                                has_double_raw = f"_raw__raw_{attr_name}" in obj_dict
                                elem_processed = bool(has_double_raw or attr_processed_hint)
                                elem_f_start, elem_f_end, elem_f_offset = _compute_file_range(
                                    stream_info, e_start, e_end, elem_processed
                                )
                                skipped_lazy = _collect_skipped_lazy_instances(elem, KaitaiStruct)
                                e_rec = {
                                    "path": elem_path,
                                    "type": "struct",
                                    "value": type(elem).__name__,
                                    "stream_id": stream_info["stream_id"],
                                    "start": e_start if isinstance(e_start, int) else None,
                                    "end": e_end if isinstance(e_end, int) else None,
                                    "file_start": elem_f_start,
                                    "file_end": elem_f_end,
                                    "file_offset": elem_f_offset,
                                    "processed": bool(
                                        has_double_raw
                                        or attr_processed_hint
                                        or stream_info.get("processed", False)
                                    ),
                                }
                                if ksy_type:
                                    e_rec["ksy_type"] = ksy_type
                                if skipped_lazy:
                                    e_rec["lazy_instances_skipped"] = skipped_lazy
                                if not emit_field(e_rec):
                                    return

                                if id(elem) in active_ids:
                                    continue
                                if depth + 2 > max_depth:
                                    truncated = True
                                    if truncation_reason is None:
                                        truncation_reason = "max_depth_exceeded"
                                    continue

                                child_stream_info = resolve_child_stream_info(
                                    obj,
                                    attr_name,
                                    elem,
                                    elem_path,
                                    stream_info,
                                    e_start,
                                    attr_processed_hint,
                                )
                                walk_struct(elem, elem_path, child_stream_info, depth + 2, active_ids)
                            else:
                                leaf_processed = bool(
                                    isinstance(elem, (bytes, bytearray, memoryview))
                                    and (f"_raw_{attr_name}" in obj_dict or attr_processed_hint)
                                )
                                leaf_rec = format_scalar_or_leaf(
                                    elem,
                                    elem_path,
                                    ksy_type,
                                    stream_info,
                                    e_start,
                                    e_end,
                                    leaf_processed,
                                )
                                if not emit_field(leaf_rec):
                                    return
                    finally:
                        active_ids.discard(id(val))
                else:
                    leaf_processed = bool(
                        isinstance(val, (bytes, bytearray, memoryview))
                        and (f"_raw_{attr_name}" in obj_dict or attr_processed_hint)
                    )
                    leaf_rec = format_scalar_or_leaf(
                        val,
                        field_path,
                        ksy_type,
                        stream_info,
                        start,
                        end,
                        leaf_processed,
                    )
                    if not emit_field(leaf_rec):
                        return
        finally:
            active_ids.discard(id(obj))

    root_skipped_lazy = []
    if root_obj is not None:
        root_skipped_lazy = _collect_skipped_lazy_instances(root_obj, KaitaiStruct)
        walk_struct(root_obj, "", stream_info_by_io[id(root_stream)], 1, set())

    try:
        consumed_bytes = int(root_stream.pos())
    except Exception:
        consumed_bytes = 0

    if parse_exc is None:
        trailing_count = max(0, total_size - consumed_bytes)
        trailing_slice = sample_bytes[consumed_bytes : consumed_bytes + max_byte_preview_len]
        return {
            "sample_path": sample_path,
            "ok": True,
            "sample_size": total_size,
            "consumed_bytes": consumed_bytes,
            "trailing_bytes": trailing_count,
            "trailing": {
                "count": trailing_count,
                "start": consumed_bytes,
                "end": total_size,
                "preview_hex": trailing_slice.hex(),
                "truncated_preview": trailing_count > max_byte_preview_len,
            },
            "fields": fields,
            "total_fields": len(fields),
            "root_lazy_instances_skipped": root_skipped_lazy,
            "truncated": truncated,
            "output_truncated": False,
            "truncation_reason": truncation_reason,
            "error_kind": None,
            "error": None,
            "error_offset": None,
            "error_stream_pos": None,
            "error_field_start": None,
            "error_field_path": None,
            "error_stream_id": None,
            "error_file_offset": None,
            "error_src_path": None,
        }

    # 计算解析异常的精确流内偏移、出错字段路径与（未变换流下的）原文件偏移
    err_io = getattr(parse_exc, "io", None)
    if err_io is None and failing_obj is not None:
        err_io = getattr(failing_obj, "_io", None)
    if err_io is None:
        err_io = root_stream

    try:
        err_stream_pos = int(err_io.pos())
    except Exception:
        err_stream_pos = consumed_bytes

    err_stream_info = stream_info_by_io.get(
        id(err_io),
        {"stream_id": "unknown_substream", "base_file_offset": None, "processed": True},
    )

    failing_prefix = obj_path_by_id.get(id(failing_obj), "") if failing_obj is not None else ""
    incomplete_attr = None
    incomplete_start = None
    last_completed_attr = None
    last_completed_start = None
    last_completed_end = None

    if failing_obj is not None:
        f_dbg = getattr(failing_obj, "__dict__", {}).get("_debug")
        if isinstance(f_dbg, dict):
            seq_order = getattr(type(failing_obj), "SEQ_FIELDS", list(f_dbg.keys()))
            for a_name in seq_order:
                entry = f_dbg.get(a_name)
                if not isinstance(entry, dict):
                    continue
                if "start" in entry and "end" not in entry:
                    arr_list = entry.get("arr")
                    if isinstance(arr_list, list) and len(arr_list) > 0 and isinstance(arr_list[-1], dict):
                        incomplete_attr = f"{a_name}[{len(arr_list) - 1}]"
                        incomplete_start = arr_list[-1].get("start", entry.get("start"))
                    else:
                        incomplete_attr = a_name
                        incomplete_start = entry.get("start")
                    break
                if "start" in entry and "end" in entry:
                    last_completed_attr = a_name
                    last_completed_start = entry.get("start")
                    last_completed_end = entry.get("end")

    if isinstance(parse_exc, ValidationFailedError):
        # --read-pos 生成代码在抛出 ValidationFailedError 时尚未写入字段 'end'，违规字段记录在 incomplete_attr
        if incomplete_attr is not None:
            err_field_name = incomplete_attr
            err_field_start = incomplete_start if isinstance(incomplete_start, int) else err_stream_pos
            err_offset = err_field_start
        elif last_completed_attr is not None:
            err_field_name = last_completed_attr
            err_field_start = last_completed_start if isinstance(last_completed_start, int) else err_stream_pos
            err_offset = err_field_start if last_completed_end == err_stream_pos else err_stream_pos
        else:
            err_field_name = None
            err_field_start = None
            err_offset = err_stream_pos
    elif incomplete_attr is not None:
        err_field_name = incomplete_attr
        err_field_start = incomplete_start if isinstance(incomplete_start, int) else None
        # EOFError / EndOfStreamError 等中途读取失败：流游标停在越界/EOF 位置，同时保留字段起始位置
        err_offset = err_stream_pos
    else:
        err_field_name = last_completed_attr
        err_field_start = last_completed_start if isinstance(last_completed_start, int) else None
        err_offset = err_stream_pos

    if err_field_name:
        err_field_path = f"{failing_prefix}.{err_field_name}" if failing_prefix else err_field_name
    else:
        err_field_path = failing_prefix or None

    if (
        not err_stream_info.get("processed", False)
        and err_stream_info.get("base_file_offset") is not None
        and isinstance(err_offset, int)
    ):
        err_file_offset = err_stream_info["base_file_offset"] + err_offset
    else:
        err_file_offset = None

    if isinstance(parse_exc, ValidationFailedError):
        err_kind = "validation_failed"
    elif isinstance(parse_exc, eof_error_types):
        err_kind = "eof_overrun"
    elif isinstance(parse_exc, KaitaiStructError):
        err_kind = "kaitai_parse_error"
    else:
        err_kind = "runtime_error"

    trailing_count = max(0, total_size - consumed_bytes)
    trailing_slice = sample_bytes[consumed_bytes : consumed_bytes + max_byte_preview_len]

    return {
        "sample_path": sample_path,
        "ok": False,
        "sample_size": total_size,
        "consumed_bytes": consumed_bytes,
        "trailing_bytes": trailing_count,
        "trailing": {
            "count": trailing_count,
            "start": consumed_bytes,
            "end": total_size,
            "preview_hex": trailing_slice.hex(),
            "truncated_preview": trailing_count > max_byte_preview_len,
        },
        "fields": fields,
        "total_fields": len(fields),
        "root_lazy_instances_skipped": root_skipped_lazy,
        "truncated": truncated,
        "output_truncated": False,
        "truncation_reason": truncation_reason,
        "error_kind": err_kind,
        "error": f"{type(parse_exc).__name__}: {parse_exc}",
        "error_offset": err_offset,
        "error_stream_pos": err_stream_pos,
        "error_field_start": err_field_start,
        "error_field_path": err_field_path,
        "error_stream_id": err_stream_info["stream_id"],
        "error_file_offset": err_file_offset,
        "error_src_path": getattr(parse_exc, "src_path", None),
    }


def _enforce_output_byte_budget(response: dict, max_output_bytes: int) -> bytes:
    """确保序列化 JSON 严格不超过 max_output_bytes（低于 runReversePython 16MiB 上限）。"""
    encoded = json.dumps(response, ensure_ascii=False).encode("utf-8")
    if len(encoded) <= max_output_bytes:
        return encoded

    results = response.get("results", [])
    for item in results:
        item["total_fields"] = len(item.get("fields", []))

    # 二分裁剪各样本的 fields 列表以满足 max_output_bytes 预算
    max_len = max((len(item.get("fields", [])) for item in results), default=0)
    lo, hi = 0, max_len
    best_keep = 0
    orig_fields = [list(item.get("fields", [])) for item in results]

    while lo <= hi:
        mid = (lo + hi) // 2
        for idx, item in enumerate(results):
            if len(orig_fields[idx]) > mid:
                item["fields"] = orig_fields[idx][:mid]
                item["truncated"] = True
                item["output_truncated"] = True
                item["truncation_reason"] = "max_output_bytes_exceeded"
            else:
                item["fields"] = orig_fields[idx]
        cand = json.dumps(response, ensure_ascii=False).encode("utf-8")
        if len(cand) <= max_output_bytes:
            best_keep = mid
            lo = mid + 1
        else:
            hi = mid - 1

    for idx, item in enumerate(results):
        if len(orig_fields[idx]) > best_keep:
            item["fields"] = orig_fields[idx][:best_keep]
            item["truncated"] = True
            item["output_truncated"] = True
            item["truncation_reason"] = "max_output_bytes_exceeded"
        else:
            item["fields"] = orig_fields[idx]
    response["output_budget_truncated"] = True

    final_encoded = json.dumps(response, ensure_ascii=False).encode("utf-8")
    if len(final_encoded) <= max_output_bytes:
        return final_encoded

    # 若元数据本身仍超极小 max_output_bytes，返回紧凑超限错误对象
    fallback = {
        "ok": False,
        "error_code": "output_limit_exceeded",
        "error": f"Worker JSON metadata exceeded max_output_bytes ({max_output_bytes} bytes)",
    }
    return json.dumps(fallback, ensure_ascii=False).encode("utf-8")


def main() -> int:
    staging_dir = os.path.dirname(os.path.abspath(__file__))
    _isolate_sys_path(staging_dir)

    raw_req = sys.stdin.read()
    if not raw_req.strip():
        sys.stdout.write(json.dumps({"ok": False, "error": "Empty request payload"}))
        return 1

    try:
        req = json.loads(raw_req)
    except Exception as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": f"Invalid request JSON: {exc}"}))
        return 1

    limits = req.get("limits") or {}
    timeout_ms = int(limits.get("timeout_ms", 30000))
    max_output_bytes = int(limits.get("max_output_bytes", 1048576))
    resource_report = _apply_resource_limits(timeout_ms)
    resource_report["max_input_bytes"] = int(limits.get("max_input_bytes", 4194304))
    resource_report["max_depth"] = int(limits.get("max_depth", 16))
    resource_report["max_fields"] = int(limits.get("max_fields", 2000))
    resource_report["max_output_bytes"] = max_output_bytes
    resource_report["timeout_ms"] = timeout_ms

    try:
        import kaitaistruct
        from kaitaistruct import (
            KaitaiStream,
            KaitaiStruct,
            KaitaiStructError,
            ValidationFailedError,
        )
        maybe_eos = getattr(kaitaistruct, "EndOfStreamError", None)
        eof_error_types = (
            (EOFError, maybe_eos)
            if isinstance(maybe_eos, type) and issubclass(maybe_eos, BaseException)
            else (EOFError,)
        )
    except Exception as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "missing_kaitaistruct",
                    "error": f"Failed to import kaitaistruct runtime: {exc}",
                }
            )
        )
        return 1

    entry_module = str(req.get("entry_module") or "").strip()
    entry_class = str(req.get("entry_class") or "").strip()
    allowed_modules = set(req.get("allowed_modules") or [])
    sample_paths = req.get("sample_paths") or []
    field_type_hints = req.get("field_type_hints") or {}
    processed_field_hints = req.get("processed_field_hints") or {}

    if not entry_module or entry_module not in allowed_modules:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "unauthorized_module",
                    "error": f"Entry module '{entry_module}' is not in verified allowed_modules",
                }
            )
        )
        return 1

    real_staging = os.path.realpath(staging_dir)
    for mod_name in sorted(allowed_modules):
        expected_file = os.path.join(staging_dir, f"{mod_name}.py")
        if not os.path.isfile(expected_file) or os.path.islink(expected_file):
            sys.stdout.write(
                json.dumps(
                    {
                        "ok": False,
                        "error_code": "missing_staged_module",
                        "error": f"Staged module '{mod_name}.py' missing or invalid",
                    }
                )
            )
            return 1

    try:
        mod = importlib.import_module(entry_module)
    except Exception as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "module_import_error",
                    "error": f"Failed to import generated parser module '{entry_module}': {exc}",
                }
            )
        )
        return 1

    mod_file = getattr(mod, "__file__", "") or ""
    if os.path.realpath(os.path.dirname(mod_file)) != real_staging:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "module_origin_violation",
                    "error": f"Module '{entry_module}' loaded from unexpected location '{mod_file}'",
                }
            )
        )
        return 1

    cls = getattr(mod, entry_class, None)
    if not isinstance(cls, type) or not issubclass(cls, KaitaiStruct):
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "invalid_entry_class",
                    "error": f"Entry class '{entry_class}' in '{entry_module}' is not a KaitaiStruct subclass",
                }
            )
        )
        return 1

    results = []
    for sp in sample_paths:
        res = _parse_single_sample(
            str(sp),
            cls,
            KaitaiStruct,
            KaitaiStream,
            KaitaiStructError,
            ValidationFailedError,
            eof_error_types,
            field_type_hints,
            processed_field_hints,
            limits,
        )
        results.append(res)

    api_ver = getattr(kaitaistruct, "API_VERSION", None)
    api_ver_str = (
        ".".join(str(x) for x in api_ver)
        if isinstance(api_ver, tuple)
        else str(getattr(kaitaistruct, "__version__", "unknown"))
    )

    response = {
        "ok": True,
        "runtime_version": str(getattr(kaitaistruct, "__version__", "unknown")),
        "runtime_api_version": api_ver_str,
        "resource_limits": resource_report,
        "output_budget_truncated": False,
        "results": results,
    }

    payload = _enforce_output_byte_budget(response, max_output_bytes)
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
