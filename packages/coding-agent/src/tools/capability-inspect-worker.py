"""
受控 capa JSON 结果无损解析与规范化 worker（Step 5）：
通过 Python 原生任意精度整数 json.loads 解析 capa 原始 JSON 报告，
在进入 TypeScript JSON.parse 之前将所有地址、偏移、64位/超大整数无损编码为十进制与十六进制字符串，
校验 capa 结果文档版本与结构合法性，并生成带 RFC 6901 JSON Pointer 的稳定规则匹配树。
"""

import hashlib
import json
import os
import re
import stat
import sys


def _isolate_sys_path(staging_dir: str) -> None:
    """移除当前工作目录与项目路径，仅保留私有 staging 目录及 Python 标准库。"""
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
        if (
            "site-packages" in real_entry
            or "dist-packages" in real_entry
            or real_entry.startswith(real_prefix)
            or real_entry.startswith(real_base_prefix)
        ):
            cleaned.append(entry)
    sys.path[:] = cleaned


def _read_regular_file_bounded_nofollow(file_path: str, max_bytes: int):
    """使用 lstat + O_NOFOLLOW 读取普通文件，拒绝符号链接、非普通文件与超限文件。"""
    try:
        st = os.lstat(file_path)
    except OSError as exc:
        return None, "io_error", f"Failed to stat '{file_path}': {exc}"

    if stat.S_ISLNK(st.st_mode):
        return None, "symlink_rejected", f"Symlink escape violation: '{file_path}' is a symbolic link"
    if not stat.S_ISREG(st.st_mode):
        return None, "not_regular_file", f"Path '{file_path}' is not a regular file"
    if st.st_size > max_bytes:
        return (
            None,
            "output_limit_exceeded",
            f"File '{file_path}' size ({st.st_size} bytes) exceeds max_output_bytes ({max_bytes} bytes)",
        )

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    try:
        fd = os.open(file_path, flags)
    except OSError as exc:
        return None, "io_error", f"Failed to open '{file_path}': {exc}"

    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            return None, "not_regular_file", f"Opened path '{file_path}' is not a regular file"
        if fst.st_size > max_bytes:
            return (
                None,
                "output_limit_exceeded",
                f"File '{file_path}' size ({fst.st_size} bytes) exceeds max_output_bytes ({max_bytes} bytes)",
            )
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                return (
                    None,
                    "output_limit_exceeded",
                    f"File '{file_path}' grew beyond max_output_bytes ({max_bytes} bytes) while reading",
                )
            chunks.append(chunk)
        return b"".join(chunks), None, None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _escape_json_pointer(token: str) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def _is_strict_int(val) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)


def _int_to_hex(val: int) -> str:
    if val < 0:
        return f"-0x{format(-val, 'x')}"
    return f"0x{format(val, 'x')}"


class _CapaSchemaError(Exception):
    def __init__(self, code: str, message: str, json_pointer: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.json_pointer = json_pointer


_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-[A-Za-z0-9._-]+)?$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_SUPPORTED_STATEMENT_TYPES = {
    "and",
    "or",
    "not",
    "optional",
    "some",
    "range",
    "subscope",
    "compound",
    "description",
}

_SUPPORTED_FEATURE_TYPES = {
    "mnemonic",
    "number",
    "offset",
    "operand number",
    "operand offset",
    "string",
    "bytes",
    "api",
    "import",
    "export",
    "section",
    "match",
    "regex",
    "substring",
    "characteristic",
    "basic block",
    "os",
    "arch",
    "format",
    "class",
    "namespace",
    "property",
    "global",
    "function-name",
}


def _extract_int_tuple(raw_val, min_len: int, max_len: int, dict_keys, ptr: str):
    if isinstance(raw_val, list):
        if len(raw_val) < min_len or len(raw_val) > max_len:
            raise _CapaSchemaError(
                "invalid_address",
                f"Address value at '{ptr}' must be an integer list of length {min_len}..{max_len}, got {len(raw_val)}",
                ptr,
            )
        for idx, item in enumerate(raw_val):
            if not _is_strict_int(item):
                raise _CapaSchemaError(
                    "invalid_address",
                    f"Address tuple element {idx} at '{ptr}' must be an integer",
                    f"{ptr}/value/{idx}",
                )
        return list(raw_val)
    if isinstance(raw_val, dict):
        extracted = []
        for k in dict_keys:
            if k in raw_val and raw_val[k] is not None:
                if not _is_strict_int(raw_val[k]):
                    raise _CapaSchemaError(
                        "invalid_address",
                        f"Address field '{k}' at '{ptr}' must be an integer",
                        f"{ptr}/value/{k}",
                    )
                extracted.append(raw_val[k])
        if len(extracted) < min_len or len(extracted) > max_len:
            raise _CapaSchemaError(
                "invalid_address",
                f"Address object at '{ptr}' is missing required integer fields ({', '.join(dict_keys)})",
                ptr,
            )
        return extracted
    raise _CapaSchemaError(
        "invalid_address",
        f"Address value at '{ptr}' must be a tuple/list or object of integers",
        ptr,
    )


def _normalize_address(raw_addr, ptr: str) -> dict:
    if not isinstance(raw_addr, dict):
        raise _CapaSchemaError(
            "invalid_address",
            f"Address at '{ptr}' must be a JSON object, got {type(raw_addr).__name__}",
            ptr,
        )
    raw_type = raw_addr.get("type")
    if not isinstance(raw_type, str) or not raw_type.strip():
        raise _CapaSchemaError(
            "invalid_address",
            f"Address at '{ptr}' is missing a non-empty string 'type'",
            ptr,
        )
    norm_type = raw_type.strip().lower()
    raw_val = raw_addr.get("value")

    if norm_type in ("no address", "no_address", "none"):
        if raw_val is not None:
            raise _CapaSchemaError(
                "invalid_address",
                f"'no address' entry at '{ptr}' must not carry a non-null 'value'",
                ptr,
            )
        return {
            "kind": "no_address",
            "raw_type": raw_type,
            "has_address": False,
            "value": None,
            "decimal": None,
            "hex": None,
            "display": "no address",
            "json_pointer": ptr,
        }

    if norm_type == "absolute":
        if not _is_strict_int(raw_val):
            raise _CapaSchemaError(
                "invalid_address",
                f"Absolute address at '{ptr}' requires an integer 'value'",
                ptr,
            )
        hex_str = _int_to_hex(raw_val)
        return {
            "kind": "absolute",
            "raw_type": raw_type,
            "has_address": True,
            "value": hex_str,
            "decimal": str(raw_val),
            "hex": hex_str,
            "display": f"va:{hex_str}",
            "json_pointer": ptr,
        }

    if norm_type == "relative":
        if not _is_strict_int(raw_val):
            raise _CapaSchemaError(
                "invalid_address",
                f"Relative address at '{ptr}' requires an integer 'value'",
                ptr,
            )
        hex_str = _int_to_hex(raw_val)
        return {
            "kind": "relative",
            "raw_type": raw_type,
            "has_address": True,
            "value": hex_str,
            "decimal": str(raw_val),
            "hex": hex_str,
            "display": f"rva:{hex_str}",
            "json_pointer": ptr,
        }

    if norm_type in ("file", "file_offset", "file offset"):
        if not _is_strict_int(raw_val):
            raise _CapaSchemaError(
                "invalid_address",
                f"File offset address at '{ptr}' requires an integer 'value'",
                ptr,
            )
        hex_str = _int_to_hex(raw_val)
        return {
            "kind": "file_offset",
            "raw_type": raw_type,
            "has_address": True,
            "value": hex_str,
            "decimal": str(raw_val),
            "hex": hex_str,
            "display": f"file:{hex_str}",
            "json_pointer": ptr,
        }

    if norm_type in ("dn token", "dn_token", "dotnet_token", ".net token"):
        if _is_strict_int(raw_val):
            hex_str = _int_to_hex(raw_val)
            dec_str = str(raw_val)
            return {
                "kind": "dotnet_token",
                "raw_type": raw_type,
                "has_address": True,
                "value": hex_str,
                "decimal": dec_str,
                "hex": hex_str,
                "display": f"token:{hex_str}",
                "token": {
                    "decimal": dec_str,
                    "hex": hex_str,
                },
                "json_pointer": ptr,
            }
        parts = _extract_int_tuple(raw_val, 2, 2, ("token", "offset"), ptr)
        tok_hex = _int_to_hex(parts[0])
        off_hex = _int_to_hex(parts[1])
        return {
            "kind": "dotnet_token_offset",
            "raw_type": raw_type,
            "has_address": True,
            "value": f"{tok_hex}+{off_hex}",
            "decimal": f"{parts[0]}+{parts[1]}",
            "hex": f"{tok_hex}+{off_hex}",
            "display": f"token:{tok_hex}+{off_hex}",
            "token": {
                "decimal": str(parts[0]),
                "hex": tok_hex,
                "offset_decimal": str(parts[1]),
                "offset_hex": off_hex,
            },
            "json_pointer": ptr,
        }

    if norm_type in ("dn token offset", "dn_token_offset", "dotnet_token_offset", ".net token offset"):
        parts = _extract_int_tuple(raw_val, 2, 2, ("token", "offset"), ptr)
        tok_hex = _int_to_hex(parts[0])
        off_hex = _int_to_hex(parts[1])
        return {
            "kind": "dotnet_token_offset",
            "raw_type": raw_type,
            "has_address": True,
            "value": f"{tok_hex}+{off_hex}",
            "decimal": f"{parts[0]}+{parts[1]}",
            "hex": f"{tok_hex}+{off_hex}",
            "display": f"token:{tok_hex}+{off_hex}",
            "token": {
                "decimal": str(parts[0]),
                "hex": tok_hex,
                "offset_decimal": str(parts[1]),
                "offset_hex": off_hex,
            },
            "json_pointer": ptr,
        }

    if norm_type == "process":
        if _is_strict_int(raw_val):
            parts = [raw_val]
        else:
            parts = _extract_int_tuple(raw_val, 1, 2, ("pid", "ppid"), ptr)
        parts_dec = [str(p) for p in parts]
        parts_hex = [_int_to_hex(p) for p in parts]
        pid_dec = parts_dec[0]
        ppid_dec = parts_dec[1] if len(parts_dec) > 1 else None
        val_str = f"pid={pid_dec}" + (f",ppid={ppid_dec}" if ppid_dec is not None else "")
        dyn = {
            "pid": pid_dec,
            "parts_decimal": parts_dec,
            "parts_hex": parts_hex,
        }
        if ppid_dec is not None:
            dyn["ppid"] = ppid_dec
        return {
            "kind": "process",
            "raw_type": raw_type,
            "has_address": True,
            "value": val_str,
            "decimal": ":".join(parts_dec),
            "hex": ":".join(parts_hex),
            "display": f"process({val_str})",
            "dynamic": dyn,
            "json_pointer": ptr,
        }

    if norm_type == "thread":
        parts = _extract_int_tuple(raw_val, 2, 3, ("pid", "ppid", "tid"), ptr)
        parts_dec = [str(p) for p in parts]
        parts_hex = [_int_to_hex(p) for p in parts]
        if len(parts_dec) == 3:
            pid_dec, ppid_dec, tid_dec = parts_dec[0], parts_dec[1], parts_dec[2]
        else:
            pid_dec, ppid_dec, tid_dec = parts_dec[0], None, parts_dec[1]
        val_str = f"pid={pid_dec}" + (f",ppid={ppid_dec}" if ppid_dec is not None else "") + f",tid={tid_dec}"
        dyn = {
            "pid": pid_dec,
            "tid": tid_dec,
            "parts_decimal": parts_dec,
            "parts_hex": parts_hex,
        }
        if ppid_dec is not None:
            dyn["ppid"] = ppid_dec
        return {
            "kind": "thread",
            "raw_type": raw_type,
            "has_address": True,
            "value": val_str,
            "decimal": ":".join(parts_dec),
            "hex": ":".join(parts_hex),
            "display": f"thread({val_str})",
            "dynamic": dyn,
            "json_pointer": ptr,
        }

    if norm_type == "call":
        parts = _extract_int_tuple(raw_val, 3, 4, ("pid", "ppid", "tid", "id"), ptr)
        parts_dec = [str(p) for p in parts]
        parts_hex = [_int_to_hex(p) for p in parts]
        if len(parts_dec) == 4:
            pid_dec, ppid_dec, tid_dec, call_id_dec = parts_dec[0], parts_dec[1], parts_dec[2], parts_dec[3]
        else:
            pid_dec, ppid_dec, tid_dec, call_id_dec = parts_dec[0], None, parts_dec[1], parts_dec[2]
        val_str = (
            f"pid={pid_dec}"
            + (f",ppid={ppid_dec}" if ppid_dec is not None else "")
            + f",tid={tid_dec},id={call_id_dec}"
        )
        dyn = {
            "pid": pid_dec,
            "tid": tid_dec,
            "call_id": call_id_dec,
            "parts_decimal": parts_dec,
            "parts_hex": parts_hex,
        }
        if ppid_dec is not None:
            dyn["ppid"] = ppid_dec
        return {
            "kind": "call",
            "raw_type": raw_type,
            "has_address": True,
            "value": val_str,
            "decimal": ":".join(parts_dec),
            "hex": ":".join(parts_hex),
            "display": f"call({val_str})",
            "dynamic": dyn,
            "json_pointer": ptr,
        }

    raise _CapaSchemaError(
        "unsupported_address_type",
        f"Unsupported capa address type '{raw_type}' at '{ptr}'",
        ptr,
    )


def _normalize_feature_detail(raw_feat: dict, ptr: str) -> dict:
    feat_type = raw_feat.get("type")
    if not isinstance(feat_type, str) or not feat_type.strip():
        raise _CapaSchemaError(
            "invalid_feature",
            f"Feature node at '{ptr}' is missing a string 'type'",
            ptr,
        )
    norm_type = feat_type.strip().lower()
    if norm_type not in _SUPPORTED_FEATURE_TYPES:
        raise _CapaSchemaError(
            "unsupported_feature_type",
            f"Unsupported capa feature type '{feat_type}' at '{ptr}'",
            ptr,
        )

    out = {"type": norm_type}
    desc = raw_feat.get("description")
    if isinstance(desc, str) and desc:
        out["description"] = desc

    if norm_type in ("number", "offset", "operand number", "operand offset"):
        val_key = "number" if "number" in norm_type else "offset"
        raw_num = raw_feat.get(val_key, raw_feat.get(norm_type))
        if not _is_strict_int(raw_num):
            raise _CapaSchemaError(
                "invalid_feature",
                f"Feature '{norm_type}' at '{ptr}' requires an integer value",
                ptr,
            )
        hex_str = _int_to_hex(raw_num)
        dec_str = str(raw_num)
        out["value"] = hex_str
        out["decimal"] = dec_str
        out["hex"] = hex_str
        if _is_strict_int(raw_feat.get("index")):
            out["operand_index"] = raw_feat["index"]
        if isinstance(raw_feat.get("bitness"), str):
            out["bitness"] = raw_feat["bitness"]
        return out

    if norm_type == "property":
        prop_val = raw_feat.get("property")
        if not isinstance(prop_val, str):
            raise _CapaSchemaError("invalid_feature", f"Feature 'property' at '{ptr}' requires a string value", ptr)
        out["value"] = prop_val
        if isinstance(raw_feat.get("access"), str):
            out["access"] = raw_feat["access"]
        return out

    if norm_type == "regex":
        reg_val = raw_feat.get("regex")
        if not isinstance(reg_val, str):
            raise _CapaSchemaError("invalid_feature", f"Feature 'regex' at '{ptr}' requires a string pattern", ptr)
        out["value"] = reg_val
        if isinstance(raw_feat.get("match"), str):
            out["match"] = raw_feat["match"]
        return out

    if norm_type == "basic block":
        out["value"] = "basic block"
        return out

    key_candidates = [norm_type, feat_type, "value", "name"]
    str_val = None
    for cand in key_candidates:
        v = raw_feat.get(cand)
        if isinstance(v, str):
            str_val = v
            break
    if str_val is None:
        raise _CapaSchemaError(
            "invalid_feature",
            f"Feature '{norm_type}' at '{ptr}' is missing its string value field",
            ptr,
        )
    out["value"] = str_val
    return out


def _normalize_statement_detail(raw_stmt: dict, ptr: str) -> dict:
    stmt_type = raw_stmt.get("type")
    if not isinstance(stmt_type, str) or not stmt_type.strip():
        raise _CapaSchemaError(
            "invalid_statement",
            f"Statement node at '{ptr}' is missing a string 'type'",
            ptr,
        )
    norm_type = stmt_type.strip().lower()
    if norm_type not in _SUPPORTED_STATEMENT_TYPES:
        raise _CapaSchemaError(
            "unsupported_statement_type",
            f"Unsupported capa statement type '{stmt_type}' at '{ptr}'",
            ptr,
        )
    out = {"type": norm_type}
    desc = raw_stmt.get("description")
    if isinstance(desc, str) and desc:
        out["description"] = desc
    if norm_type == "some" and _is_strict_int(raw_stmt.get("count")):
        out["count"] = str(raw_stmt["count"])
    if norm_type == "range":
        if _is_strict_int(raw_stmt.get("min")):
            out["min"] = str(raw_stmt["min"])
        if _is_strict_int(raw_stmt.get("max")):
            out["max"] = str(raw_stmt["max"])
        if isinstance(raw_stmt.get("child"), dict):
            out["child_feature"] = _normalize_feature_detail(raw_stmt["child"], f"{ptr}/child")
    if norm_type == "subscope" and isinstance(raw_stmt.get("scope"), str):
        out["scope"] = raw_stmt["scope"]
    return out


def _normalize_match_node(raw_node, ptr: str, leaf_collector: list, depth: int = 0) -> dict:
    if depth > 64:
        raise _CapaSchemaError(
            "max_tree_depth_exceeded",
            f"Match tree at '{ptr}' exceeds maximum nesting depth (64)",
            ptr,
        )
    if not isinstance(raw_node, dict):
        raise _CapaSchemaError(
            "invalid_match_node",
            f"Match tree node at '{ptr}' must be an object, got {type(raw_node).__name__}",
            ptr,
        )
    success = raw_node.get("success")
    if not isinstance(success, bool):
        raise _CapaSchemaError(
            "invalid_match_node",
            f"Match tree node at '{ptr}' requires a boolean 'success' field",
            ptr,
        )
    inner = raw_node.get("node")
    if not isinstance(inner, dict):
        raise _CapaSchemaError(
            "invalid_match_node",
            f"Match tree node at '{ptr}' requires an object 'node' descriptor",
            ptr,
        )
    node_kind_raw = inner.get("type")
    if node_kind_raw not in ("statement", "feature"):
        raise _CapaSchemaError(
            "invalid_match_node",
            f"Match tree node.type at '{ptr}/node' must be 'statement' or 'feature', got '{node_kind_raw}'",
            f"{ptr}/node",
        )

    raw_locations = raw_node.get("locations", [])
    if not isinstance(raw_locations, list):
        raise _CapaSchemaError(
            "invalid_match_node",
            f"Match tree 'locations' at '{ptr}/locations' must be an array",
            f"{ptr}/locations",
        )
    locations = [
        _normalize_address(loc, f"{ptr}/locations/{idx}") for idx, loc in enumerate(raw_locations)
    ]

    raw_captures = raw_node.get("captures", {})
    if not isinstance(raw_captures, dict):
        raise _CapaSchemaError(
            "invalid_match_node",
            f"Match tree 'captures' at '{ptr}/captures' must be an object",
            f"{ptr}/captures",
        )
    captures = {}
    for cap_key, cap_locs in raw_captures.items():
        if not isinstance(cap_key, str) or not isinstance(cap_locs, list):
            raise _CapaSchemaError(
                "invalid_match_node",
                f"Capture entry '{cap_key}' at '{ptr}/captures' must map string to location array",
                f"{ptr}/captures/{_escape_json_pointer(cap_key)}",
            )
        cap_ptr = f"{ptr}/captures/{_escape_json_pointer(cap_key)}"
        captures[cap_key] = [
            _normalize_address(loc, f"{cap_ptr}/{idx}") for idx, loc in enumerate(cap_locs)
        ]

    raw_children = raw_node.get("children", [])
    if not isinstance(raw_children, list):
        raise _CapaSchemaError(
            "invalid_match_node",
            f"Match tree 'children' at '{ptr}/children' must be an array",
            f"{ptr}/children",
        )
    children = [
        _normalize_match_node(ch, f"{ptr}/children/{idx}", leaf_collector, depth + 1)
        for idx, ch in enumerate(raw_children)
    ]

    if node_kind_raw == "statement":
        raw_stmt = inner.get("statement")
        if not isinstance(raw_stmt, dict):
            raise _CapaSchemaError(
                "invalid_match_node",
                f"Statement node at '{ptr}/node' is missing object 'statement'",
                f"{ptr}/node",
            )
        stmt_detail = _normalize_statement_detail(raw_stmt, f"{ptr}/node/statement")
        return {
            "json_pointer": ptr,
            "node_kind": "statement",
            "type": stmt_detail["type"],
            "success": success,
            "statement": stmt_detail,
            "locations": locations,
            "captures": captures,
            "children": children,
        }

    raw_feat = inner.get("feature")
    if not isinstance(raw_feat, dict):
        raise _CapaSchemaError(
            "invalid_match_node",
            f"Feature node at '{ptr}/node' is missing object 'feature'",
            f"{ptr}/node",
        )
    feat_detail = _normalize_feature_detail(raw_feat, f"{ptr}/node/feature")
    leaf_entry = {
        "json_pointer": ptr,
        "type": feat_detail["type"],
        "value": feat_detail.get("value"),
        "decimal": feat_detail.get("decimal"),
        "hex": feat_detail.get("hex"),
        "description": feat_detail.get("description"),
        "success": success,
        "locations": locations,
        "captures": captures,
    }
    leaf_collector.append(leaf_entry)

    return {
        "json_pointer": ptr,
        "node_kind": "feature",
        "type": feat_detail["type"],
        "success": success,
        "feature": feat_detail,
        "locations": locations,
        "captures": captures,
        "children": children,
    }


def _parse_and_validate_capa_document(doc) -> dict:
    if not isinstance(doc, dict):
        raise _CapaSchemaError(
            "invalid_schema",
            f"Capa report root must be a JSON object, got {type(doc).__name__}",
            "",
        )

    if "schema_version" in doc and str(doc.get("schema_version")) not in ("1", "2", "3"):
        raise _CapaSchemaError(
            "unsupported_version",
            f"Unsupported top-level schema_version '{doc.get('schema_version')}' in capa report",
            "/schema_version",
        )

    meta = doc.get("meta")
    if not isinstance(meta, dict):
        raise _CapaSchemaError("invalid_schema", "Capa report is missing required object '/meta'", "/meta")

    rules_raw = doc.get("rules")
    if not isinstance(rules_raw, dict):
        raise _CapaSchemaError("invalid_schema", "Capa report is missing required object '/rules'", "/rules")

    version_str = meta.get("version")
    if not isinstance(version_str, str) or not version_str.strip():
        raise _CapaSchemaError(
            "unsupported_version",
            "Capa report '/meta/version' must be a non-empty version string",
            "/meta/version",
        )
    ver_match = _VERSION_RE.match(version_str.strip())
    if not ver_match:
        raise _CapaSchemaError(
            "unsupported_version",
            f"Unrecognized capa version format '{version_str}' at '/meta/version'",
            "/meta/version",
        )
    major_ver = int(ver_match.group(1))
    if major_ver not in (9, 10):
        raise _CapaSchemaError(
            "unsupported_version",
            f"Unsupported capa result document version '{version_str}' (major {major_ver}; supported: v9, v10)",
            "/meta/version",
        )

    sample = meta.get("sample")
    if not isinstance(sample, dict):
        raise _CapaSchemaError(
            "invalid_schema",
            "Capa report '/meta/sample' must be an object",
            "/meta/sample",
        )
    sample_sha256 = sample.get("sha256")
    if not isinstance(sample_sha256, str) or not _SHA256_RE.match(sample_sha256.strip()):
        raise _CapaSchemaError(
            "invalid_schema",
            "Capa report '/meta/sample/sha256' must be a 64-character hexadecimal SHA-256 string",
            "/meta/sample/sha256",
        )

    analysis = meta.get("analysis")
    if not isinstance(analysis, dict):
        raise _CapaSchemaError(
            "invalid_schema",
            "Capa report '/meta/analysis' must be an object",
            "/meta/analysis",
        )

    for req_field in ("format", "arch", "os", "extractor"):
        val = analysis.get(req_field)
        if not isinstance(val, str) or not val.strip():
            raise _CapaSchemaError(
                "invalid_schema",
                f"Capa report '/meta/analysis/{req_field}' must be a non-empty string",
                f"/meta/analysis/{req_field}",
            )

    flavor_raw = meta.get("flavor")
    if flavor_raw is not None:
        if not isinstance(flavor_raw, str) or flavor_raw.strip().lower() not in ("static", "dynamic"):
            raise _CapaSchemaError(
                "unsupported_flavor",
                f"Unsupported capa analysis flavor '{flavor_raw}' at '/meta/flavor' (expected 'static' or 'dynamic')",
                "/meta/flavor",
            )
        flavor = flavor_raw.strip().lower()
    else:
        fmt_lower = analysis["format"].strip().lower()
        flavor = "dynamic" if fmt_lower in ("cape", "drakvuf", "vmray") else "static"

    base_addr_raw = analysis.get("base_address")
    base_address = (
        _normalize_address(base_addr_raw, "/meta/analysis/base_address")
        if base_addr_raw is not None
        else None
    )

    raw_reported_rules = analysis.get("rules")
    reported_rules = []
    if isinstance(raw_reported_rules, list):
        reported_rules = [str(item) for item in raw_reported_rules if isinstance(item, str)]
    elif isinstance(raw_reported_rules, str):
        reported_rules = [raw_reported_rules]

    feat_counts_raw = analysis.get("feature_counts")
    feature_counts = {"file": 0, "functions": [], "processes": []}
    if isinstance(feat_counts_raw, dict):
        if _is_strict_int(feat_counts_raw.get("file")):
            feature_counts["file"] = feat_counts_raw["file"]
        raw_funcs = feat_counts_raw.get("functions")
        if isinstance(raw_funcs, list):
            for idx, fn_entry in enumerate(raw_funcs):
                if isinstance(fn_entry, dict) and "address" in fn_entry:
                    fn_addr = _normalize_address(
                        fn_entry["address"],
                        f"/meta/analysis/feature_counts/functions/{idx}/address",
                    )
                    fn_count = fn_entry.get("count", 0)
                    feature_counts["functions"].append(
                        {
                            "address": fn_addr,
                            "count": fn_count if _is_strict_int(fn_count) else 0,
                        }
                    )
        raw_procs = feat_counts_raw.get("processes")
        if isinstance(raw_procs, list):
            for idx, pr_entry in enumerate(raw_procs):
                if isinstance(pr_entry, dict) and "address" in pr_entry:
                    pr_addr = _normalize_address(
                        pr_entry["address"],
                        f"/meta/analysis/feature_counts/processes/{idx}/address",
                    )
                    pr_count = pr_entry.get("count", 0)
                    feature_counts["processes"].append(
                        {
                            "address": pr_addr,
                            "count": pr_count if _is_strict_int(pr_count) else 0,
                        }
                    )

    lib_funcs_raw = analysis.get("library_functions")
    library_functions_count = len(lib_funcs_raw) if isinstance(lib_funcs_raw, list) else 0

    normalized_rules = []
    for rule_key in sorted(rules_raw.keys()):
        rule_obj = rules_raw[rule_key]
        rule_ptr = f"/rules/{_escape_json_pointer(rule_key)}"
        if not isinstance(rule_obj, dict):
            raise _CapaSchemaError(
                "invalid_schema",
                f"Rule entry at '{rule_ptr}' must be an object",
                rule_ptr,
            )
        rmeta = rule_obj.get("meta")
        if not isinstance(rmeta, dict):
            raise _CapaSchemaError(
                "invalid_schema",
                f"Rule '{rule_key}' at '{rule_ptr}' is missing object 'meta'",
                f"{rule_ptr}/meta",
            )

        rule_name = rmeta.get("name") if isinstance(rmeta.get("name"), str) and rmeta.get("name").strip() else rule_key
        namespace = rmeta.get("namespace") if isinstance(rmeta.get("namespace"), str) and rmeta.get("namespace").strip() else None

        scopes_raw = rmeta.get("scopes")
        static_scope = None
        dynamic_scope = None
        if isinstance(scopes_raw, dict):
            if isinstance(scopes_raw.get("static"), str):
                static_scope = scopes_raw["static"]
            if isinstance(scopes_raw.get("dynamic"), str):
                dynamic_scope = scopes_raw["dynamic"]
        elif isinstance(rmeta.get("scope"), str):
            static_scope = rmeta["scope"]

        primary_scope = (
            (dynamic_scope or static_scope or "unknown")
            if flavor == "dynamic"
            else (static_scope or dynamic_scope or "unknown")
        )

        matches_raw = rule_obj.get("matches")
        if not isinstance(matches_raw, list):
            raise _CapaSchemaError(
                "invalid_schema",
                f"Rule '{rule_key}' at '{rule_ptr}/matches' must be an array of [address, node] pairs",
                f"{rule_ptr}/matches",
            )

        norm_matches = []
        for m_idx, pair in enumerate(matches_raw):
            pair_ptr = f"{rule_ptr}/matches/{m_idx}"
            if not isinstance(pair, list) or len(pair) != 2:
                raise _CapaSchemaError(
                    "invalid_schema",
                    f"Match entry at '{pair_ptr}' must be a 2-element [address, match_node] array",
                    pair_ptr,
                )
            match_addr = _normalize_address(pair[0], f"{pair_ptr}/0")
            if primary_scope == "file" and match_addr["kind"] != "no_address":
                raise _CapaSchemaError(
                    "invalid_address",
                    f"File-scope rule '{rule_name}' match at '{pair_ptr}/0' must have 'no address', got '{match_addr['raw_type']}'",
                    f"{pair_ptr}/0",
                )
            leaf_features = []
            match_tree = _normalize_match_node(pair[1], f"{pair_ptr}/1", leaf_features, 0)
            norm_matches.append(
                {
                    "match_index": m_idx,
                    "json_pointer": pair_ptr,
                    "address": match_addr,
                    "success": match_tree["success"],
                    "tree": match_tree,
                    "leaf_features": leaf_features,
                }
            )

        source_str = rule_obj.get("source") if isinstance(rule_obj.get("source"), str) else None
        source_ptr = f"{rule_ptr}/source" if source_str is not None else f"{rule_ptr}/meta"

        authors = [str(a) for a in rmeta.get("authors", []) if isinstance(a, str)] if isinstance(rmeta.get("authors"), list) else []
        references = [str(r) for r in rmeta.get("references", []) if isinstance(r, str)] if isinstance(rmeta.get("references"), list) else []
        description = rmeta.get("description") if isinstance(rmeta.get("description"), str) else None
        attack_list = rmeta.get("attack") if isinstance(rmeta.get("attack"), list) else []
        mbc_list = rmeta.get("mbc") if isinstance(rmeta.get("mbc"), list) else []

        normalized_rules.append(
            {
                "rule_key": rule_key,
                "rule_name": rule_name,
                "namespace": namespace,
                "scopes": {
                    "static": static_scope,
                    "dynamic": dynamic_scope,
                },
                "primary_scope": primary_scope,
                "is_subscope_rule": bool(rmeta.get("is_subscope_rule", False)),
                "is_library_rule": bool(rmeta.get("lib", False)),
                "authors": authors,
                "description": description,
                "attack": attack_list,
                "mbc": mbc_list,
                "references": references,
                "source": source_str,
                "json_pointer": rule_ptr,
                "source_json_pointer": source_ptr,
                "match_count": len(norm_matches),
                "matches": norm_matches,
            }
        )

    return {
        "meta": {
            "timestamp": str(meta.get("timestamp") or ""),
            "version": version_str.strip(),
            "argv": [str(x) for x in meta.get("argv", [])] if isinstance(meta.get("argv"), list) else [],
            "flavor": flavor,
            "sample": {
                "sha256": sample_sha256.strip().lower(),
                "md5": str(sample.get("md5") or "").strip().lower() or None,
                "sha1": str(sample.get("sha1") or "").strip().lower() or None,
                "reported_path": str(sample.get("path") or "") or None,
            },
            "analysis": {
                "format": analysis["format"].strip(),
                "arch": analysis["arch"].strip(),
                "os": analysis["os"].strip(),
                "extractor": analysis["extractor"].strip(),
                "reported_rules": reported_rules,
                "base_address": base_address,
                "feature_counts": feature_counts,
                "library_functions_count": library_functions_count,
            },
        },
        "rules": normalized_rules,
    }


def main() -> None:
    staging_dir = os.path.dirname(os.path.abspath(__file__))
    _isolate_sys_path(staging_dir)

    try:
        raw_req = sys.stdin.read()
        req = json.loads(raw_req) if raw_req.strip() else {}
    except Exception as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "invalid_worker_request",
                    "error": f"Failed to parse worker request JSON: {exc}",
                }
            )
        )
        return

    json_path = req.get("json_path")
    max_output_bytes = int(req.get("max_output_bytes") or (16 * 1024 * 1024))

    if not isinstance(json_path, str) or not json_path.strip():
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "invalid_worker_request",
                    "error": "Missing required 'json_path' in capability_inspect worker request",
                }
            )
        )
        return

    raw_bytes, err_code, err_msg = _read_regular_file_bounded_nofollow(json_path, max_output_bytes)
    if raw_bytes is None:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": err_code or "io_error",
                    "error": err_msg or f"Failed to read '{json_path}'",
                }
            )
        )
        return

    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    raw_size_bytes = len(raw_bytes)

    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "corrupt_json",
                    "error": f"Capa JSON report is not valid UTF-8: {exc}",
                    "raw_sha256": raw_sha256,
                    "raw_size_bytes": raw_size_bytes,
                }
            )
        )
        return

    if not raw_text.strip():
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "corrupt_json",
                    "error": "Capa JSON report is empty",
                    "raw_sha256": raw_sha256,
                    "raw_size_bytes": raw_size_bytes,
                }
            )
        )
        return

    try:
        doc = json.loads(raw_text)
    except Exception as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "corrupt_json",
                    "error": f"Malformed capa JSON report: {exc}",
                    "raw_sha256": raw_sha256,
                    "raw_size_bytes": raw_size_bytes,
                }
            )
        )
        return

    try:
        normalized = _parse_and_validate_capa_document(doc)
    except _CapaSchemaError as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": exc.code,
                    "error": exc.message,
                    "json_pointer": exc.json_pointer,
                    "raw_sha256": raw_sha256,
                    "raw_size_bytes": raw_size_bytes,
                }
            )
        )
        return
    except Exception as exc:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error_code": "internal_parse_error",
                    "error": f"Unexpected error normalizing capa JSON report: {exc}",
                    "raw_sha256": raw_sha256,
                    "raw_size_bytes": raw_size_bytes,
                }
            )
        )
        return

    sys.stdout.write(
        json.dumps(
            {
                "ok": True,
                "raw_sha256": raw_sha256,
                "raw_size_bytes": raw_size_bytes,
                "document": normalized,
            }
        )
    )


if __name__ == "__main__":
    main()
