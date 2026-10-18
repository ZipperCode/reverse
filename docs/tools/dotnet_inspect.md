# dotnet_inspect

> Native read-only inspection of .NET assemblies and Common Intermediate Language (CIL/MSIL) metadata without external dependencies.

## Source
- Entry: `packages/coding-agent/src/tools/dotnet-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/dotnet-inspect.md`

## Overview
`dotnet_inspect` is an in-process, zero-dependency parser for .NET PE/COFF binaries (`.dll`, `.exe`). It parses DOS/PE headers, the CLR runtime header (`IMAGE_COR20_HEADER`), ECMA-335 metadata streams (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`), table definitions (`TypeDef`, `MethodDef`, `Assembly`, `TypeRef`, `MemberRef`, etc.), and CIL method bodies directly from file bytes.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `info \| types \| methods \| cil` | Yes | Inspection action to perform. |
| `path` | `string` | Yes | Path to .NET PE assembly, resolved against session cwd. |
| `type` | `string` | No | Target type name or namespace filter for `types`, `methods`, or `cil`. |
| `method` | `string` | No | Method name (e.g. `Main`, `Calculate`) or token (e.g. `0x06000001`) for `cil`. |
| `token` | `string` | No | Hex metadata token (e.g. `0x06000001` or `0x02000002`). |
| `filter` | `string` | No | Substring filter across type or method names. |
| `limit` | `number >= 1` | No | Maximum items or CIL instructions returned (default 50 for lists, 100 for CIL, capped at 500/2000). |
| `offset` | `number >= 0` | No | Zero-based pagination offset. |
| `max_bytes` | `number >= 1` | No | Maximum file bytes to read or cap. |

## Actions
- `info`: Discovers assembly identity (name, version, culture, public key token), module info, CLR runtime version, flags (ILOnly, 32BitRequired, etc.), entrypoint token, streams present, and summary counts.
- `types`: Lists declared types (`TypeDef`) with full names, base types/extends, visibility, flags (interface, abstract, sealed, class), and member counts.
- `methods`: Lists method definitions (`MethodDef`) across the assembly or scoped to a type, including RVA, code size, flags (public, static, virtual), and token.
- `cil`: Disassembles method CIL instructions into structured and text listings: offset, opcode, bytes, operands, and resolved MemberRef / UserString annotations.

## Non-.NET and Native Binaries
When executed against a native binary (e.g. non-PE or standard PE without a CLR COM descriptor), `dotnet_inspect` safely returns `status: "unsupported"` with an explanation without failing the agent turn.

## Limits & Caps
- Maximum file size read: 500 MiB.
- Default limit: 50 items for `types` / `methods`, 100 instructions for `cil`.
- Hard upper cap: 500 for list queries, 2000 for CIL disassembly instructions.
