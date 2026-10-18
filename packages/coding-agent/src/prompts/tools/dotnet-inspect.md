Native read-only inspection of .NET assemblies and Common Intermediate Language (CIL/MSIL) metadata. Parses PE/COFF structures, the CLR 2.0 header, ECMA-335 metadata streams (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`), type definitions, method signatures, and method CIL bytecode without any external runtime or tool dependencies.

Actions:
- `info`: Assembly name, version, culture, public key token, module MVID, CLR runtime version, flags (ILOnly, 32BitRequired, etc.), entrypoint token, and stream layout. Start here to confirm managed .NET identity.
- `types`: Declared types (`TypeDef`) with namespaces, base types, visibility, method/field counts, and flags (interface, abstract, sealed, class). Supports `filter` and paging (`limit`, `offset`).
- `methods`: Method definitions (`MethodDef`) across types or within a specific type (`type` parameter). Returns names, declaring types, RVA, CIL code sizes, metadata tokens, and method flags. Supports `filter`, `type`, and paging.
- `cil`: Disassemble CIL bytecode into human-readable instructions with opcodes, offsets, raw hex bytes, resolved operands, and annotated MemberRef / UserString references. Specify the method by name (`method`), token (`token`), or symbol (`target`).

Selection and paging:
- `limit`: Maximum items or CIL instructions returned (default 50 for lists, 100 for CIL; capped at 500/2000).
- `offset`: Zero-based pagination offset.
- `type`: Target type name filter (e.g. `Program`, `SecurityService`, or full `Namespace.ClassName`).
- `method`: Method name (e.g. `Main`, `VerifyKey`, `Decrypt`) or metadata token (e.g. `0x06000001`).
- `filter`: Substring search across type or method names.

Safety:
- Pure local parser: operates in-process with zero network or external process spawning.
- Safe path resolution against session cwd.
- Non-.NET PE binaries or native binaries return `status: "unsupported"` with a clear diagnostic explanation.

<examples>
```
dotnet_inspect(action: "info", path: "target.dll")
dotnet_inspect(action: "types", path: "target.dll", limit: 50)
dotnet_inspect(action: "types", path: "target.dll", filter: "Auth")
dotnet_inspect(action: "methods", path: "target.dll", type: "LicenseValidator")
dotnet_inspect(action: "cil", path: "target.dll", method: "ValidateLicense")
dotnet_inspect(action: "cil", path: "target.dll", token: "0x06000004", limit: 60)
```
</examples>
