Manage persistent native reverse engineering MCP sessions for x64dbg, Ghidra, and radare2.

Actions:
- `connect`: Launch or connect to a native MCP service, bootstrap the target, mount full upstream tools dynamically into the agent, and record session state.
- `status`: Inspect connection state, discovered tools, target binding verification, and execution records.
- `list`: List all active owned native MCP sessions and configured services.
- `disconnect`: Cleanly detach and unmount an owned native MCP session without killing the target process or host debugger.
- `locate`: High-precision address mapping between dynamic runtime virtual addresses (VA) and static decompilation image base using BigInt arithmetic.

Supported Services:
1. `x64dbg`: Windows dynamic debugger automation (x64dbg-automate / ghost_fungus).
   - Local start: pass `target` executable path and optional `x64dbg_path`, `cmdline`, `current_dir`.
   - Local attach: pass `session_pid` to attach to an already running x64dbg instance.
   - Remote connect: pass `host`, `req_rep_port`, and `pub_sub_port`.
   - Security Notice: ZeroMQ remote RPC has NO built-in authentication. Always tunnel through private trusted channels or SSH port forwarding (`ssh -L 31337:127.0.0.1:31337 -L 31338:127.0.0.1:31338 user@remote-windows-host`); never expose x64dbg automation ports to untrusted networks.
   - Full upstream tools mounted: `start_session`, `connect_to_session`, `connect_remote`, `disconnect`, `get_debugger_status`, `go`, `pause`, `step_into`, `step_over`, `skip_instruction`, `run_to_return`, `trace_into`, `trace_over`, `read_memory`, `read_memory_many`, `write_memory`, `allocate_memory`, `free_memory`, `get_memory_map`, `get_register`, `set_register`, `get_all_registers`, `eval_expression`, `execute_command`, `set_breakpoint`, `clear_breakpoint`, `toggle_breakpoint`, `list_breakpoints`, `disassemble`, `assemble`, `set_label`, `get_label`, `set_comment`, `get_comment`, `get_symbol`, `create_thread`, `terminate_thread`, `pause_resume_thread`, `switch_thread`, `get_latest_event`, `wait_for_event`, `get_setting`, `set_setting`, `log_message`, `get_log`, `refresh_gui`.

2. `ghidra`: Ghidra MCP server (LaurieWired GhidraMCP 2.0).
   - Headless persistent mode: pass `target` binary path. Maintains a persistent Ghidra project outside `/tmp` across turns with `--save`.
   - GUI mode: omit `target`, specify `backend_url` (defaults to loopback `http://127.0.0.1:8080/`).
   - Full upstream tools mounted: `get_program_info`, `list_functions`, `search_functions_by_name`, `list_classes`, `list_namespaces`, `list_segments`, `list_imports`, `list_exports`, `list_data_items`, `list_strings`, `get_function_by_address`, `decompile_function`, `decompile_function_by_address`, `disassemble_function`, `get_xrefs_to`, `get_xrefs_from`, `get_function_xrefs`, `get_function_calls`, `read_memory`, `rename_function_by_address`, `rename_function`, `rename_data`, `rename_variable`, `set_function_prototype`, `set_local_variable_type`, `set_decompiler_comment`, `set_disassembly_comment`.

3. `radare2`: Persistent radare2 analysis session via r2mcp (`r2pm -r r2mcp`).
   - Opens binary using upstream `open_file` and inspects via `show_info`.
   - Full upstream tools mounted: `open_file`, `show_info`, `list_functions`, `list_functions_tree`, `list_libraries`, `list_imports`, `list_exports`, `list_sections`, `list_symbols`, `list_entrypoints`, `list_strings`, `analyze`, `xrefs_to`, `decompile_function`, `disassemble_function`, `disassemble`, `calculate`, `hexdump`, `lookup_address`, `lookup_symbol`, `lookup_export`, `set_comment`, `set_function_prototype`, `run_command`.

Address Mapping (`locate`):
Bridges dynamic runtime observation and static decompilation:
- Inputs: `runtime_address` (e.g. '0x7ff6a0001000'), `module_base` (e.g. '0x7ff6a0000000'), and optional `static_base` (from Ghidra `image_base`, e.g. '0x140000000').
- Computes:
  - `module_offset` (RVA) = `runtime_address - module_base`
  - `static_address` = `static_base + module_offset`
- Generates evidence locator: `<module_name>+0x<rva> -> static:0x<static_address>`.

<examples>
```
// 1. Connect to Ghidra in headless persistent project mode
native_mcp_session(action: "connect", service: "ghidra", target: "/path/to/binary")

// 2. Connect to local x64dbg and launch target executable
native_mcp_session(action: "connect", service: "x64dbg", target: "C:\\targets\\crackme.exe")

// 3. Connect to remote x64dbg instance over trusted SSH tunnel
native_mcp_session(action: "connect", service: "x64dbg", host: "127.0.0.1", req_rep_port: 31337, pub_sub_port: 31338)

// 4. Connect to radare2 r2mcp session
native_mcp_session(action: "connect", service: "radare2", target: "/path/to/sample.elf")

// 5. Check session status and verify target match
native_mcp_session(action: "status", session_id: "native_ghidra_018f...")

// 6. Map runtime dynamic address to Ghidra static decompilation address
native_mcp_session(action: "locate", runtime_address: "0x7ff6a0001050", module_base: "0x7ff6a0000000", static_base: "0x140000000", module_name: "target.exe")

// 7. Disconnect session cleanly (detaches without terminating target or debugger)
native_mcp_session(action: "disconnect", session_id: "native_x64dbg_018f...")
```
</examples>
