Capability-driven runtime dispatch and host environment capability query tool.

Inspects canonical reverse engineering capabilities (such as APK decompilation, native binary debugging, Android native library emulation, browser CDP dynamic inspection, WebSocket capture, JavaScript de-obfuscation, and network traffic interception) to check host readiness, resolve recommended native zero-prep tools, discover available fallbacks, and retrieve trusted setup commands.

Actions:
- `list`: Enumerate all canonical reverse engineering capabilities, their target scenarios, recommended native tools, external tool requirements, fallbacks, and trusted setup commands.
- `resolve`: Evaluate host system availability for all (or a specific) reverse engineering capabilities. Checks whether external tools are installed on PATH or configured in MCP (MCP services require both runtime prerequisites and explicit configuration/enablement in `mcp.json`; Node/Java alone never marks dynamic services ready), surfaces available fallbacks, and provides model-actionable setup commands.
- `get`: Inspect a specific reverse engineering capability in detail by canonical ID, returning its operational description, problem rationale, readiness status, external tool statuses, available fallbacks, trusted setup command, and post-installation invocation guidance.
- `install`: Install the trusted `jshookmcp` MCP service with write approval, verify its MCP handshake, save the user/project configuration, and connect its tools in the current session. Uses a managed local pinned package with `webcrack`, search profile, and vector search disabled. Requires supported Node.js and npm; installation can download packages and compile native dependencies. Other catalog installers retain their interactive confirmation flow.

Workflow Guidance:
1. Call `reverse_capability(action: "resolve")` at the beginning of an investigation to understand host tool availability.
2. If an external tool is missing, prefer the `recommendedNativeTool` (which is zero-dependency and built-in, e.g. `android_package_inspect`, `r2_inspect`, `websocket_observe`) or available fallbacks.
3. If an external capability is needed, use the `setupCommand` (e.g. `reverse setup reverse apktool`) to guide the operator through interactive installation, then follow `postInstallInvocation`.
4. For frontend debugging or deobfuscation requiring jshookmcp, call `reverse_capability(action: "install", service: "jshookmcp")` after the user authorizes installation. Then use the mounted jshook `search_tools` → `describe_tool` → `call_tool` flow. Let one controller own each browser target; retain native tools for independent static analysis.

<examples>
```
// 1. List all canonical capabilities in the catalog
reverse_capability(action: "list")

// 2. Resolve host system readiness for all capabilities
reverse_capability(action: "resolve")

// 3. Resolve host readiness for APK unpacking
reverse_capability(action: "resolve", capability: "apk_unpacking")

// 4. Inspect detailed native debugger capability and post-install invocation
reverse_capability(action: "get", capability: "native_debugger")

// 5. Provision and connect jshookmcp (write approval; default active-profile user scope)
reverse_capability(action: "install", service: "jshookmcp")
```
</examples>
