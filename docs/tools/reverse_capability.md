# reverse_capability

能力驱动运行时调度与环境能力查询工具。

## 作用

在逆向会话中原生发现、解析和查询高层逆向工程能力（如 APK 反编译、原生二进制调试、Android JNI 模拟、浏览器 CDP 动态调试、WebSocket 抓包、JS 反混淆、流量拦截等）的就绪状态、推荐内置原生工具、可用降级方案、受信安装命令以及安装后的调用指引。

## Actions

- `list`：列出能力目录中的所有标准能力、对应场景与推荐工具。
- `resolve`：解析当前主机环境的可用性状态（`ready` / `available_with_fallbacks` / `missing`），检查外部工具与降级工具就绪情况。
- `get`：按能力 ID 查询指定能力的详细描述、Why 分析、环境状态与安装/调用指引。

## 调度规范

1. 优先使用推荐的原生零配置内置工具（如 `android_package_inspect`、`triage`、`websocket_observe`）。
2. 当外部工具缺失时，执行受信 setupCommand（如 `reverse setup reverse radare2`）并在安装后按 `postInstallInvocation` 调用。

## VMP 与符号分析能力

| 能力 ID | 工具 | 后端 |
|---|---|---|
| `symbolic_trace_analysis` | `triton_analyze` | Triton |
| `vmp_dump_repair` | `vmp_dump` | VMPDump |
| `native_function_lifting` | `native_devirtualize` | Mergen |
| `vmp_legacy_devirtualization` | `native_devirtualize` | NoVmp |

四个阶段分别计算就绪状态。安装 Triton 只启用轨迹分析；转储、LLVM 函数提升和旧版 VTIL 恢复各自检测对应后端。`ready` 表示后端可用，具体目标与语义结论仍通过工具执行和独立验证建立。

使用 `reverse setup reverse <后端 ID> --execute` 或 TUI `/setup` 中的逆向工具面板安装。完整方法与平台边界见 `skill://vmp-reverse`。

## `native_debugger` 能力就绪与调度合约

### 1. 真实调试器后端判定

- **就绪标准**：`native_debugger` 的 `ready` 状态（`ready: true`）严格代表主机环境已探知到真实的动态调试器执行后端：
  - **DAP 协议后端**：通过只读配置与 PATH 探测，检测到支持原生二进制语言（C、C++、Rust、Zig、Swift、Objective-C）的调试适配器（如 `lldb-dap`、带 `-i dap` 的 `gdb`、`codelldb`），且在会话设置未禁用 `debug.enabled` 时，推荐内置原生调试工具 `debug`。
  - **Radare2 调试后端**：主机已安装 `radare2`（`r2` 可执行文件就绪）时，通过 `postInstallInvocation` 指向 `r2 -d`；`r2_inspect` 仅用于静态查询。缺少 native DAP 后端时，推荐内置入口为 `triage`。

### 2. 动态插桩与静态反编译降级区分

- **仅安装 Frida（Frida-only）**：Frida 提供动态函数插桩、内存 Hook 与追踪能力（`frida` / `frida_session`），但缺乏单步指令执行、硬件断点与寄存器级 DAP 调试会话控制，判定为 `status: "available_with_fallbacks"`、`ready: false`。且当 `radare2` 缺失时，绝不错误推荐不可用的 `r2_inspect`，而推荐零配置原生兜底工具 `triage`。
- **仅安装 Ghidra（Ghidra-only）**：Ghidra 为无头/静态反编译工具，属于深层静态反编译降级路径，判定为 `status: "available_with_fallbacks"`、`ready: false`。
- **r2mcp 与原生 MCP 服务状态约束**：仅在配置文件中记录但未实际连接，或缺失底层依赖的 r2mcp / x64dbg-mcp / ghidra-mcp 服务，不判定为可用调试后端；需通过 `native_mcp_session` 建立经过真实目标与能力校验的活跃连接。

### 3. 主机后端发现与目标程序权限隔离

- **主机工具链探测边界**：能力解析仅进行只读工具与配置探测（which / 适配器配置检查），绝不启动测试子进程或执行二进制样本。
- **目标验证**：执行阶段单独验证目标架构、设备连接、代码签名、进程权限、断点结果及反调试约束。主机探测只记录后端可发现性。

### 4. 命令行适配器区分

- 普通系统 `lldb` 命令行工具不等同于 `lldb-dap`（需要 DAP 协议通信支持）。
- `gdb` 需支持 `-i dap` 通信模式；适配器解析严格依据实际配置的命令探测。

### 5. IDA Pro 多后端就绪与独立性判定

- **四类独立运行后端**：
  1. **IDA GUI 桌面程序**：用于交互式图形界面逆向与人工研判，通过 `hasIdaBinary` / `probeIdaTool` 探测。
  2. **idalib 无头 SDK**：`idalibAvailable` 表示原生库已安装；`pythonAdapterReady` 表示实际解释器按工作进程环境成功导入 `idapro` 和 `ida_domain`。原生库与 Python 适配器共同决定原生解析后端是否就绪。
  3. **本地数据库 (.idb / .i64)**：格式识别使用 `localDatabaseRecognized`；解析后端就绪使用 `localDatabaseBackendAvailable` / `localDatabaseSupported`，要求原生库与 Python 导入检查通过。实际打开数据库和反编译另行验证。
  4. **MCP 桥接服务 (`ida-mcp`)**：连接外部活跃 IDA 调试/分析会话的桥接插件。
- **桥接缺失不代表 IDA 缺失**：`ida-mcp` 桥接未配置或未连接时，仅说明 MCP 桥接通道未就绪，**绝不判定整个 IDA 安装缺失**；若 GUI 或 `idalib` 存在，仍可分别独立用于桌面分析或无头反编译。
- **非强制性约束**：Native 逆向分析根据目标场景平滑降级，绝不设定硬性外部 IDA 安装数或 MCP 服务连接数要求；零配置内置工具（`triage`）及 `r2_inspect` 在无商业授权或沙盒环境中足以完成基线逆向。
- **依赖修复入口**：`reverse setup reverse ida --execute` 与 TUI `/setup reverse ida` 使用同一安装流程，确认后在实际选定的 Python 中安装 `ida-domain==0.5.1` 并重新探测。显式 `ida.python` 优先；自动探测依次检查当前／项目虚拟环境、受管环境与 PATH。状态包含 `pythonPath`、`pythonVersion`、`missingPackages` 和 `adapterErrorType`，区分缺包、Python 版本过低、解释器缺失及导入失败；GUI 与 MCP 桥接保持独立。
