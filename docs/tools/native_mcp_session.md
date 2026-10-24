# native_mcp_session

管理针对 x64dbg、Ghidra 与 radare2 的持久化原生逆向工程 MCP 会话，支持动态挂载上游分析工具、会话隔离与跨轮次复用，以及基于 64 位 BigInt 算术的运行时虚拟地址（VA）到静态反编译基址的高精度映射。

## 安装与发现

- CLI 安装：
  - x64dbg MCP 桥接：`reverse setup reverse x64dbg-mcp --execute`
  - Ghidra MCP 服务：`reverse setup reverse ghidra-mcp --execute`
  - radare2 MCP 插件：`reverse setup reverse r2mcp --execute`
- TUI 入口：`/setup` → 逆向工程工具链 → 选择对应 MCP 工具交互式安装。
- 对应逆向能力：`native_debugger`。
- 方法指引：`skill://native-binary-reverse`、`skill://windows-reverse` 与 `skill://reverse-tool-guide`。

受管 x64dbg/Ghidra 安装在独立 Python 环境中配置依赖（需要 Python >= 3.10）。x64dbg 安装 `x64dbg_automate[mcp]==0.9.2`；GhidraMCP 使用固定 commit 与 SHA-256 校验的官方发布包；radare2 通过 `r2pm -Uci r2mcp` 安装，使用 `r2pm -r r2mcp` 启动。缺失依赖时工具返回明确安装引导，不进行静默后台下载。

## 参数定义

| 参数 | 类型 | 适用动作 | 说明 |
| --- | --- | --- | --- |
| `action` | `connect \| status \| list \| disconnect \| locate \| jni_enrich` | 必填 | 执行的会话操作。 |
| `service` | `x64dbg \| ghidra \| radare2` | `connect` 必填 | 目标原生逆向服务类型。 |
| `session_id` | `string` | `disconnect` 必填；`status`/`locate` 可选 | 会话唯一标识符（如 `native_x64dbg_...`）。 |
| `target` | `string` | `connect` 可选 | 目标二进制文件或样本可执行文件路径。 |
| `project_dir` | `string` | `connect` 可选 | Ghidra 持久化项目目录（默认使用基于样本哈希的存储目录）。 |
| `backend_url` | `string` | `connect` 可选 | Ghidra GUI 后端地址（默认 `http://127.0.0.1:8080/`）。 |
| `x64dbg_path` | `string` | `connect` 可选 | 本地 x64dbg 可执行文件路径（支持环境变量 `X64DBG_PATH`）。 |
| `session_pid` | `number` (整数 >= 1) | `connect` 可选 | 附加到已有 x64dbg 实例的进程 PID。 |
| `cmdline` | `string` | `connect` 可选 | x64dbg 启动目标程序时的命令行参数。 |
| `current_dir` | `string` | `connect` 可选 | x64dbg 启动目标程序时的工作目录。 |
| `host` | `string` | `connect` 可选 | 远程 x64dbg 自动化服务主机或 IP 地址（需通过安全通道/SSH 隧道）。 |
| `req_rep_port` | `number` (1–65535) | `connect` 可选 | 远程 x64dbg REQ/REP 请求响应端口（默认通常为 31337）。 |
| `pub_sub_port` | `number` (1–65535) | `connect` 可选 | 远程 x64dbg PUB/SUB 广播端口（默认通常为 31338）。 |
| `timeout_ms` | `number` (>= 1000) | `connect` 可选 | 连接与引导超时毫秒数（默认 30000）。 |
| `workflow_id` | `string` | 可选 | 关联的 `reverse_workflow` 工作流 ID。 |
| `step_id` | `string` | 可选 | 关联的工作流步骤 ID。 |
| `runtime_address` | `string` | `locate` 必填 | 动态运行时虚拟地址十六进制字符串（如 `"0x7ff6a0001050"`）。 |
| `module_base` | `string` | `locate` 必填 | 运行时模块加载基地址十六进制字符串（如 `"0x7ff6a0000000"`）。 |
| `static_base` | `string` | `locate` 可选 | 静态反编译镜像基地址十六进制字符串（如 `"0x140000000"`）。 |
| `module_name` | `string` | `locate` 可选 | 模块文件名（如 `"main.exe"`），用于证据定位符归属。 |
| `records` | `unknown[]` | `jni_enrich` 可选 | 规范化 JNI 方法记录数组。 |
| `events` | `unknown` | `jni_enrich` 可选 | Frida / Unidbg 动态 JNI 注册原始事件。 |
| `preview` | `boolean` | `jni_enrich` 可选 | 默认 `true`（演练预览）；设为 `false` 执行真实上游工具重命名与原型写入。 |
| `decompile` | `boolean` | `jni_enrich` 可选 | 默认 `true`，在应用新符号与原型后重新反编译输出伪代码。 |
| `batch_size` | `number` (1–100) | `jni_enrich` 可选 | 单批应用的最大函数数量（默认 20）。 |
| `is_static_map` | `unknown` | `jni_enrich` 可选 | DEX `ACC_STATIC` 声明映射，明确指定方法静态或虚函数属性。 |

## 调用示例

### 1. 建立会话与动态挂载 (`connect`)

无头持久化 Ghidra 分析（在 `/tmp` 之外维护项目并使用 `--save`）：
```js
native_mcp_session({
  action: "connect",
  service: "ghidra",
  target: "/path/to/sample.bin"
})
```

本地启动 Windows x64dbg 调试目标：
```js
native_mcp_session({
  action: "connect",
  service: "x64dbg",
  target: "C:\\targets\\crackme.exe"
})
```

通过 SSH 端口转发隧道连接远程 x64dbg 实例：
```js
native_mcp_session({
  action: "connect",
  service: "x64dbg",
  host: "127.0.0.1",
  req_rep_port: 31337,
  pub_sub_port: 31338
})
```

启动 radare2 r2mcp 会话：
```js
native_mcp_session({
  action: "connect",
  service: "radare2",
  target: "/path/to/sample.elf"
})
```

### 2. 状态检查与会话清单 (`status` / `list`)

```js
native_mcp_session({ action: "status", session_id: "native_ghidra_018f..." })
native_mcp_session({ action: "list" })
```

### 3. 动态地址映射 (`locate`)

将断点或崩溃时的动态运行地址换算为 Ghidra/IDA 静态反编译基址：
```js
native_mcp_session({
  action: "locate",
  runtime_address: "0x7ff6a0001050",
  module_base: "0x7ff6a0000000",
  static_base: "0x140000000",
  module_name: "target.exe"
})
```

计算生成 `RVA = runtime_address - module_base` 及 `static_address = static_base + RVA`，并格式化规范证据定位符 `<module_name>+0x<RVA> -> static:0x<static_address>`。结果附带纪律属性 `{ source: "supplied", computation: "arithmetic", evidence_verified: false }`，表明算术映射属于坐标投影，而非经由执行探针实际检验的真值。

### 4. 安全断开与分离 (`disconnect`)

```js
native_mcp_session({
  action: "disconnect",
  session_id: "native_x64dbg_018f..."
})
```

### 5. JNI 动态注册符号与原型丰富化 (`jni_enrich`)

在已连接的 Ghidra 或 radare2 会话中预览并应用 `RegisterNatives` 动态注册的方法名称与 C 原型：
```js
// 1. 演练预览（只读级别）
native_mcp_session({
  action: "jni_enrich",
  session_id: "native_ghidra_018f...",
  events: [
    {
      event: "jni_register_natives",
      status: "confirmed",
      retval: 0,
      class: "com.example.app.SecurityBridge",
      methods: [
        { name: "verifyToken", signature: "(Ljava/lang/String;[B)Z", fnPtr: "0x140001000", base: "0x140000000" }
      ]
    }
  ],
  preview: true
})

// 2. 真实应用（执行级别，动态发现上游 rename_function_by_address 与 set_function_prototype 工具）
native_mcp_session({
  action: "jni_enrich",
  session_id: "native_ghidra_018f...",
  events: [...],
  preview: false,
  is_static_map: { "verifyToken(Ljava/lang/String;[B)Z": true }
})
```

## 生命周期与状态层级

工具生命周期区分 5 个严格的可观测状态层级：
1. `installed`：宿主依赖与受管 Python venv 已就绪（`x64dbg-mcp` / `ghidra-mcp` / `r2mcp`）。
2. `configured`：配置已写入项目或用户 `mcp.json`。
3. `transport connected`：Stdio、ZeroMQ 或 HTTP SSE 传输握手建立。
4. `target matched`：目标模块、PID、PE/ELF 格式或 SHA-256 在后端引擎内校验匹配。
5. `executed verified`：实际下发指令并获得验证的动态或静态逆向证据。

## 权限与安全边界

- `status`、`list` 与 `locate` 为只读操作 (`read`)。
- `connect` 与 `disconnect` 为执行操作 (`exec`)，受安全审批模式保护。
- **目标进程与调试器解耦**：`disconnect` 只从 MCPManager 中干净卸载挂载的工具并分离通信通道，**绝不会终止、强杀被调试的目标程序或外部调试器**。
- **网络安全约束**：ZeroMQ RPC（x64dbg 自动化）无内置身份鉴权，严禁直接暴露至公网；远程自动化必须通过本地私有环回口或 SSH 端口转发安全连接。
- **平台限制**：当前 macOS / Linux 宿主无法在本地直接拉起 Windows PE；非 Windows 环境下 x64dbg 本地启动如实报错并引导使用远程隧道，不伪造跨平台执行。
