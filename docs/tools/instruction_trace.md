# instruction_trace

使用 Frida Stalker 与 QuarkslaB 动态二进制插桩引擎（QBDI，Apache-2.0）对目标进程执行有界指令级动态跟踪，捕获执行前的具体寄存器快照、内存读取数据以及实际执行的指令序列，生成符合 Triton 符号执行工件格式的结构化 JSONL 轨迹与元数据伴随清单，支持一键交接至 `triton_analyze` 进行离线符号回放。

## 安装与发现

- **QBDI 运行时依赖**：
  - CLI：`reverse setup reverse qbdi --execute` 安装固定的 QBDI 运行时资源（v0.12.1，包含 `libQBDI` 与 Frida 绑定脚本）。
  - TUI：`/setup` → 逆向工程工具链 → QBDI。
  - 自动回退：当 QBDI 未安装或未提供标量签名时，`instruction_trace` 自动使用 Frida 内置的 Stalker 引擎，无需强制外部安装。
- **Frida 环境**：
  - 需要系统 PATH 或环境中的 Frida CLI，或 persistent Frida Live 环境。

## 核心能力

1. **环境与引擎探测 (`action: "status"`)**：
   - 探测 Frida CLI 与 Frida Live 环境就绪状态。
   - 探测 Stalker 支持的 CPU 架构（ARM32、AArch64、x86、x86_64）。
   - 通过 `resolveProtectionTool("qbdi")` 探测已安装的 QBDI 运行时库路径与版本。
   - 属 `read` 审批层，允许在计划模式（Plan Mode）下运行。
2. **有界指令与状态捕获 (`action: "capture"`)**：
   - **目标附加与绑定**：支持附加已有 PID (`pid`)、按进程名附加 (`process`)、启动目标二进制/应用 (`spawn`) 或复用已建立的 Frida 会话 (`session_id`)。
   - **精确范围限定**：支持限定模块 (`module`)、导出函数/符号 (`function`)、RVA 偏移 (`offset`)、绝对虚拟地址 (`address`) 或显式地址区间 (`range: { start, end }`)。
   - **线程级隔离**：仅在目标线程（调用函数的主线程或显式指定的 `thread_id`）启用插桩，避免全进程跟踪造成的性能雪崩与多线程噪音。
   - **双插桩引擎**：
     - `engine: "qbdi"`：调用 QBDI 原生插桩，利用 `getInstMemoryAccess` 获取每条指令执行前的确切内存读取（包含地址、大小与读出值）。若目标调用了插桩范围之外的动态库 helper，ExecBroker 执行转移将记录 `exec_transfer_occurred` 并将 `memory_reads_complete` 标记为 `false`，保留未覆盖的外部依赖。
     - `engine: "stalker"`：调用 Frida 原生 Stalker 引擎，在执行前 Callout 中提取通用寄存器、NZCV/CPSR 标志位，并安全计算内存操作数有效地址。
     - `engine: "auto"`（默认）：若检测到已安装 QBDI 且提供了适用函数的标量 `signature`，则优先使用 QBDI；若未安装或未提供签名，则回退至 Stalker。
   - **符合 Triton 规范的 JSONL 格式**：
     - `{"type": "registers", "values": {<name>: <hex>}}`：指令执行前的完整 GPR 寄存器状态（严格小写规范，ARM32 自动映射 `lr` 与 `r14`，标志寄存器映射 `apsr`/`cpsr`，AArch64 映射 `nzcv`）。
     - `{"type": "memory_read", "address": <hex>, "size": <int>, "value": <hex>}`：指令执行前读取的具体内存。
     - `{"type": "instruction", "address": <hex>, "bytes": <hex>, "size": <int>, "disasm": <str>}`：实际执行的机器码指令与反汇编。
   - **伴随元数据清单 (`<trace>.manifest.json`)**：
     - 记录目标 PID、设备、目标架构、模块基址、大小与 SHA-256 校验和。
     - 记录执行指令数、唯一地址数、内存读取数与完成原因（`function_return`、`max_instructions_reached`、`range_exit`、`timeout`、`max_bytes_exceeded`）。
     - 包含 Thumb 模式标志、NZCV 标志位状态与 `memory_reads_complete` 完备性标识。
     - 附带 `replay_handoff` 字典，可直接作为参数传递给 `triton_analyze(replay_handoff.params)`。
   - **自属生命周期清理**：
     - 无论跟踪正常结束、达到上限还是用户中断，均确保立即脱附 `Interceptor` 钩子并调用 `Stalker.unfollow()` 与 `Stalker.flush()`，杜绝宿主内存泄漏或遗留钩子干扰后续操作。
   - 属 `exec` 审批层，在计划模式下拦截。

## 调用参数

| 参数 | 类型 | 说明 |
| :--- | :--- | :--- |
| `action` | `"status" \| "capture"` | 必选。探测引擎状态或执行指令捕获。 |
| `pid` | `number` | 目标进程 PID（与 `process`、`spawn`、`session_id` 互斥或任选一）。 |
| `process` | `string` | 目标进程名或 Android 包名。 |
| `spawn` | `string` | 待启动并跟踪的目标二进制路径或应用包名。 |
| `session_id` | `string` | 已创建的 Frida 活跃会话 ID。 |
| `device` | `string` | 目标设备 ID 或 ADB 序列号。 |
| `usb` | `boolean` | 是否连接 USB 设备/模拟器（等同于 `-U`）。 |
| `host` | `string` | 远程 frida-server 地址（如 `192.168.1.5:27042`）。 |
| `module` | `string` | 目标动态库/可执行模块名（如 `libnative-lib.so`）。 |
| `function` | `string` | 目标函数符号名或导出名（如 `Java_com_example_Calc`）。 |
| `offset` | `string \| number` | 相对模块基地址的 RVA 偏移（如 `"0x10a0"`）。 |
| `address` | `string \| number` | 绝对内存起始地址。 |
| `thread_id` | `number` | 显式跟踪的线程 ID（默认限定进入函数的目标线程）。 |
| `scope` | `"function" \| "thread" \| "range"` | 跟踪范围模式，默认为 `"function"`。 |
| `range` | `{ start, end }` | 显式地址边界区间。 |
| `max_instructions`| `number` | 最大指令采集数（默认 10000，上限 200000）。 |
| `timeout_ms` | `number` | 超时时间毫秒数（默认 30000）。 |
| `max_bytes` | `number` | 轨迹工件最大文件字节数（默认 32MB）。 |
| `engine` | `"auto" \| "qbdi" \| "stalker"` | 插桩引擎，默认为 `"auto"`。 |
| `format` | `"jsonl" \| "salwan"` | 输出格式，默认为 `"jsonl"`（符合 Triton 分析格式）。 |
| `signature` | `{ return_type, arg_types }` | 显式 C 函数签名（`engine: "qbdi"` 必选，支持 `pointer`、`uint64`、`int64`、`uint32`、`int32`、`int`、`uint`、`void` 等标量类型）。 |
| `output_path` | `string` | 可选自定义轨迹文件保存路径。 |

## 使用示例

### 1. 探测可用性与插桩引擎状态

```json
{
  "action": "status"
}
```

返回示例：
```json
{
  "action": "status",
  "success": true,
  "status": "ok",
  "qbdi": {
    "available": true,
    "installed": true,
    "version": "0.12.1",
    "lib_path": "/Users/.../.reverse/tools/qbdi/libQBDI.dylib"
  },
  "stalker": {
    "available": true,
    "supported_architectures": ["arm", "arm64", "ia32", "x64"]
  },
  "frida": {
    "available": true
  }
}
```

### 2. 跟踪指定函数并交接至 Triton 符号分析

```json
{
  "action": "capture",
  "usb": true,
  "process": "com.example.crackme",
  "module": "libnative.so",
  "function": "Java_com_example_crackme_MainActivity_checkFlag",
  "max_instructions": 5000,
  "engine": "auto"
}
```

返回结果中包含 `replay_handoff`：
```json
{
  "success": true,
  "status": "ok",
  "trace_path": "/Users/.../.reverse/artifacts/trace_1730000000.jsonl",
  "manifest_path": "/Users/.../.reverse/artifacts/trace_1730000000.jsonl.manifest.json",
  "sha256": "3a7b...",
  "instruction_count": 142,
  "memory_read_count": 28,
  "completion_reason": "function_return",
  "replay_handoff": {
    "tool": "triton_analyze",
    "valid": true,
    "params": {
      "action": "replay",
      "trace": "/Users/.../.reverse/artifacts/trace_1730000000.jsonl",
      "arch": "aarch64",
      "initial_registers": {
        "x0": "0x7ffffff0",
        "sp": "0x7fffffe0"
      },
      "bounds": {
        "max_instructions": 50000
      },
      "output": {
        "kind": "register",
        "target": "x0"
      }
    }
  }
}
```

后续在 `valid` 为真时可直接将 `replay_handoff.params` 作为参数输入至 `triton_analyze`：
```js
if (traceResult.details.replay_handoff?.valid) {
  await triton_analyze(traceResult.details.replay_handoff.params);
}
```

### 3. 使用 QBDI 引擎与显式 C 签名跟踪函数

```json
{
  "action": "capture",
  "spawn": "/tmp/reverse_trace_target_smoke",
  "module": "reverse_trace_target_smoke",
  "function": "reverse_trace_target",
  "signature": {
    "return_type": "uint64",
    "arg_types": ["uint64", "pointer"]
  },
  "max_instructions": 200,
  "engine": "qbdi"
}
```
