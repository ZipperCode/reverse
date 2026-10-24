# triton_analyze

使用 Triton 二进制分析引擎离线回放 x86/x64 指令轨迹，恢复符号输入输出表达式、检查路径约束，并在引擎支持时导出 LLVM IR。

## 安装与发现

- CLI：`reverse setup reverse triton --execute`，按交互提示确认安装。
- TUI：`/setup` → 逆向工程工具链 → Triton。
- 能力：`reverse_capability(action: "resolve", capability: "symbolic_trace_analysis")`。
- Skill：`skill://vmp-reverse`；轨迹格式详见其 `references/vmp-trace-format.md`。

安装器使用独立 Python 环境，安装 `triton-library==1.0.0rc4`；Apple Silicon 使用固定提交的源码与固定 Capstone/Z3 依赖构建。`TRITON_PYTHON` 可指定已有且经过实际 `TritonContext` 探测的解释器。此包是二进制符号执行库，与 NVIDIA 同名包区分。

源码构建需要 Python、CMake、Ninja 或 Make 及 C++ 编译器。LLVM 是可选编译功能；`status` 实际探测求解器、综合器与 LLVM，缺失功能会独立返回不可用原因。

## 调用

```js
triton_analyze({ action: "status" })
```

对于内容为以下两条指令的轨迹文件：

```text
i:0x401000:2:89f8
i:0x401002:2:31f0
```

```js
triton_analyze({
  action: "replay",
  trace: "./artifacts/xor.trace",
  arch: "x86_64",
  initial_registers: { rip: "0x401000", rdi: "0x10", rsi: "0x20", rsp: "0x7ffffff0" },
  symbolic_registers: [{ name: "rdi", alias: "x" }, { name: "rsi", alias: "y" }],
  output: { kind: "register", target: "eax" },
  bounds: { max_instructions: 50000, max_trace_bytes: 33554432, timeout_ms: 60000 }
})
```

预期具体结果为 `0x30`，表达式包含两个符号输入的 XOR。寄存器名、调用约定与输出目标由调用者明确提供。

- `initial_memory`：`[{ address, size, value }]`。
- `symbolic_registers`：`[{ name, alias?, seed? }]`；种子来自显式 `seed` 或已提供的初始寄存器。
- `symbolic_memory`：`[{ address, size, seed, alias? }]`。
- 内存输出：`output: { kind: "memory", address: "0x2000", size: 4 }`。
- `synthesize`、`lift_llvm`：控制表达式综合和可选 LLVM 输出。
- `bounds.max_expr_chars`：限制内联预览，完整结果保存在会话产物或本地 `artifacts/triton/`。

轨迹支持 Salwan `mr:`、`r:`、`i:` 记录及工具说明中的结构化 JSONL。提供每条指令实际读取的具体状态；缺失状态、格式错误或不一致的符号快照会报错。

## 边界与审批

`status` 为读取操作；`replay` 需要写审批并受计划模式保护。目标机器码仅由 Triton 模拟，工具不启动目标程序。输入大小、指令数、输出和执行时间均有限额。

恢复结论限定于捕获路径。分支覆盖、内存副作用、异常与调用约定需独立验证；产物生成成功不构成全函数等价证明。
