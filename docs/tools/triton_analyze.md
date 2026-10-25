# triton_analyze

使用 Triton 二进制分析引擎离线回放 x86、x64、ARM32 与 AArch64 指令轨迹，恢复符号输入输出表达式、检查路径约束，并在引擎支持时导出 LLVM IR。

## 安装与发现

- CLI：`reverse setup reverse triton --execute`，按交互提示确认安装。
- TUI：`/setup` → 逆向工程工具链 → Triton。
- 能力：`reverse_capability(action: "resolve", capability: "symbolic_trace_analysis")`。
- Skill：`skill://vmp-reverse`；轨迹格式详见其 `references/vmp-trace-format.md`。

安装器使用独立 Python 环境，安装 `triton-library==1.0.0rc4`；Apple Silicon 使用固定提交的源码与固定 Capstone/Z3 依赖构建。`TRITON_PYTHON` 可指定已有且经过实际 `TritonContext` 探测的解释器。此包是二进制符号执行库，与 NVIDIA 同名包区分。

源码构建需要 Python、CMake、Ninja 或 Make 及 C++ 编译器。LLVM 是可选编译功能；`status` 实际探测求解器、综合器与 LLVM，缺失功能会独立返回不可用原因。

## 调用

### 状态探测与架构规格

```js
triton_analyze({ action: "status" })
triton_analyze({ action: "arch_info", arch: "aarch64" })
```

### 轨迹回放示例

对于 x86_64 指令轨迹：

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

对于 AArch64 轨迹回放（支持 Wn 零扩展与硬件零寄存器 xzr/wzr）：

```js
triton_analyze({
  action: "replay",
  trace: "./artifacts/aarch64.trace",
  arch: "aarch64",
  initial_registers: { pc: "0x401000", x0: "0x1234", sp: "0x7ffffff0" },
  symbolic_registers: [{ name: "x0", alias: "x" }],
  output: { kind: "register", target: "x0" }
})
```

对于 ARM32 轨迹回放（支持 Thumb 执行模式）：

```js
triton_analyze({
  action: "replay",
  trace: "./artifacts/arm_thumb.trace",
  arch: "arm32",
  thumb: true,
  initial_registers: { pc: "0x401000", r0: "0x5", sp: "0x7ffffff0" },
  symbolic_registers: [{ name: "r0", alias: "x" }],
  output: { kind: "register", target: "r0" }
})
```

### 字段说明

- `arch`：`"x86"`、`"x86_64"`、`"arm32"` 或 `"aarch64"`（默认为 `"x86_64"`）。
- `thumb`：对于 ARM32，是否启用 Thumb 执行模式（默认 false，奇数地址自动激活）。
- `initial_registers`：键值映射，支持标准小写寄存器名称（AArch64 下写入 32 位 Wn 自动零扩展至 Xn；ARM32 下 lr 与 r14 互通，cpsr 与 apsr 互通）。
- `initial_memory`：`[{ address, size, value }]`。
- `symbolic_registers`：`[{ name, alias?, seed? }]`；种子来自显式 `seed` 或已提供的初始寄存器。
- `symbolic_memory`：`[{ address, size, seed, alias? }]`。
- `output`：`{ kind: "register", target: "rax" }` 或 `{ kind: "memory", address, size }`。
- `bounds`：`max_instructions`、`max_trace_bytes`、`timeout_ms`、`max_expr_chars`。
- `synthesize`、`lift_llvm`：控制表达式综合和可选 LLVM 输出。

轨迹支持 Salwan 冒号格式（`mr:<addr>:<size>:<val>`、`r:<reg>=<val>...` 或按位置 `r:<v0>:<v1>...`、`i:<addr>:<size>:<hex>[:<disasm>]`）及结构化 JSONL（`{"type": "instruction"|"registers"|"memory_read", ...}`）。严禁隐式填零：未初始化内存读取、未初始化通用寄存器位或未初始化 SIMD/向量寄存器读取均会抛出明确错误。

## 边界与审批

`status` 与 `arch_info` 属于只读操作，允许在计划模式下运行；`replay` 需要写审批并受计划模式保护。目标机器码仅在 Triton 引擎内部仿真，不直接在宿主上运行。恢复结论严格限定于所捕获或探索的执行路径。
