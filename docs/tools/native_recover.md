# native_recover

使用 Triton、Z3 与 LLVM/llvmlite 完成有界机器快照的路径探索、VM handler 语义提取、带域守卫合并和差分验证。

## 动作与审批

| 动作 | 输入 | 结果 | 审批 |
|---|---|---|---|
| `status` | 无 | 已安装引擎、架构、求解器与 LLVM 能力 | `read` |
| `explore` | `snapshot`、可选 `bounds` | 完成路径、输入种子、路径谓词、输出 AST、内存写入和未探索前沿 | `exec` |
| `handlers` | `snapshot`、`range`、`inputs`、`output` | 单次执行的条件化转换公式、依赖和完成状态 | `exec` |
| `merge` | `paths`、`inputs`、`output_size_bits` | 重叠冲突、覆盖域、SMT2 与可用的 LLVM 工件 | `write` |
| `verify` | `snapshot`、`recovered`、向量或生成设置 | 返回值与副作用差分、反例、形式化证明范围 | `exec` |

计划模式允许 `status`；其余动作在执行前拦截。依赖由 `reverse setup reverse triton --execute` 或 TUI 的逆向工具安装面板按需配置；查询与分析过程不会自动安装依赖。

## 完整调用示例

以下 ARM32 样本计算 `x > 10 ? x * 2 + 1 : x + 5`，同时向 `0x200` 写入分支标记。代码区、数据区、初始状态与停止地址均显式提供。

```js
const snapshot = {
  arch: "arm32",
  entry: "0x401000",
  stop_addresses: ["0x401030"],
  registers: { pc: "0x401000", sp: "0x7ffffff0", r14: "0x401030" },
  segments: [
    {
      address: "0x401000",
      bytes: "0a0050e30400008afe1a0ce3022ca0e3001082e5050080e2040000eaef1e0be3022ca0e3001082e5001080e0010081e21eff2fe1",
      permissions: "r-x"
    },
    { address: "0x200", bytes: "00000000", permissions: "rw-" }
  ],
  symbolic_inputs: [{ name: "r0", alias: "x", seed: "0x4" }],
  output: { kind: "register", target: "r0" }
};

const explored = await native_recover({
  action: "explore",
  snapshot,
  bounds: { branch_budget: 8, max_depth: 8, max_instructions: 200 }
});

const handler = await native_recover({
  action: "handlers",
  snapshot,
  range: { start: snapshot.entry, stop: snapshot.stop_addresses[0] },
  inputs: snapshot.symbolic_inputs,
  output: snapshot.output,
  bounds: { max_instructions: 200 }
});

const merged = await native_recover({
  action: "merge",
  inputs: [{ name: "x", size_bits: 32 }],
  output_size_bits: 32,
  paths: explored.details.discovered_paths.map(path => ({
    path_id: path.path_id,
    status: path.status,
    predicate: path.path_predicate,
    output_ast: path.output_ast
  }))
});

const verified = await native_recover({
  action: "verify",
  snapshot,
  recovered: {
    kind: "smt2",
    expression: "(ite (bvugt x (_ bv10 32)) (bvadd (bvmul x (_ bv2 32)) (_ bv1 32)) (bvadd x (_ bv5 32)))",
    inputs: [{ name: "x", size_bits: 32, reg: "r0" }],
    output: snapshot.output,
    memory_side_effects: [{
      address: "0x200",
      size: 4,
      condition: "(bvugt x (_ bv10 32))",
      value: "0xbeef",
      else_value: "0xcafe"
    }],
    strict_memory_check: true
  },
  vectors: [{ x: "0x0" }, { x: "0xa" }, { x: "0xb" }, { x: "0xffffffff" }],
  test_generation: { boundary: true, random_count: 8, seed: 42 },
  proof_mode: "both"
});
```

## 状态、域和证据

- `snapshot.arch` 支持 `x86`、`x86_64`、`arm32`、`aarch64`。ARM32 的 `thumb` 显式选择 Thumb；输入地址和大整数使用十六进制字符串保持精度。
- `symbolic_inputs` 可绑定寄存器或内存。内存输入提供 `kind: "memory"`、`address`、`size` 和 `alias`；每个输入提供具体 `seed`，可选无符号 `min`/`max`。
- 未初始化读取、未建模指令、符号地址特化和执行上限保留具体诊断。只有到达声明的停止地址且状态完整的路径用于恢复证明；预算耗尽的前沿保留为待探索项。
- `handlers` 提取当前路径的转换关系；结合 `path_predicate` 使用。`handler_completed: false` 的结果保留诊断，不进入完整语义合并。
- `merge` 检查路径重叠的一致性和输入域覆盖；缺失域返回反例。SMT2 公式与 LLVM IR 保存为独立工件，使用返回的路径或 `artifact://` 引用读取。
- `recovered.domain_predicate` 或 `domain_guard` 可声明候选的有效域。域外向量单独记录在 `out_of_domain_vectors`。
- `verify` 按 `recovered.kind` 执行所提交的 SMT2/AST 或 LLVM IR；LLVM 使用实际 IR 执行结果，不使用附带公式替代。原始执行复用相同的严格快照引擎。
- 差分检查按最终写入字节比较副作用，覆盖额外写入、缺失写入、写入宽度与值。LLVM 候选的 `i8/i16/i32/i64` 读写通过快照段界限与权限检查回调执行，逐向量重置内存；越界、权限冲突、原子/向量内存、外部或间接调用、全局变量与回调冒用将被拒绝。
- `proof_mode: "finite_vectors"` 表示有限向量观察。对 SMT2/AST，`smt_formal`/`both` 额外检查完整建模域上的返回值和副作用；求解器未知或覆盖不完整时保留未证明状态。LLVM IR 当前执行独立的有限向量差分，附带公式不参与该 IR 的形式化证明。
- `formal_proof_scope` 在已证明结果中区分 `return_only` 与 `full_algorithm`；未证明时为空。结合 `smt_formal_proved`、`side_effects_proved` 和反例使用。有限向量一致对应 `dynamic_call_observation`，完整建模域及副作用均证明后才建议 `algorithm_recovery`。
