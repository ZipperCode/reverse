# capability_inspect

基于 Mandiant `capa`（`backend: "capa"`）的可解释二进制能力识别、布尔规则匹配树检视与离线 `capa` JSON 报告导入工具。

## Source

- Entry: `packages/coding-agent/src/tools/capability-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/capability-inspect.md`
- Lossless Python bridge worker: `packages/coding-agent/src/tools/capability-inspect-worker.py`
- Toolchain & rules manifest: `packages/coding-agent/src/extensibility/protocol-toolchain.ts`（`capa`、`capa-rules`）

## 何时选用 (When to Choose)

- **适用场景**：当需要识别 PE、ELF、.NET 模块或原始 32/64 位 shellcode（`sc32` / `sc64`）中的可解释行为能力（如加密/哈希/编码例程、网络通信、反调试/反分析、持久化、宿主系统交互），并保留完整的布尔语句匹配树（`and` / `or` / `not` / `optional` / `some` / `range` / `subscope`）、叶特征命中地址（`locations`）与捕获内容（`captures`），或在未安装 `capa` 可执行文件的环境中离线导入并校验已有 `capa -j` 原始 JSON 报告时使用。
- **能力目录映射**：对应标准逆向能力 `executable_capability_identification`，可通过 `reverse_capability(action: "resolve", capability: "executable_capability_identification")` 或 `capability_inspect(action: "status")` 查询就绪状态。
- **与邻近工具的边界与互补**：
  - 零依赖快速文件初筛、节区熵、导入导出与字符串概览优先使用 `triage`；
  - Go / Rust 编译器构建信息与依赖包元数据提取使用 `binary_metadata_inspect`；
  - **与 FindCrypt 常数扫描互补**：`ghidra_inspect(action: "findcrypt")` 擅长定位已知密码学常量表（如 AES S-Box、SHA 初始向量），而 `capability_inspect` 通过指令序列、控制流特征、API 调用组合与立即数识别算法结构（如无固定常数表的 XOR 循环、RC4 KSA/PRGA、自定义位运算或系统调用组合）。对加密/编码类命中规则，报告会将 `complements_findcrypt` 标记为 `true`；
  - `capability_inspect` 产出的匹配位置属于静态候选证据（`static_candidate`），后续应结合 `ghidra_inspect`、`r2_inspect`、`dotnet_inspect`（反编译核实逻辑）或 `debug`、`frida_session`、`instruction_trace`（动态执行验证）完成闭环。

## 安装与环境要求 (Requirements & Setup)

1. **`capa` 引擎与 `capa-rules` 官方规则库（用于 `action: "detect"`）**：
   - 受管版本锁定 Mandiant `capa` `v10.0.0` 与官方 `capa-rules` `v10.0.0`（许可证均为 `Apache-2.0`）。
   - CLI 安装：`reverse setup reverse capa --execute`
   - TUI 安装：`/setup` → 逆向工程工具链 → `capa`
   - 路径解析：支持环境变量 `CAPA_PATH` / `CAPA_BIN` 指定可执行文件；默认规则目录优先使用受管工具链分发目录 `<agentDir>/tools/capa/rules` 或项目内显式绑定的 `rules_path`。
2. **离线导入模式（`action: "import"`）无需安装 `capa`**：
   - 当主机未安装 `capa` 时，`import` 动作无需 `capa` 二进制即可运行，仅使用内置 `runReversePython`（Python 3 标准库）完成无损 64 位整数解析、Schema 校验与样本 SHA-256 核对。

## Actions

- **`status`**：只读探测本地 `capa` 可执行文件（`--version`）与默认规则库就绪状态（`resolveCapa`），返回引擎路径、版本号、默认规则路径、有效规则数量、缺失项与受信安装命令。
- **`detect`**：在活跃实验运行（`workflow_id` / `step_id` / `run_id`）内校验 `sample_path` 及显式 `rules_path` 全量 `.yml`/`.yaml` 规则闭包的 `begin` 输入绑定；以固定参数调用本地 `capa -j`，在执行前后复核外部规则清单 `manifest_sha256`（或 `use_embedded_rules: true` 时的引擎二进制 SHA-256）未发生漂移；保留 `0600` 原始 `capa` JSON 报告与规范化 `CapabilityInspectReportV1` JSON（失败、超时或输出越界时保留 `0600` 诊断报告 `CapabilityInspectFailureReportV1`，绝不返回空匹配伪成功）。
- **`import`**：在不依赖本地 `capa` 可执行文件的前提下，离线导入已有的原始 `capa` JSON 报告（`report_path`），校验活跃 run 输入绑定，强制核对报告内 `/meta/sample/sha256` 与绑定样本 SHA-256 一致，过滤并生成规范化 `CapabilityInspectReportV1`（`0600`）与原始报告留存副本（`0600`）。

## Inputs

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `action` | `"status" \| "detect" \| "import"` | 是 | 操作类型：`status`、`detect` 或 `import`。 |
| `backend` | `"capa"` | 否 | 能力识别引擎后端标识（固定为 `"capa"`，传入其他值会报错）。 |
| `workspace_path` | `string` | 否 | 工作区目录路径（默认为项目下的 `".reverse"`）。 |
| `workflow_id` | `string` | `detect` / `import` 必填 | 当前活跃逆向工作流 ID。 |
| `step_id` | `string` | `detect` / `import` 必填 | 当前活跃工作流步骤 ID。 |
| `run_id` | `string` | `detect` / `import` 必填 | 来自 `reverse_workspace(action: "begin")` 的活跃实验运行 ID。 |
| `sample_path` | `string` | `detect` 必填；`import` 可选 | 目标二进制样本路径（需在项目内并绑定于 `begin` `inputs`；`import` 省略时默认对照当前 run 绑定的首样本/目标样本 SHA-256）。 |
| `report_path` | `string` | `import` 必填 | 待离线导入的原始 `capa` JSON 报告路径（需在项目内并绑定于 `begin` `inputs` 或当前 run）。 |
| `rules_path` | `string` | 否 | 显式指定的项目内本地 `capa` 规则目录或单个 `.yml`/`.yaml` 规则文件（闭包内所有规则文件必须在 `begin` `inputs` 中声明绑定；与 `use_embedded_rules: true` 互斥）。 |
| `use_embedded_rules` | `boolean` | 否 | 在 `detect` 中设为 `true`（且未传 `rules_path`）时，使用 `capa` 可执行文件内嵌规则集并记录引擎二进制 SHA-256 与版本。 |
| `namespace` | `string` | 否 | 按规则命名空间前缀或精确名称过滤（如 `"data-manipulation/encryption/xor"`）。 |
| `tag` | `string` | 否 | 单个规则元数据/标签过滤项（对应 `-t`）。 |
| `tags` | `string[]` | 否 | 多个规则元数据/标签过滤项列表。 |
| `restrict_to_functions` | `string[]` | 否 | 仅对指定函数虚拟地址列表执行静态分析（`detect` 专用，对应 `--restrict-to-functions`，每项为十六进制如 `"0x401000"` 或十进制地址字符串）。 |
| `format` | `"auto" \| "pe" \| "elf" \| "dotnet" \| "sc32" \| "sc64"` | 否 | `detect` 静态输入格式（对应 `-f`，默认 `"auto"`；不支持在 `detect` 中传入动态格式，历史动态报告请使用 `action: "import"`）。 |
| `capa_backend` | `"auto" \| "vivisect" \| "pefile" \| "dotnet"` | 否 | `detect` 静态特征提取后端（对应 `-b`，默认 `"auto"`）。 |
| `os` | `"auto" \| "linux" \| "macos" \| "windows"` | 否 | `detect` 目标操作系统覆盖项（对应 `--os`，默认 `"auto"`）。 |
| `output_path` | `string` | 否 | 规范化 `CapabilityInspectReportV1` JSON 的唯一输出路径，必须位于当前活跃 run 的受管子目录（`reports/`、`dumps/`、`scripts/`、`tmp/`）内且不得覆盖已有文件。 |
| `raw_output_path` | `string` | 否 | 原始 `capa` JSON 报告副本的唯一输出路径，必须位于当前活跃 run 的受管子目录内且与 `output_path` 互异。 |
| `max_sample_bytes` | `number` | 否 | 最大允许输入样本字节数（整数，默认 `33554432` 即 32 MiB，范围 `1..134217728` 即 128 MiB）。 |
| `max_output_bytes` | `number` | 否 | 最大允许原始 `capa` JSON 报告字节数（整数，默认 `8388608` 即 8 MiB，范围 `512..12582912` 即 12 MiB）。 |
| `timeout` | `number` | 否 | 执行超时秒数（默认 `60`，上限 `300`）。 |
| `timeout_ms` | `number` | 否 | 执行超时毫秒数（整数，范围 `100..300000`；指定时优先于 `timeout`）。 |

## 调用示例 (Examples)

### 1. 检查本地 `capa` 引擎与规则库就绪状态 (`status`)

```typescript
capability_inspect({
  action: "status"
});
```

### 2. 使用项目内自定义规则目录与函数地址过滤执行静态检测 (`detect`)

调用前需在 `reverse_workspace(action: "begin")` 的 `inputs` 中声明 `samples/target.elf` 以及 `rules/crypto/` 下的规则文件：

```typescript
capability_inspect({
  action: "detect",
  backend: "capa",
  workflow_id: "wf_elf_01",
  step_id: "step_capability_triage",
  run_id: "run_01",
  sample_path: "samples/target.elf",
  rules_path: "rules/crypto",
  namespace: "data-manipulation/encryption/xor",
  restrict_to_functions: ["0x401000"]
});
```

### 3. 使用受管默认规则库或内嵌规则快速检测样本 (`detect`)

```typescript
capability_inspect({
  action: "detect",
  backend: "capa",
  workflow_id: "wf_pe_01",
  step_id: "step_capability_triage",
  run_id: "run_02",
  sample_path: "samples/suspect.exe",
  format: "pe",
  use_embedded_rules: true
});
```

### 4. 在无 `capa` 二进制环境下离线导入并核验原始 JSON 报告 (`import`)

```typescript
capability_inspect({
  action: "import",
  backend: "capa",
  workflow_id: "wf_elf_01",
  step_id: "step_capability_triage",
  run_id: "run_01",
  sample_path: "samples/target.elf",
  report_path: "captures/capa_raw_report.json"
});
```

## 输出、可解释匹配树与安全边界 (Outputs, Explainable Match Tree & Safety Boundaries)

### 1. 无损 64 位地址桥接与可解释匹配树

- **Python 原生任意精度整数桥接**：
  - 原始 `capa` JSON 在进入 TypeScript `JSON.parse` 前先经由 `capability-inspect-worker.py` 解析，避免 IEEE-754 双精度浮点数截断 64 位虚拟地址、掩码或大整数立即数。
  - 所有数值型地址与特征值均同时保留无损十进制字符串（`decimal`）与十六进制字符串（`hex`）。
- **全类型地址规范化 (`CapabilityAddressKind`)**：
  - 支持并显式区分 9 种地址类型：`no_address`（如 `file` 作用域规则命中，明确标记 `has_address: false`）、`absolute`（VA）、`relative`（RVA）、`file_offset`、`dotnet_token`、`dotnet_token_offset`、`process`、`thread`、`call`。
- **完整布尔匹配树与 RFC 6901 JSON Pointer**：
  - 每条命中的规则记录（`CapabilityRuleMatchRecord`）保留元数据（`rule_name`、`namespace`、`scopes`、`primary_scope`、`attack`、`mbc`、`references`、`source`）、匹配树根节点 `tree`（含 `and`、`or`、`not`、`optional`、`some`、`range`、`subscope` 语句节点与特征节点）、叶特征列表 `leaf_features`（含 `locations` 与 `captures`），以及指向规范化报告与原始报告精确节点的 `json_pointer` / `source_json_pointer`。

### 2. 证据候选分级与历史动态报告边界

- **`FACT` 与 `HYPOTHESIS` 分离**：
  - **`fact` 候选**：陈述“规则 `R` 在样本观测位置 `L` 发生静态特征匹配”，绑定归一化报告与原始报告的 SHA-256 及 `json_pointer`。
  - **`hypothesis` 候选**：陈述规则所指向的程序行为或算法语义假设（`claim`），并附带具体的反编译或动态验证计划（`verification_plan`）。
  - 所有由 `capability_inspect` 生成的证据候选均固定为 `assurance_level: "static_candidate"`，且 `can_satisfy_dynamic_call_gate: false`。
- **历史动态报告离线导入约束 (`historical_dynamic_import`)**：
  - 当通过 `action: "import"` 导入 `flavor: "dynamic"` 的历史沙箱/跟踪 `capa` 报告时，报告与证据候选会强制标记 `historical_dynamic_import: true`、`historical_context_only: true`、`can_satisfy_dynamic_call_gate: false`。
  - 历史动态报告中的进程/线程/调用序号仅作为静态历史上下文参考，**绝不伪造实时动态会话定位符或 `metadata.callsite`，也不满足工作流的实时动态调用验证门禁**。
- **自动推荐下一步工具 (`next_actions`)**：
  - 根据命中规则的作用域与格式，自动生成绑定观测地址的后续建议：对 `function` / `basic block` / `instruction` 作用域推荐 `ghidra_inspect`、`r2_inspect`、`debug`、`frida_session`、`instruction_trace`；对 `.NET` token 推荐 `dotnet_inspect`；对文件级规则推荐 `triage` / `elf_inspect`。

### 3. 规则来源防漂移与安全防线

- **外部规则来源限制与执行前后复核**：
  - 项目内规则（显式 `rules_path` 或位于项目内的默认规则）必须在 `begin` `inputs` 中全量声明绑定；项目外规则仅允许受管工具链目录 `<agentDir>/tools/capa/rules`，严禁通过 `CAPA_RULES_PATH` / `CAPA_RULES_DIR` 引入未绑定的项目外任意目录。
  - 在 `capa` 子进程执行前后分别计算外部规则闭包的 `manifest_sha256`（或在 `use_embedded_rules: true` 时复核 `capa` 引擎二进制 SHA-256），一旦执行期间发生篡改或漂移立即报错阻断。
  - 使用内嵌规则（`use_embedded_rules: true`）或未绑定外部规则目录的离线导入（`import`）时，`rules_provenance.independent_content_hash_available` 会如实设为 `false` 并说明原因。
- **失败诚实报告**：
  - 当 `capa` 进程超时、输出超过 `max_output_bytes`、非零退出或输出非法 JSON 时，工具会持久化 `0600` 权限的 `CapabilityInspectFailureReportV1` 并返回 `status: "error"`，绝不静默降级为空匹配列表。

### 4. 资源上限与审批属性

- `DEFAULT_MAX_SAMPLE_BYTES = 32 MiB`，`HARD_MAX_SAMPLE_BYTES = 128 MiB`。
- `DEFAULT_MAX_OUTPUT_BYTES = 8 MiB`，`HARD_MAX_OUTPUT_BYTES = 12 MiB`。
- `MAX_RULE_FILE_BYTES = 2 MiB`（单规则 YAML 文件上限），`MAX_RULE_TOTAL_BYTES = 64 MiB`（规则闭包总字节上限）。
- `DEFAULT_TIMEOUT_MS = 60,000`（60s），`HARD_MAX_TIMEOUT_MS = 300,000`（300s）。
- `MAX_STDERR_CAPTURE_BYTES = 256 KiB`。
- **Tool Attributes**：
  - `name`: `"capability_inspect"`
  - `approval`: `status` 为 `"read"`（计划模式下允许）；`import` 为 `"write"`；`detect` 为 `"exec"`（`import` 与 `detect` 在计划模式下均被拦截）
  - `loadMode`: `"discoverable"`
  - `strict`: `true`
