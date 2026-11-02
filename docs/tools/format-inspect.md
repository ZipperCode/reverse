# format_inspect

基于 Kaitai Struct（`kaitai-struct-compiler --read-pos` 与 Python `kaitaistruct` 运行时）的可执行二进制格式与自定义协议规范编译、单样本解析及多样本语料断言验证工具。

## Source

- Entry: `packages/coding-agent/src/tools/format-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/format-inspect.md`
- Staged Python worker: `packages/coding-agent/src/tools/format-inspect-worker.py`
- Toolchain & installer: `packages/coding-agent/src/extensibility/protocol-toolchain.ts`（`kaitai-struct-compiler`、`kaitaistruct`）

## 何时选用 (When to Choose)

- **适用场景**：当逆向分析需要对自定义二进制协议报文、私有文件容器、帧分界结构、TLV 记录或序列化负载建立可复现的结构化假设（`.ksy` 规范），并提取每个解析字段的精确 0 基字节偏移区间 `[start, end)`、流层级（`stream_id`）、原始文件偏移映射、尾部未消费字节（`trailing_bytes`），或跨正/负样本语料批量验证字段断言时使用。
- **能力目录映射**：对应标准逆向能力 `protocol_format_parsing`，可通过 `reverse_capability(action: "resolve", capability: "protocol_format_parsing")` 或 `format_inspect(action: "status")` 检查工具链就绪状态。
- **与邻近工具的边界**：
  - 标准 PCAP / PCAPNG 抓包与常见网络层/传输层/TLS/DNS/HTTP 流量概览优先使用零依赖内置工具 `pcap_inspect`；
  - ELF / PE / Mach-O 等标准可执行容器头部、导入导出与节区结构优先使用 `triage`、`elf_inspect`、`binary_metadata_inspect`；
  - 双二进制样本直接字节级或结构化差异比对使用 `binary_diff`；
  - 当进入自定义协议格式建模、字段偏移精确定位与多样本结构回归验证阶段时，使用 `format_inspect` 替代易出错的手工偏移推算。

## 安装与环境要求 (Requirements & Setup)

`format_inspect` 的编译与解析依赖两个受管组件，且两者版本需保持兼容（最低基线 `0.9`，受管版本锁定 `0.11`）：

1. **`kaitai-struct-compiler` (`ksc`)**：
   - 官方 JVM 编译器（受管版本 `v0.11`，许可证 `GPL-3.0-or-later`），要求宿主具备可用 Java 运行时（JRE/JDK）且编译器支持 `--read-pos` 参数。
   - CLI 安装：`reverse setup reverse kaitai-struct-compiler --execute`（macOS 亦支持 `brew install kaitai-struct-compiler`）
   - TUI 安装：`/setup` → 逆向工程工具链 → `kaitai-struct-compiler`
2. **`kaitaistruct` (Python Runtime)**：
   - Python 3.9+ 运行时库（受管版本 `0.11`，许可证 `MIT`），用于执行编译后的解析器并读取 `_debug` 字节偏移字典。
   - CLI 安装：`reverse setup reverse kaitaistruct --execute`
   - TUI 安装：`/setup` → 逆向工程工具链 → `kaitaistruct`

若主机缺失 Java 或 Python 解释器，`status` 会明确报告缺失的前置依赖（`java` / `python`）及对应修复命令。

## Actions

- **`status`**：探测本地 `kaitai-struct-compiler`（含 Java 运行时与 `--read-pos` 支持）、Python `kaitaistruct` 运行时版本及两者兼容性，返回路径、版本、缺失组件列表与安装命令。
- **`compile`**：在活跃实验运行（`workflow_id` / `step_id` / `run_id`）内校验 `.ksy` 根文件与显式本地 `import_roots` 下的 `meta.imports` 传递闭包，确认全部 `.ksy` 已在 `reverse_workspace(action: "begin")` 的 `inputs` 中绑定且无哈希漂移；以隔离 `KSPATH` 调用 `kaitai-struct-compiler --target python --read-pos --opaque-types false`，生成 `0600` 权限的 Python 解析器模块与 `FormatInspectManifestV1` 清单文件（编译失败时保留 `0600` 诊断报告 `FormatInspectCompileFailureReportV1`）。
- **`parse`**：加载已编译的 `manifest_path` 与待解析样本 `sample_path`，校验活跃 run 输入绑定、KSY 闭包哈希、生成源码哈希与运行时兼容性；通过受信任编译器对绑定闭包执行私有重编译并与 manifest 全量比对哈希后，在 `runReversePython` 隔离工作目录中执行单样本解析，返回展平字段、流偏移、原文件偏移、尾部残留字节与错误定位，并持久化 `FormatInspectParseReportV1`（`0600`）。
- **`validate`**：针对非空样本列表 `sample_paths[]` 批量执行验证后的解析器，核对每个样本的正/负样本预期（`expect_success`、`max_trailing_bytes`、`expected_error_offset`、`expected_error_contains`）与字段级显式断言（`field_assertions` / `sample_expectations[].assertions`），输出预期匹配率、断言满足率及针对失败字段/偏移的下一步实验建议，并持久化 `FormatInspectValidateReportV1`（`0600`）。

## Inputs

### 顶层参数 (`FormatInspectParams`)

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `action` | `"status" \| "compile" \| "parse" \| "validate"` | 是 | 操作类型：`status`、`compile`、`parse` 或 `validate`。 |
| `workspace_path` | `string` | 否 | 工作区目录路径（默认为项目下的 `".reverse"`）。 |
| `workflow_id` | `string` | `compile` / `parse` / `validate` 必填 | 当前活跃逆向工作流 ID。 |
| `step_id` | `string` | `compile` / `parse` / `validate` 必填 | 当前活跃工作流步骤 ID。 |
| `run_id` | `string` | `compile` / `parse` / `validate` 必填 | 来自 `reverse_workspace(action: "begin")` 的活跃实验运行 ID。 |
| `schema_path` | `string` | `compile` 必填 | 根 Kaitai Struct (`.ksy`) 规范文件路径（需位于项目目录内并绑定在 `begin` `inputs` 中）。 |
| `import_roots` | `string[]` | 否 | `compile` 解析 `meta.imports` 时允许搜索的本地项目目录列表（禁止网络或越界路径）。 |
| `manifest_path` | `string` | `parse` / `validate` 必填 | `compile` 产出的 `FormatInspectManifestV1` JSON 清单路径（需位于受管 run 目录内并绑定在当前 run `inputs` 中）。 |
| `sample_path` | `string` | `parse` 必填 | 单样本解析的目标二进制文件路径（需绑定在当前 run `inputs` 中）。 |
| `sample_paths` | `string[]` | `validate` 必填 | 多样本语料验证的非空二进制样本路径列表（全部样本需绑定在当前 run `inputs` 中）。 |
| `sample_expectations` | `FormatSampleExpectation[]` | 否 | `validate` 中按样本指定的解析成败预期、尾部字节上限、错误偏移预期与字段断言。 |
| `field_assertions` | `FormatFieldAssertion[]` | 否 | `validate` 中的顶层显式字段断言列表；指定 `sample_path` 时作用于该样本，省略时作用于所有预期解析成功的正样本。 |
| `output_path` | `string` | 否 | 产物输出路径，必须位于当前活跃 run 的受管子目录（`scripts/`、`dumps/`、`reports/`、`tmp/`）内且不得覆盖已有文件；省略时默认在 `reports/` 下生成唯一文件名。 |
| `max_input_bytes` | `number` | 否 | 单个输入样本最大字节数（整数，默认 `4194304` 即 4 MiB，范围 `1..16777216` 即 16 MiB）。 |
| `max_depth` | `number` | 否 | 结构体与数组递归展开的最大深度（整数，默认 `16`，范围 `1..64`）。 |
| `max_fields` | `number` | 否 | 单样本展平字段记录的最大数量（整数，默认 `2000`，范围 `1..20000`）。 |
| `max_output_bytes` | `number` | 否 | Python worker JSON 输出最大字节数（整数，默认 `1048576` 即 1 MiB，范围 `1024..8388608` 即 8 MiB）。 |
| `timeout` | `number` | 否 | 执行超时秒数（默认 `30`，上限 `120`）。 |
| `timeout_ms` | `number` | 否 | 执行超时毫秒数（整数，范围 `10..120000`；指定时优先于 `timeout`）。 |

### 样本预期结构 (`sample_expectations[]`)

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `sample_path` | `string` | 是 | 对应 `sample_paths` 中的某一样本路径。 |
| `expect_success` | `boolean` | 否 | 预期解析成功（`true`，正样本）或失败（`false`，负样本）。默认 `true`。 |
| `max_trailing_bytes` | `number` | 否 | 当 `expect_success: true` 时允许的最大尾部未消费字节数（非负整数）。 |
| `expected_error_offset` | `number` | 否 | 当 `expect_success: false` 时预期的 0 基流内错误偏移 `error_offset`（非负整数）。 |
| `expected_error_contains` | `string` | 否 | 当 `expect_success: false` 时预期错误信息中包含的子串（不区分大小写）。 |
| `assertions` | `FormatFieldAssertion[]` | 否 | 绑定到该样本的显式字段断言列表。 |

### 字段断言结构 (`field_assertions[]` / `assertions[]`)

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `sample_path` | `string` | 否 | 在顶层 `field_assertions` 中指定目标样本路径；省略时默认应用于所有正样本。 |
| `path` | `string` | 是 | 从根对象开始的展平字段路径（如 `"magic"`、`"items[0].id"`、`"body.inner_val"`）。 |
| `exists` | `boolean` | 否 | 预期字段是否存在（默认 `true`；设为 `false` 可断言条件分支未激活）。 |
| `type` | `string` | 否 | 预期字段类型（如 `"bytes"`、`"int"`、`"uint64"`、`"int64"`、`"str"`、`"enum"`、`"struct"`、`"array"`，也可匹配底层 `ksy_type` 如 `"u4be"`）。 |
| `equals` | `unknown` | 否 | 预期字段值（64 位大整数使用十进制字符串，如 `"18446744073709551615"`；`bytes` 使用小写十六进制字符串，如 `"52565031"`；枚举可匹配名称或数值）。 |
| `stream_id` | `string` | 否 | 预期所属流标识（根流为 `"root"`，子流为 `"substream:<path>"`）。 |
| `start` | `number` | 否 | 预期在 `stream_id` 内的 0 基起始偏移（包含）。 |
| `end` | `number` | 否 | 预期在 `stream_id` 内的 0 基结束偏移（不包含）。 |
| `file_start` | `number \| null` | 否 | 预期在原始文件中的 0 基起始偏移；经过 `process` 变换的子流为 `null`。 |
| `file_end` | `number \| null` | 否 | 预期在原始文件中的 0 基结束偏移（不包含）；经过 `process` 变换的子流为 `null`。 |

## 调用示例 (Examples)

### 1. 检查 Kaitai 编译器与 Python 运行时就绪状态 (`status`)

```typescript
format_inspect({
  action: "status"
});
```

### 2. 在活跃实验 run 中编译 `.ksy` 规范与本地导入闭包 (`compile`)

调用前需先通过 `reverse_workspace(action: "begin")` 声明 `schemas/packet.ksy` 及 `schemas/common/` 下被引用的 `.ksy` 文件为当前 run 的 `inputs`：

```typescript
format_inspect({
  action: "compile",
  workflow_id: "wf_proto_01",
  step_id: "step_frame_schema",
  run_id: "run_01",
  schema_path: "schemas/packet.ksy",
  import_roots: ["schemas/common"]
});
```

### 3. 使用编译生成的 Manifest 解析单个二进制样本 (`parse`)

```typescript
format_inspect({
  action: "parse",
  workflow_id: "wf_proto_01",
  step_id: "step_frame_schema",
  run_id: "run_01",
  manifest_path: ".reverse/analysis/wf_proto_01/runs/run_01/reports/kaitai_packet.manifest.json",
  sample_path: "samples/frame_01.bin"
});
```

### 4. 跨正负样本语料验证字段值、偏移与尾部字节约束 (`validate`)

```typescript
format_inspect({
  action: "validate",
  workflow_id: "wf_proto_01",
  step_id: "step_frame_schema",
  run_id: "run_01",
  manifest_path: ".reverse/analysis/wf_proto_01/runs/run_01/reports/kaitai_packet.manifest.json",
  sample_paths: ["samples/frame_01.bin", "samples/corrupt_magic.bin"],
  sample_expectations: [
    {
      sample_path: "samples/frame_01.bin",
      expect_success: true,
      max_trailing_bytes: 0,
      assertions: [
        { path: "magic", type: "bytes", equals: "52565031", start: 0, end: 4, file_start: 0, file_end: 4 },
        { path: "session_id", type: "uint64", equals: "18446744073709551615", start: 8, end: 16 }
      ]
    },
    {
      sample_path: "samples/corrupt_magic.bin",
      expect_success: false,
      expected_error_offset: 0
    }
  ]
});
```

## 输出、证据与安全边界 (Outputs, Evidence & Safety Boundaries)

### 1. 结构化输出与偏移语义

- **展平字段记录 (`FormatInspectFieldRecord`)**：
  - 每个字段包含 `path`、`type`、`ksy_type`、`value`、`stream_id`（`"root"` 或 `"substream:<path>"`）、流内 0 基左闭右开偏移 `start` / `end`。
  - **原始文件偏移映射**：仅当字段位于根流或未经 `process` 变换的确定性切片子流时，计算 `file_start`、`file_end` 与 `file_offset: { start, end }`；若子流经过 `zlib`、`xor(...)`、`rol(...)`、`ror(...)` 处理（`processed: true`），则 `file_start`、`file_end`、`file_offset` 明确返回 `null`，绝不伪造失真的原文件偏移。
  - **无损数值与字节预览**：`u8` / `s8` 及超过 JS 安全整数范围的整数统一编码为十进制字符串（`type` 标为 `"uint64"` 或 `"int64"`）；`bytes` 字段提供最多 64 字节（128 个十六进制字符）的小写 hex 预览，同时附带完整 `byte_length`、`bytes_sha256` 与 `preview_truncated` 标记。
  - **惰性实例安全跳过**：为避免触发非确定性副作用或越界求值，解析器遍历 `_seq` 顺序属性并跳过未求值的惰性 `@property` 实例，将其名称记录在 `lazy_instances_skipped` 与 `root_lazy_instances_skipped` 中。
- **实验产物记录提示**：`compile`、`parse`、`validate` 均会在 `details.relativeOutputPaths` 中返回本次写入的 `0600` 产物路径，可直接传入 `reverse_workspace(action: "record", output_paths: [...])` 完成实验台账登记。

### 2. 证据等级与覆盖率诚实边界

- **证据候选 (`evidenceCandidates`)**：
  - `compile` 生成 `kind: "hypothesis"` 候选，`parse` 与 `validate` 生成 `kind: "fact"` 候选。
  - 所有候选的保证等级固定为 `assurance_level: "static_candidate"`。
- **语料覆盖声明 (`coverage_claim`)**：
  - `validate` 报告固定标记 `coverage_claim: "corpus_and_explicit_assertions_only"`。
  - 样本语料解析通过仅代表所提供的样本与显式字段断言得到满足，**不等于完整协议逆向恢复，不提供未观测分支覆盖证明，也不替代动态运行时验证**。

### 3. 语法、输入绑定与子进程安全防线

- **实验输入强绑定与防漂移**：
  - `compile`、`parse`、`validate` 在启动任何外部进程前均通过 `loadAnalysisExecution` 校验当前活跃 run 及全部输入文件（`.ksy` 闭包、`manifest_path`、生成 `.py` 源码、二进制样本）的 SHA-256。
  - 跨 run 复用历史 `manifest_path` 时，还会回溯校验源 `run.json` 中已登记的 manifest 与脚本输出哈希，防止篡改。
  - `parse` 与 `validate` 在执行前会使用受信任的 `kaitai-struct-compiler` 对哈希绑定的 `.ksy` 闭包执行私有重编译，并校验新编译产物与 manifest 中记录的生成源码 SHA-256 完全一致，杜绝通过手改 `.py` 源码注入任意 Python 代码。
- **KSY 语法与导入白名单**：
  - 禁止任何 URI / 网络导入、绝对路径、`..` 路径穿越或符号链接段。
  - `meta.id` 与字段标识符必须符合 `/^[a-z][a-z0-9_]{0,127}$/`，且禁止使用 Python 关键字或受保留标准库模块名（如 `os`、`sys`、`subprocess`、`builtins`、`kaitaistruct` 等）。
  - 禁止 `meta.ks-opaque-types: true` 与未声明外部类型；`process` 属性仅允许内置 `zlib`、`xor(...)`、`rol(...)`、`ror(...)`，拒绝自定义 Python 处理器类。
- **隔离模型说明**：
  - `resource_limits.isolation_model` 为 `"subprocess_staging_not_security_sandbox"`。
  - 生成解析器在私有临时目录中通过 `runReversePython` 执行，清理环境变量（`PYTHONNOUSERSITE=1`、`PYTHONPATH=""`）并尽力设置 `RLIMIT_CPU` 与 `RLIMIT_AS` 资源上限，但该机制属于受界子进程隔离而非操作系统安全沙箱。

### 4. 资源上限与审批属性

- `MAX_KSY_FILE_BYTES = 1 MiB`，`MAX_KSY_CLOSURE_FILES = 64`。
- `MAX_MANIFEST_FILE_BYTES = 2 MiB`，`MAX_GENERATED_PY_BYTES = 4 MiB`。
- `DEFAULT_MAX_INPUT_BYTES = 4 MiB`，`HARD_MAX_INPUT_BYTES = 16 MiB`。
- `DEFAULT_MAX_DEPTH = 16`，`HARD_MAX_DEPTH = 64`。
- `DEFAULT_MAX_FIELDS = 2000`，`HARD_MAX_FIELDS = 20000`。
- `DEFAULT_MAX_OUTPUT_BYTES = 1 MiB`，`HARD_MAX_OUTPUT_BYTES = 8 MiB`。
- `DEFAULT_TIMEOUT_MS = 30,000`（30s），`HARD_MAX_TIMEOUT_MS = 120,000`（120s）。
- **Tool Attributes**：
  - `name`: `"format_inspect"`
  - `approval`: `status` 为 `"read"`（计划模式下允许）；`compile`、`parse`、`validate` 为 `"exec"`（计划模式下拦截）
  - `loadMode`: `"discoverable"`
  - `strict`: `true`
