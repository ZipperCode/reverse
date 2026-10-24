# reverse_workspace

标准化逆向工程工作区管理工具。

## 作用

显式导出到目标项目的 `.reverse/` 目录（兼容 `.rea/`），集中保存目标清单、工作流、证据、finding、脚本、转储引用和报告，避免分析产物散落在临时目录。

## Inputs

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `action` | `string` | 是 | 操作类型：`"export"`、`"status"`、`"manifest"`、`"clean"`。 |
| `workflow_id` | `string` | 否 | 要导出的工作流标识符（alias `id`）。在 `status`/`manifest`/`clean` 中可选，省略时自动选择最近的工作流。 |
| `id` | `string` | 否 | `workflow_id` 的别名。 |
| `workspace_path` | `string` | 否 | 目标工作区目录（默认为项目根目录下的 `".reverse"`）。 |
| `format_type` | `string` | 否 | 导出报告格式：`"markdown"`（默认）或 `"json"`。 |
| `clean_dumps_only` | `boolean` | 否 | 清理时是否仅清理转储文件 (`dumps/`) 而保留脚本（默认为 `false`，同时清理实验性转储与脚本）。 |
| `experimental_targets` | `string[]` | 否 | 指定要清理的特定实验性产物相对路径列表。省略时默认覆盖所有分类为实验性（`experiment`）的条目。 |
| `include_protected` | `boolean` | 否 | 请求清理受保护产物。需要显式交互式确认决策，禁止仅靠自由布尔值放行删除。 |

## Actions

- **`export`**：将指定工作流的完整上下文导出至本地工作区目录。目标样本保留为只读安全引用，不复制原始大文件；对文本产物进行敏感凭据脱敏。
- **`status`**：检查工作区目录结构、子目录完整性以及 `manifest.json` 的清单状态。
- **`manifest`**：读取结构化工作区清单，获取目标信息、产物索引与统计摘要。
- **`clean`**：根据产物分类执行受控清理，默认保留核心报告、证据与受保护基准。

## 产物分类与受保护默认规则 (Classified Cleanup)

工作区清单对所有受纳管产物建立严格的分类（`ArtifactClassification`）：

| 分类 | 默认保护状态 | 适用场景与说明 |
| --- | --- | --- |
| `experiment` | **可清理** | 逆向过程中的临时分析脚本、中间内存转储、临时构建产物。默认允许清理。 |
| `baseline` | **受保护 (Protected)** | 已验证的分析基准、基准测试快照与参考规格。默认禁止清理。 |
| `original` | **受保护 (Protected)** | 原始样本引用、未修改二进制镜像索引。默认禁止清理。 |
| `evidence` | **受保护 (Protected)** | 证据账本（`ledger.json`）、已验证事实与结论支撑记录。默认禁止清理。 |
| `rollback` | **受保护 (Protected)** | 补丁回滚备份、差异还原归档。默认禁止清理。 |
| `userfile` | **受保护 (Protected)** | 用户提供的输入脚本、本地证书与外部引用。默认禁止清理。 |

### 命名受保护删除与交互式确认机制 (No Free Boolean)

1. **禁止自由布尔值随意删除**：仅传入 `include_protected: true` 不足以触发受保护产物的删除。
2. **强制指定具体目标**：请求删除受保护产物时，必须在 `experimental_targets` 中明确列出具名目标路径。禁止对受保护产物执行无差别通配全量删除。
3. **真实交互确认回调**：清理引擎要求通过交互式确认回调（`confirmDeleteProtected`）由用户或审批系统显式批准该删除决策。若当前会话无法提供交互式确认，操作将被明确拒绝（返回 `cancelled: true`），且不删除任何受保护文件。
4. **最小可复现清单持久保留**：核心复现性清单文件（`manifest.json`、`target/`、`workflow/`、`evidence/`、`findings/`、`reports/`）始终保留，不受清理参数影响。清理完成后会持久化并报告最小可复现性清单。

## 进程与删除安全防护 (Process Safety & Shell Deletion Guard)

在宿主命令执行（`bash` 工具）层面，reverse 部署了常驻的进程与工作区防护网：

- **拦截全局进程名查杀**：严禁执行按可执行文件名称进行全局广播式杀进程的命令（如 `taskkill /IM`、`pkill`、`killall`、`Stop-Process -Name`）。此类命令无法验证任务所有权，容易误伤宿主 IDE、Java 运行时或其他后台工作进程。终止进程应使用受纳管的会话取消边界（如 `proc://<id>/kill` 或任务专有取消句柄）。
- **拦截工作区直接递归删除**：拦截通过 shell 直接执行的 `rm -rf .reverse`、`rmdir /s`、`Remove-Item -Recurse` 等针对工作区目录或已知受保护产物路径的直接删除命令，引导调用方使用 `reverse_workspace(action: "clean")` 进行分类受控清理。
- **边界说明**：此守卫针对工作区根目录及已登记的受保护工作流产物路径进行定向拦截，并不声明对宿主操作系统全部任意文件系统路径具备无死角的通用防护。

## 调用示例

```typescript
// 1. 标准导出当前工作流至工作区
reverse_workspace({
  action: "export",
  workflow_id: "wf_rw_apk_20261024"
});

// 2. 默认受控清理：仅清理临时转储和实验性脚本，保留基准与证据
reverse_workspace({
  action: "clean",
  clean_dumps_only: false
});

// 3. 具名清理特定实验性产物
reverse_workspace({
  action: "clean",
  experimental_targets: ["dumps/mem_0x400000.bin", "scripts/temp_hook.js"]
});
```
