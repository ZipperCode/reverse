# ADR 0001：Skill-first 逆向 Agent 架构

## 状态

已接受

## 背景

参考项目 rea 的能力覆盖静态分析、Android、浏览器、Frida、DAP、证据、知识和工作流。对于 reverse（前身 omp，兼容 rva），若继续把调查流程塞进工具，会造成工具之间重复编排、状态分散和每新增能力都需要独立测试的问题。

## 决策

采用三层架构：

1. Skill 编排层：保存方法论、路由、降级、阶段门禁和验证规则。
2. 工具适配层：执行单个受控动作，返回统一结果，不实现完整调查流程。
3. 领域状态层：保存 Workspace、Evidence、Runtime Session、Workflow 和 Knowledge。

Frida、CDP、DAP、Unidbg 统一为 Runtime Controller；其事件先进入统一动态事件模型，再形成 Evidence candidate。只有验证后的 Conclusion 才能晋升 Knowledge 或推进 Workflow。

测试采用共享契约和关键路径冒烟，不要求每个 Skill 或工具都拥有独立测试。

## 后果

正面：Skill 可快速扩展；工具保持可复用；动态闭环有统一状态和证据血缘；测试成本集中在真正的共享契约。

代价：需要逐步迁移现有工具中的工作流逻辑；必须维护统一事件和结果契约；外部运行时的真实能力仍受环境和依赖限制。

## 许可证约束

参考项目代码和知识按许可证处理。MIT/Apache-2.0 可在保留声明条件下复用；GPL/AGPL 或来源不清的实现和知识不直接复制，采用 clean-room 重写。
