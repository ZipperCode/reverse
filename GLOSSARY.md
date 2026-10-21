# reverse 逆向领域术语

本词汇表定义 `reverse` 通用逆向工程系统的核心领域术语。

## Skill

面向模型的逆向方法论和决策约束，负责路由、降级、验证和推进；不直接执行外部命令或持久化调查状态。

## Tool

执行一个明确、受控动作的能力单元。工具可以读取样本、调用外部程序或管理运行时会话，但返回标准化结果，不承担完整调查流程。

## Runtime Controller

管理 Frida、Browser/CDP、DAP、Unidbg 等有生命周期的动态执行环境的工具适配器。

## Universal Dynamic Event

来自任意动态运行时的标准化事件，包含来源、会话、序列、类型、目标、载荷和定位信息。它是 Evidence candidate 的输入，不是自动验证结论。

## Evidence

与目标和可复现定位绑定的调查记录，分为 Fact、Hypothesis、Unknown 和 Conclusion。

## Knowledge

从已验证 Conclusion 或成功恢复路径中提炼出的可复用模式。未验证事件和用户样本事实不能直接成为 Knowledge。

## Workflow

围绕一个目标的阶段、步骤、门禁、失败和恢复状态。Workflow 由 Skill 推进，状态由持久化领域层保存。

## 动态闭环

`Runtime Event → Evidence → Verification → Knowledge / Workflow Progression` 的可追踪过程。
