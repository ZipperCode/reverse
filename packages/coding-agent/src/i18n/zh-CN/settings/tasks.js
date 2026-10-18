export const tasksSettingsZhCN = {
    "task.isolation.enabled": {
        label: "隔离子代理",
        description: "在检出的隔离副本中运行子代理，之后再整合它们的更改",
    },
    "isolation.backend": {
        label: "隔离后端",
        description: "用于子代理隔离和工作树克隆的后端",
        options: {
            auto: { label: "自动", description: "让 PAL 选择最佳可用后端" },
            apfs: { label: "APFS", description: "macOS clonefile reflink（APFS）" },
            btrfs: { label: "btrfs", description: "btrfs 子卷快照" },
            zfs: { label: "ZFS", description: "ZFS 快照 + 克隆" },
            reflink: { label: "Reflink", description: "Linux FICLONE 按文件 reflink" },
            overlayfs: { label: "Overlayfs", description: "Linux 内核 overlay（或 fuse-overlayfs 回退）" },
            projfs: { label: "ProjFS", description: "Windows Projected File System" },
            "block-clone": { label: "块克隆", description: "Windows FSCTL_DUPLICATE_EXTENTS_TO_FILE（NTFS/ReFS）" },
            rcopy: { label: "递归复制", description: "可用时使用 git worktree，否则递归复制" },
        },
    },
    "worktree.clone": {
        label: "将检出克隆到工作树",
        description: "通过 `github pr_checkout` 和 bash 中的 `git worktree add` 创建的新工作树会以当前检出的写时复制克隆启动，使被忽略的构建产物（node_modules、target）得以保留；文件系统无法克隆时回退到普通检出",
    },
    "worktree.cleanSource": {
        label: "在 /wt 时清理源检出",
        description: "使用 `/wt` 创建工作树时，在转移更改后重置原始检出中的已跟踪更改并移除未跟踪文件",
    },
    "worktree.onStart": {
        label: "启动时使用工作树",
        description: "新的交互会话是否在新建的链接工作树中启动",
        options: {
            off: { label: "关闭", description: "在当前检出中启动" },
            ask: { label: "询问", description: "会话启动时询问" },
            create: { label: "创建", description: "始终在 `wt/*` 分支的新工作树中启动" },
        },
    },
    "worktree.onExit": {
        label: "退出时处理工作树",
        description: "退出时如何处理自 omp 启动以来创建的工作树（启动时或通过 `/wt`）",
        options: {
            keep: { label: "保留", description: "保留工作树" },
            ask: { label: "询问", description: "退出时询问" },
            remove: {
                label: "移除",
                description: "移除干净的工作树；有未提交更改或新提交时询问。被 gitignore 的文件（如 `.env`）也会被删除",
            },
        },
    },
    "task.isolation.apply": {
        label: "应用隔离更改",
        description: "自动将成功的隔离任务更改应用到父检出；禁用则保留补丁或分支产物",
    },
    "task.isolation.merge": {
        label: "隔离合并策略",
        description: "如何整合隔离任务更改（补丁应用或分支合并）",
        options: {
            patch: { label: "补丁", description: "合并差异并 git apply" },
            branch: { label: "分支", description: "按任务提交，使用 --no-ff 合并" },
        },
    },
    "task.isolation.commits": {
        label: "隔离提交风格",
        description: "嵌套仓库更改的提交消息风格（通用或 AI 生成）",
        options: {
            generic: { label: "通用", description: "静态提交消息" },
            ai: { label: "AI", description: "根据差异生成 AI 提交消息" },
        },
    },
    "worktree.base": {
        label: "工作树基础目录",
        description: "代理管理工作树的基础目录——任务隔离副本、`github` PR 检出和 `omp worktree` 清理都位于此处。未设置时使用 ~/.omp/wt。必须是绝对路径或 ~ 相对路径；相对路径会被忽略。OMP_WORKTREE_DIR 环境变量会覆盖此设置。",
    },
    "task.eager": {
        label: "偏好任务委派",
        description: "推动将工作委派给子代理的强度",
        options: {
            default: { label: "默认", description: "使用所选模型的策略；某些模型需要显式委派请求" },
            preferred: { label: "偏好", description: "在系统提示中添加委派指导" },
            always: { label: "始终", description: "提示指导加首轮委派提醒" },
        },
    },
    "task.batch": {
        label: "批量任务调用",
        description: "将 task 工具切换为批量形态：一次调用携带 { context, tasks[] }——每个项一个子代理，可选的按项 agent（默认为会话生成策略代理）、按项隔离，以及前置到每个任务的必需共享上下文。async.enabled=true 时，每次派生都作为独立后台代理运行，具有正常的空闲/停泊生命周期；否则调用会阻塞以获取合并结果。禁用则恢复扁平的单次派生 schema。",
    },
    "task.structured": {
        label: "结构化任务结果",
        description: "在 task 工具上暴露 outputSchema/schemaMode，并通过 yield 工具返回子代理结果，按调用方或代理输出 schema 验证。关闭：task 子代理没有 yield 工具，其最终消息以纯文本返回，除非代理定义设置了 structured: true。Eval agent()/workpool 派生始终保留结构化结果。",
    },
    "task.speculativeLaunch": {
        label: "推测性任务启动",
        description: "每个批量子代理在其 tasks[] 项完成流式输出后立即启动，而不是等待整个 task 调用完成。若完成的调用验证失败、被阻止或其参数变化，已启动的代理会被中止。需要自动允许的 task 审批，且没有扩展工具生命周期处理器。",
    },
    "task.enableEffort": {
        label: "按任务 effort",
        description: "在 task 派生中暴露可选的 effort 参数，允许调用方覆盖每个子代理的思考级别",
    },
    "task.maxConcurrency": {
        label: "最大并发任务数",
        description: "同时运行的子代理最大数量",
        options: {
            "0": { label: "不限制" },
            "1": { label: "1 个任务" },
            "2": { label: "2 个任务" },
            "4": { label: "4 个任务" },
            "8": { label: "8 个任务" },
            "16": { label: "16 个任务" },
            "32": { label: "32 个任务" },
            "64": { label: "64 个任务" },
        },
    },
    "task.enableLsp": {
        label: "子代理中的 LSP",
        description: "允许通过 task 工具派生的子代理使用 lsp 工具。默认关闭以保持子代理低成本；当支持 LSP 的委派值得额外 token 时启用。",
    },
    "task.maxRecursionDepth": {
        label: "最大任务递归深度",
        description: "子代理可以再派生多少层自己的子代理",
        options: {
            "-1": { label: "不限制" },
            "0": { label: "无" },
            "1": { label: "单层" },
            "2": { label: "双层" },
            "3": { label: "三层" },
        },
    },
    "task.maxRuntimeMs": {
        label: "子代理最大运行时间",
        description: "每个子代理的硬墙钟上限（毫秒）。0 禁用。针对逃逸推理层看门狗的提供商侧流挂起提供纵深防御；会触发带“超时”原因的正常子代理中止。",
        options: {
            "0": { label: "不限制", description: "默认" },
            "300000": { label: "5 分钟" },
            "900000": { label: "15 分钟" },
            "1800000": { label: "30 分钟" },
            "3600000": { label: "1 小时" },
        },
    },
    "task.completionProbe": {
        label: "子代理完成度探测",
        description: "通过类似 /btw 的缓存侧请求，让工作中的子代理估计任务完成度：在再经过 2、5、10、30 分钟后，然后每小时一次。估计值显示在 wait 和 task 视图中的子代理旁边。仅交互式会话主代理派生的子代理会被询问；print、RPC、ACP 和 SDK 运行从不探测。",
    },
    "task.agentIdleTtlMs": {
        label: "代理空闲 TTL",
        description: "空闲子代理在内存中保持活跃多久后停泊到磁盘（毫秒）。停泊的代理在收到消息或恢复时会自动复活。0 表示空闲代理保持活跃直到退出。",
    },
    "task.softRequestBudget": {
        label: "子代理软请求预算",
        description: "每个子代理的软请求预算（每次运行的助手请求数）。越过后会注入收尾引导通知（见 task.softRequestBudgetNotice）；达到预算的 1.5 倍时运行被强制停止，代理必须交回部分发现。0 禁用此保护。捆绑的 scout/sonic 代理有更低的内置预算上限，因此低于该上限的值仍适用于它们。task.agentSoftRequestBudget 条目会为其指定的代理替换此预算。",
        options: {
            "0": { label: "禁用" },
            "90": { label: "90 次请求" },
            "150": { label: "150 次请求" },
            "200": { label: "200 次请求", description: "默认" },
        },
    },
    "task.softRequestBudgetNotice": {
        label: "软请求预算通知",
        description: "当子代理越过软请求预算时注入一次引导通知，要求它在 1.5 倍强制产出停止前收尾。",
    },
    "task.maxEffort": {
        label: "每次派生最大 effort",
        description: "task 工具按次派生 effort 提示允许的最大推理强度。较低值可防止调用方将子代理提升到超过此上限；默认保留模型的完整范围。",
        options: {
            minimal: { label: "min", description: "非常简短的推理（约 1k token）" },
            low: { label: "low", description: "轻度推理（约 2k token）" },
            medium: { label: "medium", description: "中等推理（约 8k token）" },
            high: { label: "high", description: "深度推理（约 16k token）" },
            xhigh: { label: "xhigh", description: "扩展推理（约 32k token）" },
            max: { label: "max", description: "模型支持的最大推理" },
        },
    },
    "task.prewalk": {
        label: "通用任务预走",
        description: "为捆绑的通用 `task` 子代理启用预走：它先从解析后的模型开始，规划并开始实现，然后在首次编辑/写入时交接给 'smol' 角色。按代理覆盖（task.agentPrewalk，在 /agents 中心配置）和用户代理 `prewalk` frontmatter 不受此开关影响。",
    },
    "plan.enabled": {
        label: "计划模式",
        description: "启用计划模式，在执行前进行只读探索和规划",
    },
    "plan.defaultOnStartup": {
        label: "启动时进入计划模式",
        description: "每个新会话开始时自动进入计划模式",
    },
    "plan.autosave": {
        label: "自动保存计划",
        description: "计划模式完成时自动将已批准的计划保存到磁盘",
    },
    "plan.autosaveDir": {
        label: "自动保存目录",
        description: "自动保存计划的目录。支持 ~、绝对路径和 cwd 相对路径。留空使用 <project>/.omp/plans/。",
    },
    "goal.enabled": {
        label: "目标模式",
        description: "启用按会话的目标模式和隐藏的 goal 工具",
    },
    "goal.statusInFooter": {
        label: "页脚中的目标状态",
        description: "在状态栏的目标指示器旁显示 token 预算",
    },
    "goal.continuationModes": {
        label: "目标延续模式",
        description: '活动目标可在轮次之间自动延续的运行模式（"interactive"、"rpc"）',
    },
    "title.generator": {
        label: "标题生成器",
        description: "根据用户消息为无标题会话命名的来源",
        options: {
            fork: {
                label: "分叉",
                description: "使用会话模型对回复进行一次侧轮：读取其提示缓存，并添加卡片图标（默认）",
            },
            tiny: { label: "微型", description: "仅使用标题模型角色；纯标题，不带卡片" },
        },
    },
    "title.refreshOnReplan": {
        label: "重新规划时刷新标题",
        description: "待办初始化重新规划后刷新生成的会话标题，除非标题由用户设置",
    },
    "skills.enableSkillCommands": {
        label: "技能命令",
        description: "将技能注册为 /skill:name 命令",
    },
    "commands.enableClaudeUser": {
        label: "Claude 用户命令",
        description: "从 ~/.claude/commands/ 加载命令",
    },
    "commands.enableClaudeProject": {
        label: "Claude 项目命令",
        description: "从 .claude/commands/ 加载命令",
    },
    "commands.enableOpencodeUser": {
        label: "OpenCode 用户命令",
        description: "从 ~/.config/opencode/commands/ 加载命令",
    },
    "commands.enableOpencodeProject": {
        label: "OpenCode 项目命令",
        description: "从 .opencode/commands/ 加载命令",
    },
};
