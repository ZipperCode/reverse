export const shellSettingsZhCN = {
    "bash.enabled": {
        label: "Bash",
        description: "启用 bash 工具以执行 shell 命令",
    },
    "bash.allowCompoundCommands": {
        label: "允许复合命令",
        description: "按命令评估字面量 && 链；未匹配的命令使用常规 bash 审批策略和模式",
    },
    "bash.autoBackground.enabled": {
        label: "Bash 自动后台",
        description: "自动将长时间运行的 bash 命令转入后台，稍后交付结果",
    },
    "bash.gitGuard": {
        label: "Git 防护",
        description: "在 bash 工具中拒绝会丢弃或移动共享工作的 git 命令：stash、reset --hard 或 reset 到其他提交，以及在合并/变基冲突之外执行 checkout/switch/restore",
    },
    "bash.patterns": {
        label: "Bash 审批模式",
        description: "有序的 bash 命令审批规则。每项包含 match 和 approval 字段；仅支持 '*' 通配符。",
    },
    "bashInterceptor.enabled": {
        label: "Bash 拦截器",
        description: "阻止已有专用工具的 shell 命令",
    },
    "bash.direnv": {
        label: "direnv 自动加载",
        description: "将仓库的 direnv/devenv `.envrc` 自动加载到 bash 会话中，使 devenv 工具和环境变量无需手动 `direnv exec` 即可使用。遵守 direnv 的允许列表：未执行 `direnv allow` 的 `.envrc` 绝不会被执行",
    },
    "bash.direnvLoadTimeoutMs": {
        label: "direnv 加载超时（毫秒）",
        description: "首次 `direnv export` 的最长等待时间（冷启动的 devenv shell 可能较慢）；超时后会话在没有 direnv 环境的情况下运行",
    },
    "shellMinimizer.enabled": {
        label: "Shell 输出精简",
        description: "在将冗长的 shell 输出（git、npm、cargo 等）返回给代理前进行压缩",
    },
    "shellMinimizer.sourceOutlineLevel": {
        label: "Shell 精简源码大纲",
        description: "cat/read 源码文件时的大纲模式：default 或 aggressive",
    },
    "eval.py": {
        label: "Python Eval 后端",
        description: "允许 eval 工具将 Python 单元格分派到 IPython 内核",
    },
    "eval.js": {
        label: "JavaScript Eval 后端",
        description: "允许 eval 工具将 JavaScript 单元格分派到进程内运行时",
    },
    "eval.autoProvision": {
        label: "Eval 环境自动配置",
        description: "首次安装时自动创建托管的 JavaScript eval 包环境",
    },
    "eval.tools.enabled": {
        label: "Eval 定义的工具",
        description: "允许 eval 单元格定义工具（Python 中的 @tool，JS 中的 tool(fn)），供 task、agent() 和 workpool() 子代理调用",
    },
    "eval.workpool.freshAgents": {
        label: "Workpool 全新代理",
        description: "为每个 workpool 项派生新子代理，而不是复用工作器或批量处理排队项",
    },
    "eval.autoBackground.enabled": {
        label: "Eval 自动后台",
        description: "自动将长时间运行的 eval 单元格转入后台，稍后交付结果",
    },
    "python.kernelMode": {
        label: "Python 内核模式",
        description: "在多次 eval 调用之间保持 IPython 内核存活，或每次重新启动",
    },
    "python.interpreter": {
        label: "Python 解释器",
        description: "可选：指定确切的 Python 可执行文件路径。设置后将跳过自动 Python 运行时发现。",
    },
};
