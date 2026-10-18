export const interactionSettingsZhCN = {
    "tools.approval": {
        label: "工具审批策略",
        description: "按工具设置审批策略。设为 'allow' 自动批准，'prompt' 需要确认，'deny' 阻止。覆盖设置在所有审批模式下都生效。",
    },
    "tools.approvalMode": {
        label: "工具审批",
        description: "工具调用的默认审批行为。'Always ask' 仅自动批准只读工具。'Write' 自动批准读取和工作区写入工具。'Yolo' 自动批准所有层级；用户策略仍可能要求确认或阻止。",
        options: {
            "always-ask": {
                label: "始终询问",
                description: "自动批准只读工具；写入和执行工具需要确认。",
            },
            write: {
                label: "写入",
                description: "自动批准只读和写入工具；bash、eval、browser、task 等执行工具需要确认。",
            },
            yolo: {
                label: "Yolo",
                description: "自动批准读取、写入和执行工具。用户策略仍可要求确认或阻止调用。",
            },
        },
    },
    autoResume: {
        label: "自动恢复",
        description: "自动恢复当前目录中最近的会话",
    },
    "git.enabled": {
        label: "启用 Git 集成",
        description: "在 TUI 中显示 git 分支、状态和 PR 信息，并监视仓库元数据。",
    },
    steeringMode: {
        label: "引导模式",
        description: "代理工作时如何处理排队的消息",
    },
    followUpMode: {
        label: "后续消息模式",
        description: "一轮完成后如何排空后续消息",
    },
    interruptMode: {
        label: "中断模式",
        description: "引导消息何时中断工具执行",
    },
    "tui.vimMode": {
        label: "Vim 编辑模式",
        description: "模态提示编辑。Esc 退出插入模式；普通模式支持 hjkl、0、$、^、w、b、e、gg、G、计数、x/D/C、dd/yy、p 和 u；操作符可接受动作或文本对象（diw、ca(、dap）；v/V 启动可视选择，y 复制，d 删除",
    },
    "tui.vimModeDisplay": {
        label: "Vim 模式指示器",
        description: "当前 Vim 模式在状态栏中的显示方式",
        options: {
            text: { label: "文本", description: "完整模式名——NORMAL、INSERT、VISUAL、V-LINE、REPLACE" },
            icon: { label: "图标", description: "每种模式使用单个紧凑字形" },
            none: { label: "隐藏", description: "不在状态栏显示模式" },
        },
    },
    "loop.mode": {
        label: "循环模式",
        description: "在重新提交提示之前，/loop 迭代之间执行什么操作",
        options: {
            prompt: { label: "提示", description: "将提示作为后续消息重新提交（当前行为）" },
            compact: { label: "压缩", description: "压缩会话上下文，然后重新提交提示" },
            reset: { label: "重置", description: "启动新会话，然后重新提交提示" },
        },
    },
    "loop.conditionTimeoutMs": {
        label: "循环条件超时（毫秒）",
        description: "等待 `/loop --while` / `--until` 条件命令的最长时间，超时后视为失败并停止循环。设为 0 表示无限等待",
        options: {
            "0": { label: "无限" },
            "10000": { label: "10 秒" },
            "30000": { label: "30 秒" },
            "120000": { label: "2 分钟" },
        },
    },
    "composer.recallClearedDrafts": {
        label: "恢复已清除草稿",
        description: "将用 Ctrl+C 清除的草稿保留在本地上/下历史中直到退出；禁用后只影响未来的清除操作",
    },
    doubleEscapeAction: {
        label: "双击 Esc 操作",
        description: "编辑器为空时连按两次 Esc 的行为：打开记录回退选择器、打开会话树，或什么都不做",
    },
    "input.bareExitOnEmptySession": {
        label: "空会话裸退出",
        description: "在第一条消息之前，仅提交 `exit`、`quit` 或 `q`（不区分大小写）时直接退出，而不是发送给模型",
    },
    "input.bareSlashCommands": {
        label: "裸斜杠命令",
        description: "仅提交不带前导 `/` 的命令名（例如 `model`、`compact`）时运行该斜杠命令；会话已有消息后，需按两次 Enter 确认",
    },
    treeFilterMode: {
        label: "会话树过滤器",
        description: "打开会话树时的默认过滤模式",
    },
    autocompleteMaxVisible: {
        label: "自动补全项数",
        description: "自动补全下拉框中可见项的最大数量（3-20）",
        options: {
            "3": { label: "3 项" },
            "5": { label: "5 项" },
            "7": { label: "7 项" },
            "10": { label: "10 项" },
            "15": { label: "15 项" },
            "20": { label: "20 项" },
        },
    },
    "spelling.typoDetection": {
        label: "拼写错误检测（macOS）",
        description: "使用当前 macOS 词典标记提示中拼写错误的单词",
    },
    "spelling.autocomplete": {
        label: "单词自动补全",
        description: "以内联提示显示预测的单词补全：Tab 接受并加空格，右方向键接受但不加",
        options: {
            off: { label: "关闭", description: "不进行单词补全" },
            auto: { label: "自动", description: "N-gram（无需下载）" },
            ngram: { label: "N-gram", description: "从提示历史中学习你的词汇" },
            smollm: { label: "SmolLM", description: "设备端小型语言模型与 N-gram 混合（首次使用时下载权重）" },
            apple: { label: "Apple", description: "macOS 词典补全" },
        },
    },
    "composer.predictions": {
        label: "输入区预测",
        description: "一轮完成后，让当前模型预测你的下一条消息，并以幽灵文本显示在空输入区中；按 Tab 或右方向键插入但不发送。额外用量：每个完成的轮次都会为整段对话多发一次计费请求（计入 /stats）",
    },
    "spelling.autocorrect": {
        label: "自动更正（macOS）",
        description: "在单词完成后应用有把握的 macOS 拼写更正",
    },
    emojiAutocomplete: {
        label: "Emoji 自动补全",
        description: "根据 `:name:` 短代码建议 emoji，并展开 `:D`、`:-)` 等文本表情",
    },
    "paste.largeMenuThreshold": {
        label: "大段粘贴菜单",
        description: "当粘贴达到这么多行时，提供菜单将其包入代码块、包入 XML 标签，或保存到文件。0 禁用菜单（大段粘贴仍会折叠为 [Paste] 标记）。",
        options: {
            "0": { label: "关闭" },
            "100": { label: "100 行" },
            "250": { label: "250 行" },
            "500": { label: "500 行" },
            "1000": { label: "1000 行" },
        },
    },
    "startup.quiet": {
        label: "静默启动",
        description: "跳过欢迎界面和启动状态消息",
    },
    "startup.showSplash": {
        label: "显示启动画面",
        description: "正常交互启动时显示完整动画设置启动画面，但不重新运行设置。静默启动仍会抑制它。",
    },
    "startup.setupWizard": {
        label: "设置向导",
        description: "每个设置版本显示一次新增的引导步骤",
    },
    "marketplace.autoUpdate": {
        label: "插件市场自动更新",
        description: "启动时检查插件更新",
        options: {
            off: { label: "关闭", description: "不检查插件更新" },
            notify: { label: "通知", description: "启动时检查，有更新时通知" },
            auto: { label: "自动", description: "启动时检查并自动安装更新" },
        },
    },
    "startup.changelogMode": {
        label: "启动更新日志",
        description: "选择更新说明以摘要、完整详情还是隐藏方式启动",
        options: {
            summary: { label: "摘要", description: "显示版本和变更数量，并提示 /changelog" },
            expanded: { label: "展开", description: "完整显示最近的版本说明" },
            hidden: { label: "隐藏", description: "启动时不显示版本说明" },
        },
    },
    "magicKeywords.enabled": {
        label: "魔法关键词",
        description: "为独立的 ultrathink、orchestrate、workflowz、jevify 关键词启用隐藏提示",
    },
    "magicKeywords.ultrathink": {
        label: "Ultrathink 关键词",
        description: "允许独立的 ultrathink 请求最大自动思考，并附加其隐藏提示",
    },
    "magicKeywords.orchestrate": {
        label: "Orchestrate 关键词",
        description: "允许独立的 orchestrate 附加其隐藏的多代理编排提示",
    },
    "magicKeywords.workflow": {
        label: "Workflow 关键词",
        description: "允许独立的 workflowz 附加其隐藏的 eval 工作流提示",
    },
    "magicKeywords.jevify": {
        label: "Jevify 关键词",
        description: "允许独立的 jevify 附加其隐藏的批量评判分类提示",
    },
    "completion.notify": {
        label: "完成通知",
        description: "代理完成一轮时通知",
    },
    "error.notify": {
        label: "错误通知",
        description: "代理因错误停止时通知",
    },
    "ask.timeout": {
        label: "询问超时",
        description: "在这么多秒后自动选择推荐的询问选项（0 禁用）。同时限制 cfg:// 审批提示；未回答的审批会拒绝写入，而不是自动选择",
        options: {
            "0": { label: "禁用" },
            "15": { label: "15 秒" },
            "30": { label: "30 秒" },
            "60": { label: "60 秒" },
            "120": { label: "120 秒" },
        },
    },
    "ask.notify": {
        label: "询问通知",
        description: "询问工具等待输入时通知",
    },
    "recap.enabled": {
        label: "空闲回顾",
        description: "终端空闲后，生成一段简短的 LLM 回顾说明当前进展",
    },
    "recap.idleSeconds": {
        label: "空闲回顾延迟",
        description: "显示回顾前等待的空闲秒数",
        options: {
            "60": { label: "1 分钟" },
            "120": { label: "2 分钟" },
            "240": { label: "4 分钟" },
            "300": { label: "5 分钟" },
            "600": { label: "10 分钟" },
        },
    },
    "power.sleepPrevention": {
        label: "防止睡眠",
        description: "活动会话期间防止系统睡眠。每个级别都是累积的——会包含所有更低级别的标志。",
        options: {
            off: { label: "关闭", description: "不阻止任何睡眠" },
            idle: { label: "阻止空闲睡眠", description: "会话打开时保持系统唤醒（macOS `caffeinate -i`）" },
            display: { label: "阻止显示器睡眠", description: "同时防止显示器空闲睡眠（macOS `caffeinate -i -d`）" },
            system: {
                label: "阻止系统睡眠",
                description: "同时阻止 AC 供电时的所有系统睡眠，并声明用户活跃（macOS `caffeinate -i -d -s -u`）",
            },
        },
    },
    "features.unexpectedStopDetection": {
        label: "意外停止",
        description: "当助手没有可见消息却停止时自动恢复。Smart 还会用小模型对纯文本停止进行分类。",
        options: {
            none: { label: "无", description: "禁用" },
            mechanical: { label: "机械", description: "在没有可见助手消息时重试；工具调用不在此列（默认）" },
            smart: { label: "智能", description: "机械恢复 + 小模型对纯文本停止进行分类" },
        },
    },
    "stt.enabled": {
        label: "语音转文字",
        description: "启用麦克风语音转文字输入",
    },
    "stt.submitTrigger": {
        label: "语音转文字提交触发",
        description: "选择语音听写何时自动提交：从不、松开（2 个及以上单词）、松开且为完整句子，或当我说提交时。",
        options: {
            never: { label: "从不", description: "从不自动提交；插入听写内容并留在编辑器中。" },
            release: { label: "松开", description: "松开时若话语有 2 个及以上单词则提交，以避免误发。" },
            "release-complete": {
                label: "松开且为完整句子",
                description: "松开时若话语以句子终止标点（. ? ! 等）结尾则提交。",
            },
            "say-submit": {
                label: "当我说提交时",
                description: "若话语以包含 'submit' 的单词结尾则提交（提交前会去掉该词）。",
            },
        },
    },
    "stream.redactPatterns": {
        label: "额外脱敏模式",
        description: "除 env/secrets.yml 值和内置凭据形态外，从每个流式行中额外脱敏的正则表达式",
    },
};
