import type { SettingTranslation } from "../../types";

export const toolsSettingsZhCN: Record<string, SettingTranslation> = {
	"ida.enabled": {
		label: "IDA Pro",
		description: "在 IDA Pro（idalib）中打开用 `read` 读取的可执行文件，并启用 `ida` 工具；未找到 IDA 安装时不生效",
	},
	"ida.python": {
		label: "IDA Python",
		description: "可导入 ida_domain 和 idapro 的 Python 解释器；留空自动检测",
	},
	"ida.installDir": {
		label: "IDA 安装目录",
		description: "包含 libidalib 的目录，导出为 IDADIR；留空自动检测（$IDADIR、ida-config.json、标准安装路径）",
	},
	"ida.maxOpen": {
		label: "IDA 最大打开数据库数",
		description:
			"每个项目同时打开的 IDA 数据库上限（omp ps 中的 omp.ida.* 守护进程）；再打开一个时会保存并关闭最久未使用的空闲数据库",
		options: {
			"2": { label: "2" },
			"4": { label: "4" },
			"8": { label: "8" },
			"16": { label: "16" },
		},
	},
	"ida.idleCloseSec": {
		label: "IDA 空闲关闭超时",
		description: "空闲超过这么多秒后保存并关闭 IDA 数据库（0 = 从不）；重新打开时 exec 命名空间会重置",
		options: {
			"0": { label: "从不" },
			"300": { label: "5 分钟" },
			"900": { label: "15 分钟" },
			"1800": { label: "30 分钟" },
			"3600": { label: "1 小时" },
		},
	},
	"tools.artifactSpillThreshold": {
		label: "产物溢出阈值（KB）",
		description: "超过此大小的工具输出会保存为产物；尾部保持内联",
		options: {
			"1": { label: "1 KB", description: "约 250 token" },
			"2.5": { label: "2.5 KB", description: "约 625 token" },
			"5": { label: "5 KB", description: "约 1.25K token" },
			"10": { label: "10 KB", description: "约 2.5K token" },
			"20": { label: "20 KB", description: "约 5K token" },
			"30": { label: "30 KB", description: "约 7.5K token" },
			"50": { label: "50 KB", description: "默认；约 12.5K token" },
			"75": { label: "75 KB", description: "约 19K token" },
			"100": { label: "100 KB", description: "约 25K token" },
			"200": { label: "200 KB", description: "约 50K token" },
			"500": { label: "500 KB", description: "约 125K token" },
			"1000": { label: "1 MB", description: "约 250K token" },
		},
	},
	"tools.artifactTailBytes": {
		label: "产物尾部大小（KB）",
		description: "输出溢出到产物时保持内联的尾部内容大小",
		options: {
			"1": { label: "1 KB", description: "约 250 token" },
			"2.5": { label: "2.5 KB", description: "约 625 token" },
			"5": { label: "5 KB", description: "约 1.25K token" },
			"10": { label: "10 KB", description: "约 2.5K token" },
			"20": { label: "20 KB", description: "默认；约 5K token" },
			"50": { label: "50 KB", description: "约 12.5K token" },
			"100": { label: "100 KB", description: "约 25K token" },
			"200": { label: "200 KB", description: "约 50K token" },
		},
	},
	"tools.artifactHeadBytes": {
		label: "产物头部大小（KB）",
		description: "输出溢出到产物时与尾部一起保持内联的头部内容大小（中间省略）。0 禁用——仅保留尾部。",
		options: {
			"0": { label: "0 KB", description: "禁用；仅截断尾部" },
			"1": { label: "1 KB", description: "约 250 token" },
			"2.5": { label: "2.5 KB", description: "约 625 token" },
			"5": { label: "5 KB", description: "约 1.25K token" },
			"10": { label: "10 KB", description: "约 2.5K token" },
			"20": { label: "20 KB", description: "默认；约 5K token" },
			"50": { label: "50 KB", description: "约 12.5K token" },
			"100": { label: "100 KB", description: "约 25K token" },
			"200": { label: "200 KB", description: "约 50K token" },
		},
	},
	"tools.outputMaxColumns": {
		label: "输出列上限",
		description:
			"流式工具输出（bash、python、js eval）和 `read` 的每行字节上限。超过此宽度的行会被省略号截断；到下一个换行符之前的剩余字节会被丢弃。0 禁用。",
		options: {
			"0": { label: "关闭", description: "无每行上限" },
			"256": { label: "256", description: "紧凑" },
			"512": { label: "512" },
			"768": { label: "768", description: "默认" },
			"1024": { label: "1024" },
			"2048": { label: "2048" },
			"4096": { label: "4096", description: "宽松" },
		},
	},
	"tools.artifactTailLines": {
		label: "产物尾部行数",
		description: "输出溢出到产物时保持内联的尾部内容最大行数",
		options: {
			"50": { label: "50 行", description: "约 250 token" },
			"100": { label: "100 行", description: "约 500 token" },
			"250": { label: "250 行", description: "约 1.25K token" },
			"500": { label: "500 行", description: "默认；约 2.5K token" },
			"1000": { label: "1000 行", description: "约 5K token" },
			"2000": { label: "2000 行", description: "约 10K token" },
			"5000": { label: "5000 行", description: "约 25K token" },
		},
	},
	"tools.artifactMaxBytes": {
		label: "产物文件上限（MB）",
		description:
			"为流式工具输出（bash、python、js eval）保存的产物文件最大大小。更大的输出会保留开头（最多 3 MB）和最近的剩余部分，并在两者之间显示截断提示。0 = 不限制。",
		options: {
			"0": { label: "不限制", description: "保存完整输出" },
			"4": { label: "4 MB" },
			"16": { label: "16 MB", description: "默认" },
			"64": { label: "64 MB" },
			"256": { label: "256 MB" },
			"1024": { label: "1 GB" },
		},
	},
	"todo.enabled": {
		label: "待办",
		description: "启用 todo 工具以跟踪任务",
	},
	"todo.reminders": {
		label: "待办提醒",
		description: "提醒代理在停止前完成待办",
	},
	"todo.remindersMax": {
		label: "待办提醒上限",
		description: "放弃前的最大待办提醒次数",
		options: {
			"1": { label: "1 次提醒" },
			"2": { label: "2 次提醒" },
			"3": { label: "3 次提醒" },
			"5": { label: "5 次提醒" },
		},
	},
	"todo.eager": {
		label: "自动创建待办",
		description: "第一条消息后推动自动创建待办列表的强度",
		options: {
			default: { label: "默认", description: "由模型决定；不自动创建待办列表" },
			preferred: { label: "偏好", description: "在第一条消息时建议创建待办列表（提醒，不强制）" },
			always: { label: "始终", description: "在第一条消息时强制创建完整的待办列表" },
		},
	},
	"tasks.todoClearDelay": {
		label: "待办自动清除延迟",
		description: "已完成或放弃的待办从待办组件中移除前的延迟",
		options: {
			"0": { label: "立即" },
			"60": { label: "1 分钟", description: "默认" },
			"300": { label: "5 分钟" },
			"900": { label: "15 分钟" },
			"1800": { label: "30 分钟" },
			"3600": { label: "1 小时" },
			"-1": { label: "从不" },
		},
	},
	"glob.enabled": {
		label: "Glob",
		description: "启用 glob 工具以进行基于通配符的文件查找",
	},
	"grep.enabled": {
		label: "Grep",
		description: "启用 grep 工具以进行正则内容搜索",
	},
	"grep.contextBefore": {
		label: "Grep 前置上下文",
		description: "每个 grep 匹配前的上下文行数",
		options: {
			"0": { label: "0 行" },
			"1": { label: "1 行" },
			"2": { label: "2 行" },
			"3": { label: "3 行" },
			"5": { label: "5 行" },
		},
	},
	"grep.contextAfter": {
		label: "Grep 后置上下文",
		description: "每个 grep 匹配后的上下文行数",
		options: {
			"0": { label: "0 行" },
			"1": { label: "1 行" },
			"2": { label: "2 行" },
			"3": { label: "3 行" },
			"5": { label: "5 行" },
			"10": { label: "10 行" },
		},
	},
	"astGrep.enabled": {
		label: "AST Grep",
		description: "启用 ast_grep 工具以进行结构化 AST 搜索",
	},
	"astEdit.enabled": {
		label: "AST Edit",
		description: "启用 ast_edit 工具以进行结构化 AST 重写",
	},
	"find.enabled": {
		label: "Find（语义搜索）",
		description:
			"启用 find 工具：用自然语言搜索文件和行范围，由评判模型角色判断。auto 仅在评判角色解析为原生 TypeSafe jev 模型时启用",
		options: {
			auto: { label: "自动", description: "当评判角色解析为原生 TypeSafe jev 模型时启用" },
			on: { label: "开启", description: "无论评判角色解析为哪个模型都始终启用" },
			off: { label: "关闭", description: "禁用 find 工具" },
		},
	},
	"debug.enabled": {
		label: "调试",
		description: "启用 debug 工具以进行基于 DAP 的调试",
	},
	"launch.enabled": {
		label: "服务",
		description: "启用命名 bash 服务和 proc:// 监管，用于共享的长时间运行项目进程",
	},
	"speechgen.enabled": {
		label: "语音生成",
		description: "启用 tts 工具以进行设备端（Kokoro）或 xAI Grok Voice 语音文件合成",
	},
	"generate_image.enabled": {
		label: "生成图片",
		description: "启用 generate_image 工具（文生图生成和编辑）。当 tools.xdev 开启时以 xd:// 设备形式暴露。",
	},
	"computer.enabled": {
		label: "计算机",
		description: "启用可脚本化的宿主桌面 eval 前奏（截图、输入、辅助功能）",
	},
	"ratchet.enabled": {
		label: "Ratchet",
		description: "启用 ratchet eval/hillclimb 前奏；/ratchet 会为当前会话开启它",
	},
	"archive.enabled": {
		label: "归档",
		description: "启用只读 archive eval 前奏：提示历史、最近项目、过往会话和回顾",
	},
	"computer.display": {
		label: "计算机显示器",
		description: "活动窗口所在显示器（active）、所有显示器（all），或原生显示器 ID",
	},
	"computer.maxWidth": {
		label: "计算机截图宽度",
		description: "截图最大宽度（像素）",
	},
	"computer.maxHeight": {
		label: "计算机截图高度",
		description: "截图最大高度（像素）",
	},
	"images.questionTimeoutMs": {
		label: "图片提问超时",
		description:
			"read 的 ?q= 图片提问背后的视觉模型调用的每请求超时（毫秒）。卡住的提供商会快速失败并报超时错误，而不是阻塞到手动中止。设为 0 禁用超时。",
		options: {
			"0": { label: "禁用" },
			"60000": { label: "1 分钟" },
			"120000": { label: "2 分钟" },
			"180000": { label: "3 分钟" },
			"300000": { label: "5 分钟" },
		},
	},
	"checkpoint.enabled": {
		label: "检查点/回退",
		description: "启用 checkpoint 和 rewind 工具以进行上下文检查点",
	},
	"fetch.enabled": {
		label: "读取 URL",
		description: "允许 read 工具抓取并处理 URL",
	},
	"vault.enabled": {
		label: "Obsidian 仓库",
		description:
			"启用 vault:// 内部 URL，通过 Obsidian CLI 读取和编辑 Obsidian 仓库内容。禁用时拒绝 vault:// 解析，并从系统提示中省略 vault:// 条目。",
	},
	"github.enabled": {
		label: "GitHub CLI",
		description:
			"启用 github 工具（基于 op 的分派，用于仓库、议题、拉取请求、差异、搜索、检出、推送和 Actions 监视工作流）",
	},
	"github.cache.enabled": {
		label: "GitHub 视图缓存",
		description: "将渲染后的议题/PR 视图输出缓存到 ~/.omp/cache/github-cache.db，使重复读取无需开销",
	},
	"github.cache.softTtlSec": {
		label: "GitHub 缓存软 TTL",
		description: "在此窗口内直接返回缓存的议题/PR 视图行（秒；默认 5 分钟）",
	},
	"github.cache.hardTtlSec": {
		label: "GitHub 缓存硬 TTL",
		description: "超过软 TTL 后返回缓存行并在后台刷新；超过硬 TTL 后丢弃（秒；默认 7 天）",
	},
	"web_search.enabled": {
		label: "网络搜索",
		description: "启用 web_search 工具以获取实时网络结果",
	},
	"security.enabled": {
		label: "安全",
		description: "启用 OMP 原生安全扫描规划、执行以及只读 security:// 资源命名空间",
	},
	"ask.enabled": {
		label: "询问",
		description: "启用 ask 工具以向用户提出交互式问题",
	},
	"tools.intentTracing": {
		label: "意图跟踪",
		description: "要求代理在执行每个工具调用前描述其意图",
	},
	"tools.abortOnFabricatedResult": {
		label: "伪造工具结果时中止",
		description:
			"使用带内工具调用时，若模型在轮次中途开始幻觉工具结果，立即停止模型。禁用则让模型完成生成并丢弃伪造的续写。",
	},
	"tools.speculativeExecution.enabled": {
		label: "实验性推测执行",
		description:
			"启用可安全丢弃的首批范围：通过直接 read 调用和嵌套 eval 进行经过验证的本地读取。网络请求、提供商补全和实时文件系统写入不在此基线内。",
	},
	"tools.speculativeExecution.maxInFlight": {
		label: "推测执行并发数",
		description: "正常分派前允许并发运行的经过验证的本地读取数量上限。",
		options: {
			"1": { label: "1 个操作" },
			"2": { label: "2 个操作" },
			"3": { label: "3 个操作" },
			"4": { label: "4 个操作" },
		},
	},
	"tools.maxTimeout": {
		label: "工具最大超时",
		description: "代理可为任何工具设置的最大超时秒数（0 = 不限制）",
		options: {
			"0": { label: "不限制" },
			"30": { label: "30 秒" },
			"60": { label: "60 秒" },
			"120": { label: "120 秒" },
			"300": { label: "5 分钟" },
			"600": { label: "10 分钟" },
		},
	},
	"async.enabled": {
		label: "异步执行",
		description: "启用异步 bash 命令和后台任务执行",
	},
	"tools.xdev": {
		label: "xd:// 工具",
		description:
			"将不常用的（可发现的）工具挂载到 xd:// 设备 URL 下，通过 read/write 驱动，而不是在每个请求中携带其 schema。显式工具列表授予 read 但省略 write 的会话会通过仅设备写入传输挂载设备（除设备外，只有 local:// 暂存区可写）。禁用则将所有已启用工具暴露在顶层。",
	},
	"tools.xdevDocs": {
		label: "xd:// 提示文档",
		description:
			"选择哪些已挂载设备的文档和 schema 内联到系统提示中。内置模式保持核心工具内联，MCP 和扩展工具按需获取。",
		options: {
			inline: { label: "所有设备", description: "内联每个已挂载设备的文档和 schema。" },
			builtins: { label: "仅内置", description: "内联内置文档；按需获取 MCP 和扩展文档。" },
			catalog: { label: "仅目录", description: "列出所有设备；按需获取全部文档。" },
		},
	},
	"tools.xdevInlineDevices": {
		label: "xd:// 内联设备",
		description:
			"当 xd:// 提示文档设为“仅内置”时，内联名称匹配这些 glob 模式的动态设备（例如 mcp__context_mode_*）。“仅目录”会忽略此设置。",
	},
	"extensionHandlers.toolCallTimeoutMs": {
		label: "工具调用处理器超时（毫秒）",
		description: "扩展 tool_call 处理器的正有限活动工作超时；无效值使用 30000ms，等待 OMP 自有对话框的时间不计入",
	},
	"browser.enabled": {
		label: "浏览器",
		description: "启用 browser eval 前奏以进行脚本化 Chromium 自动化（Puppeteer）",
	},
	"browser.cdpUrl": {
		label: "浏览器 CDP URL",
		description:
			"默认 HTTP CDP 发现端点（例如 http://127.0.0.1:9222），用于附加而非启动浏览器。工具调用中显式的 app.cdp_url 或 app.path 优先。",
	},
	"browser.relay": {
		label: "浏览器中继",
		description:
			"通过 omp 浏览器中继驱动你自己的 Chrome 标签页。安装一次扩展（`omp browser-relay install`）；浏览器前奏需要时中继服务器会自动启动。优先于浏览器 CDP URL；设置 PI_BROWSER_RELAY=0 或 PI_BROWSER_RELAY=1 可覆盖。",
	},
	"browser.relayUrl": {
		label: "浏览器中继 URL",
		description: "omp 浏览器中继端点（默认 http://127.0.0.1:9224）。",
	},
	"browser.headless": {
		label: "无头浏览器",
		description: "以无头模式启动浏览器（禁用则显示浏览器 UI）",
	},
	"browser.cmux": {
		label: "cmux 浏览器",
		description:
			"cmux socket 可用时，使用 cmux WKWebView 表面进行浏览器自动化。设置 PI_BROWSER_CMUX=0 或 PI_BROWSER_CMUX=1 可覆盖。",
	},
	"browser.tern": {
		label: "Tern 浏览器",
		description:
			"在 Tern 窗格内，将浏览器标签页作为画中画打开在 omp 窗格上（原生 Web 视图），而不是无头 Chromium；没有可承载的 Tern 窗口时回退到 Chromium。显式 app 选项、中继和浏览器 CDP URL 优先；app.tern:false 可使单次打开退出。设置 PI_BROWSER_TERN=0 或 PI_BROWSER_TERN=1 可覆盖。",
	},
	"browser.freezeOnTurnEnd": {
		label: "轮次结束时冻结浏览器标签页",
		description:
			"轮次稳定时冻结 OMP 拥有的无头浏览器标签页，使动画页面在空闲时停止消耗 CPU/GPU。标签页下次使用时自动解冻；打开时传 persist:true 可使标签页退出此行为。",
	},
	"browser.idleCloseSec": {
		label: "浏览器空闲关闭超时",
		description:
			"关闭空闲超过这么多秒的 OMP 拥有的无头浏览器标签页和 Tern 浏览器画中画（0 = 从不；会话释放仍会回收）。绝不影响中继/CDP/派生的浏览器或其他会话的标签页。",
		options: {
			"0": { label: "从不" },
			"900": { label: "15 分钟" },
			"1800": { label: "30 分钟" },
			"3600": { label: "1 小时" },
		},
	},
	"browser.screenshotDir": {
		label: "截图目录",
		description:
			"保存截图的目录。未设置时截图保存到临时文件。支持 ~。示例：~/Downloads、~/Desktop、/sdcard/Download（Android）",
	},
	"mcp.enableProjectConfig": {
		label: "MCP 项目配置",
		description: "从项目根目录加载 .mcp.json/mcp.json",
	},
	"mcp.startupTimeoutMs": {
		label: "MCP 启动窗口",
		description: "等待初始 MCP 工具发现的毫秒数；0 表示等待连接稳定",
	},
	"mcp.renderMarkdownResults": {
		label: "MCP Markdown 结果",
		description: "在记录中将非 JSON 的 MCP 文本结果渲染为 Markdown",
	},
	"mcp.notifications": {
		label: "MCP 更新注入",
		description: "将 MCP 资源更新注入代理对话",
	},
	"mcp.notificationDebounceMs": {
		label: "MCP 通知防抖",
		description: "将 MCP 资源更新注入对话前的防抖窗口（毫秒）",
	},
};
