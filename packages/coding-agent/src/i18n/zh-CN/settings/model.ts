import type { SettingTranslation } from "../../types";

export const modelSettingsZhCN: Record<string, SettingTranslation> = {
	"prewalk.enabled": {
		label: "启用预走（Prewalk）",
		description:
			"先使用当前模型，在计划提示的待办列表出现后、首次编辑/写入时切换到快速/低成本模型（默认 'smol' 角色）——强模型负责规划、提交待办并开始实现，然后交接。可用 --prewalk / --no-prewalk 按会话覆盖。",
	},
	"prewalk.from": {
		label: "预走规划模型",
		description: "/prewalk restart 返回用于规划的模型或角色（默认 '@default'）。",
	},
	"prewalk.into": {
		label: "预走目标",
		description:
			"预走在首次编辑/写入时交接到的模型或角色（默认 '@smol'）：适用于 /prewalk、/prewalk restart、启用预走及 --prewalk。自动预走使用其独立目标。",
	},
	"prewalk.auto": {
		label: "自动预走（Auto Prewalk）",
		description:
			"通过 'judge' 角色解析出的原生评判模型判断每个新的顶层用户任务是否将困难推理解析前置。需要原生评判模型；若无则不进行分类。独立于“启用预走（Prewalk）”。",
		options: {
			off: { label: "关闭", description: "从不对提示进行预走分类" },
			suggest: {
				label: "建议",
				description: "对每个任务进行分类并报告结论，但不启用预走",
			},
			on: {
				label: "开启",
				description: "对于高置信度的推理前置任务，准备从当前模型交接到自动目标模型；下一个任务重新从规划模型开始",
			},
		},
	},
	"prewalk.autoTarget": {
		label: "自动预走目标",
		description: "自动预走在首次编辑/写入时交接到的模型或角色（默认 '@smol'）。",
	},
	"images.describeForTextModels": {
		label: "为纯文本模型描述图片",
		description:
			"当图片附加到不支持视觉的模型时，将其保存到 local://，并注入由支持视觉的模型生成的描述，而不是丢弃图片",
	},
	defaultThinkingLevel: {
		label: "思考级别",
		description: "支持思考的模型的推理深度",
		options: {
			auto: { label: "auto", description: "按提示自动检测" },
			minimal: { label: "min", description: "非常简短的推理（约 1k token）" },
			low: { label: "low", description: "轻度推理（约 2k token）" },
			medium: { label: "medium", description: "中等推理（约 8k token）" },
			high: { label: "high", description: "深度推理（约 16k token）" },
			xhigh: { label: "xhigh", description: "扩展推理（约 32k token）" },
			max: { label: "max", description: "模型支持的最大推理" },
		},
	},
	hideThinkingBlock: {
		label: "隐藏思考块",
		description: "在助手回复中隐藏思考块",
	},
	expandThinkingBlocks: {
		label: "展开思考块",
		description: "默认显示思考正文；展开记录详情时可临时查看已折叠内容",
	},
	proseOnlyThinking: {
		label: "仅散文思考",
		description: "从思考摘要中省略代码块，并用省略号代替",
	},
	omitThinking: {
		label: "省略思考摘要",
		description: "指示上游提供商在响应中完全省略思考摘要（如支持）",
	},
	externalThinking: {
		label: "外部思考",
		description: "私有草稿区；不向用户显示。禁用受支持的 GPT、Claude 和 Gemini 推理",
		warning: "风险自负：提供商已将这种请求形态标记为滥用，可能导致账户级处罚",
	},
	"model.loopGuard.enabled": {
		label: "循环防护",
		description: "为模型推理和散文启用自动流循环检测",
	},
	"model.loopGuard.checkAssistantContent": {
		label: "循环防护扫描散文",
		description: "除思考日志外，也对助手散文消息应用循环防护",
	},
	"model.loopGuard.toolCallReminder": {
		label: "循环防护工具调用提醒",
		description:
			"当 Gemini 推理流连续输出多个规划标题却不调用工具时，中断它并注入提醒，要求发出工具调用（需要循环防护）",
	},
	"model.toolCallLoopGuard.enabled": {
		label: "工具调用循环防护",
		description: "检测重复调用及同因确定性派发失败；达到阈值后提醒，并在执行前拦截未修正的重试",
	},
	"model.toolCallLoopGuard.threshold": {
		label: "工具调用循环阈值",
		description: "提醒前累计的重复调用或同因确定性派发失败次数；下一次未修正的重试会停止当前回合",
	},
	"model.toolCallLoopGuard.exemptTools": {
		label: "工具调用循环豁免工具",
		description: "允许连续重复而不触发跨轮次循环防护的工具名称",
	},
	inlineToolDescriptors: {
		label: "内联工具描述",
		description:
			"在系统提示中渲染完整的工具描述，并从提供商工具 schema 中移除顶层/嵌套描述，使描述文本只发送一次。auto 对 Gemini 模型启用，其他情况禁用",
		options: {
			auto: { label: "自动", description: "Gemini 模型使用内联描述；其他情况保留在工具 schema 中" },
			on: { label: "开启", description: "始终在系统提示中内联描述" },
			off: { label: "关闭", description: "仅在提供商工具 schema 中保留描述" },
		},
	},
	includeModelInPrompt: {
		label: "在提示中包含模型",
		description: "在系统提示中显示当前模型标识符，让代理知道自己是哪个模型",
	},
	includeWorkspaceTree: {
		label: "包含工作区目录树",
		description: "在系统提示中渲染工作区目录树。警告：文件修改后可能破坏跨会话的提示缓存。",
	},
	skillful: {
		label: "在提示中列出技能",
		description: "在系统提示中列出可用技能；禁用可节省上下文，并可用 /skillful 按会话切换",
	},
	personality: {
		label: "个性",
		description: "渲染到系统提示个性块中的沟通风格",
		options: {
			default: { label: "默认", description: "简洁、证据优先的工程师；回复密集且面向行动" },
			friendly: { label: "友好", description: "温暖、鼓励的协作者，关注势头和士气" },
			pragmatic: { label: "务实", description: "直接、高效的工程师，注重清晰和严谨" },
			none: { label: "无", description: "完全省略个性块" },
		},
	},
	temperature: {
		label: "温度",
		description: "采样温度（0 = 确定性，1 = 创造性，-1 = 提供商默认）",
		options: {
			"-1": { label: "默认", description: "使用提供商默认值" },
			"0": { label: "0", description: "确定性" },
			"0.2": { label: "0.2", description: "聚焦" },
			"0.5": { label: "0.5", description: "均衡" },
			"0.7": { label: "0.7", description: "创造性" },
			"1": { label: "1", description: "最大多样性" },
		},
	},
	topP: {
		label: "Top P",
		description: "核采样截断值（0-1，-1 = 提供商默认）",
		options: {
			"-1": { label: "默认", description: "使用提供商默认值" },
			"0.1": { label: "0.1", description: "非常聚焦" },
			"0.3": { label: "0.3", description: "聚焦" },
			"0.5": { label: "0.5", description: "均衡" },
			"0.9": { label: "0.9", description: "宽泛" },
			"1": { label: "1", description: "不做核过滤" },
		},
	},
	topK: {
		label: "Top K",
		description: "从前 K 个 token 中采样（-1 = 提供商默认）",
		options: {
			"-1": { label: "默认", description: "使用提供商默认值" },
			"1": { label: "1", description: "贪心选择最高 token" },
			"20": { label: "20", description: "聚焦" },
			"40": { label: "40", description: "均衡" },
			"100": { label: "100", description: "宽泛" },
		},
	},
	minP: {
		label: "Min P",
		description: "最小概率阈值（0-1，-1 = 提供商默认）",
		options: {
			"-1": { label: "默认", description: "使用提供商默认值" },
			"0.01": { label: "0.01", description: "非常宽松" },
			"0.05": { label: "0.05", description: "均衡" },
			"0.1": { label: "0.1", description: "严格" },
		},
	},
	presencePenalty: {
		label: "存在惩罚",
		description: "对引入已存在 token 的惩罚（-1 = 提供商默认）",
		options: {
			"-1": { label: "默认", description: "使用提供商默认值" },
			"0": { label: "0", description: "无惩罚" },
			"0.5": { label: "0.5", description: "轻度新颖性" },
			"1": { label: "1", description: "鼓励新颖性" },
			"2": { label: "2", description: "强烈新颖性" },
		},
	},
	repetitionPenalty: {
		label: "重复惩罚",
		description: "对重复 token 的惩罚（-1 = 提供商默认）",
		options: {
			"-1": { label: "默认", description: "使用提供商默认值" },
			"0.8": { label: "0.8", description: "允许重复" },
			"1": { label: "1", description: "无惩罚" },
			"1.1": { label: "1.1", description: "轻度惩罚" },
			"1.2": { label: "1.2", description: "均衡" },
			"1.5": { label: "1.5", description: "强惩罚" },
		},
	},
	textVerbosity: {
		label: "文本详细度",
		description: "OpenAI Responses 和 Codex 响应的详细度（low、medium 或 high）",
		options: {
			low: { label: "低", description: "偏好简洁回复" },
			medium: { label: "中", description: "平衡简洁与细节（默认）" },
			high: { label: "高", description: "偏好详细回复" },
		},
	},
	"tier.openai": {
		label: "服务层级 — OpenAI",
		description:
			"OpenAI / OpenAI-Codex 请求以及经 OpenRouter 路由的 OpenAI 系列模型的处理层级（none = 省略）。以 `service_tier` 发送。",
		options: {
			none: { label: "无", description: "省略 service_tier（标准处理）" },
			auto: { label: "自动", description: "提供商默认层级选择" },
			default: { label: "默认", description: "标准优先级处理" },
			flex: { label: "Flex", description: "可用时成本更低、延迟更高" },
			scale: { label: "Scale", description: "可用时使用 Scale Tier 额度" },
			priority: { label: "优先", description: "更快、成本更高（高级请求）" },
			ultrafast: { label: "极速", description: "最低延迟服务；需要 OpenAI API 预览权限或支持该能力的 Codex 模型" },
		},
	},
	"tier.anthropic": {
		label: "服务层级 — Anthropic",
		description:
			'Claude 请求的处理层级。`priority` 在受支持的 Anthropic 直连模型上启用快速模式（`speed: "fast"`）；在 Bedrock/Vertex Claude 及经 OpenRouter 时忽略。',
		options: {
			none: { label: "无", description: "标准处理" },
			priority: {
				label: "优先",
				description: '受支持的 Claude 直连模型启用快速模式（`speed: "fast"`）；Bedrock/Vertex 上忽略',
			},
		},
	},
	"tier.google": {
		label: "服务层级 — Google",
		description:
			"Gemini（Google AI Studio + Vertex）请求以及经 OpenRouter 路由的 Google 系列模型的处理层级（none = 省略）。以顶层 `serviceTier` 字段发送。",
		options: {
			none: { label: "无", description: "标准处理" },
			flex: { label: "Flex", description: "可用时成本更低、延迟更高（Gemini API + Vertex）" },
			priority: { label: "优先", description: "更快、更可靠（Gemini API + Vertex）" },
		},
	},
	"tier.subagent": {
		label: "服务层级 — 子代理",
		description:
			"任务/eval 子代理使用的服务层级。inherit = 跟随主代理按模型系列实时设置的层级（跟踪 /fast）；选择具体值则应用到子代理模型所属系列。",
		options: {
			inherit: { label: "继承", description: "跟随主代理按模型系列实时设置的层级" },
			none: { label: "无", description: "标准处理" },
			auto: { label: "自动", description: "提供商默认层级选择（OpenAI 系列）" },
			default: { label: "默认", description: "标准优先级处理（OpenAI 系列）" },
			flex: { label: "Flex", description: "弹性容量层级（OpenAI/Google 系列）" },
			scale: { label: "Scale", description: "Scale Tier 额度（OpenAI 系列）" },
			priority: { label: "优先", description: "对派生模型所有受支持系列使用优先处理" },
			ultrafast: { label: "极速", description: "极速服务（OpenAI 系列，如可用）" },
		},
	},
	"tier.advisor": {
		label: "服务层级 — 顾问",
		description:
			"顾问模型的服务层级。none = 标准处理；inherit = 跟随主代理按模型系列实时设置的层级；选择具体值则应用到顾问模型所属系列。",
		options: {
			inherit: { label: "继承", description: "跟随主代理按模型系列实时设置的层级" },
			none: { label: "无", description: "标准处理" },
			auto: { label: "自动", description: "提供商默认层级选择（OpenAI 系列）" },
			default: { label: "默认", description: "标准优先级处理（OpenAI 系列）" },
			flex: { label: "Flex", description: "弹性容量层级（OpenAI/Google 系列）" },
			scale: { label: "Scale", description: "Scale Tier 额度（OpenAI 系列）" },
			priority: { label: "优先", description: "对派生模型所有受支持系列使用优先处理" },
			ultrafast: { label: "极速", description: "极速服务（OpenAI 系列，如可用）" },
		},
	},
	"retry.maxRetries": {
		label: "重试次数",
		description: "API 错误时的最大重试次数",
		options: {
			"1": { label: "1 次重试" },
			"2": { label: "2 次重试" },
			"3": { label: "3 次重试" },
			"5": { label: "5 次重试" },
			"10": { label: "10 次重试" },
		},
	},
	"retry.maxDelayMs": {
		label: "最大重试延迟",
		description:
			"重试之间的最长等待时间（毫秒）。当提供商要求等待超过此值，且没有凭据或模型回退成功时，请求快速失败而不是休眠（例如 Anthropic 的 3 小时限流窗口）。0 禁用上限——让会话在提供商声明的配额重置后自动恢复。",
	},
	"retry.waitForUsageReset": {
		label: "等待用量重置",
		description:
			"当提供商报告用量限制耗尽并给出重置时间（任何提供商的 5 小时或每周配额窗口）时，休眠到重置，而不是在超过 retry.maxDelayMs 后快速失败。等待可中止（Esc），但也会阻塞子代理，因此无人值守运行时应保持关闭。",
	},
	"retry.modelFallback": {
		label: "重试模型回退",
		description: "允许重试恢复在提供商错误后切换到 retry.fallbackChains 中的模型。独立于自动提升上下文",
	},
	"retry.fallbackOn": {
		label: "回退触发条件",
		description: "哪些失败请求可以切换到配置的回退模型",
		options: {
			any: { label: "任何错误", description: "每个提供商错误都可以切换模型" },
			"usage-limit": {
				label: "仅用量限制",
				description: "仅在用量限制时切换；其他错误在同一模型上重试，然后上报",
			},
			"except-usage-limit": {
				label: "除用量限制外全部",
				description: "等待或上报用量限制；其他错误时切换",
			},
		},
	},
	"retry.usageAwareFallback": {
		label: "用量感知回退",
		description:
			"使用可靠的编码套餐配额报告，在触发硬性用量限制前优先选择同提供商账户，然后选择配置的回退模型。普通配置的 API 密钥不在此列。",
	},
	"retry.usageReservePct": {
		label: "保留余量",
		description: "当编码套餐模型剩余百分比低于此值时，视为接近限制。用量未知或未映射时保留主模型。",
		options: {
			"5": { label: "5%", description: "仅在几乎耗尽时行动" },
			"10": { label: "10%", description: "均衡的安全余量" },
			"15": { label: "15%", description: "保守" },
			"20": { label: "20%", description: "提前保护" },
			"25": { label: "25%", description: "非常保守" },
		},
	},
	"retry.usageReservePolicy": {
		label: "保留策略",
		description: "当所有同提供商编码套餐账户都进入保留余量时如何处理。",
		options: {
			confirm: {
				label: "交互确认",
				description: "交互会话在确认前继续使用主模型；后台代理自动回退",
			},
			auto: { label: "自动回退", description: "始终选择下一个符合条件的已配置回退" },
			"fail-closed": { label: "失败关闭", description: "不消耗保留配额，也不选择回退" },
		},
	},
	"retry.fallbackChains": {
		label: "重试回退链",
		description:
			'JSON 对象，将模型角色、模型选择器（"provider/model-id"）或提供商通配符（"provider/*"）映射到有序回退选择器，例如 {"default":["openai/gpt-4o-mini"],"google-antigravity/*":["google/*","google-vertex/*"]}。面向模型的键在该模型/提供商活跃时适用，与角色无关；"provider/*" 条目保留失败模型的 id 并替换提供商。带 id 前缀的通配符（"openrouter/google/*"）会为失败模型的裸 id 重新加前缀（google-antigravity/gemini-x -> openrouter/google/gemini-x），作为键时仅匹配该前缀下该提供商的 id。回退条目可带显式思考后缀（"provider/model:low"、":high"、":max"、":off"）；裸条目继承失败轮次的 effort，"provider/*" 条目始终继承。',
	},
	"retry.fallbackRevertPolicy": {
		label: "回退恢复策略",
		description: "回退后何时返回主模型",
		options: {
			"cooldown-expiry": { label: "冷却到期", description: "在主模型的抑制窗口结束后返回" },
			never: { label: "从不", description: "保持使用回退模型，直到手动更改" },
		},
	},
	"providers.anthropic.serverSideFallback": {
		label: "Anthropic 服务端回退（Fable 5）",
		description:
			"当 Claude Fable 5 / Mythos 5 请求被 Anthropic 安全分类器阻止时，在服务端改用 Claude Opus 5 重试（Anthropic `server-side-fallback-2026-06-01` beta）。需主动开启——关闭时对所有请求保留启用回退前的行为。",
	},
	"providers.autoThinkingMaxEffort": {
		label: "自动思考上限",
		description:
			"`auto` 分类器可解析的最高 effort。`xhigh` 使分类器保持比最高档低一级，因此只有显式 `ultrathink` 才会到达 `max`；`max` 允许分类器判定为特殊的轮次在支持该档的模型上按最高档计费。",
		options: {
			xhigh: { label: "xhigh", description: "分类器最高到 xhigh（默认）" },
			max: { label: "max", description: "分类器可在模型支持时解析到 max" },
		},
	},
	"advisor.enabled": {
		label: "启用顾问",
		description: "配对第二个模型（分配给 'advisor' 角色），被动审查每一轮并注入笔记。",
	},
	"advisor.syncBacklog": {
		label: "顾问同步积压",
		description:
			"暂停主代理，直到顾问积压低于阈值。数字值将等待上限设为 30 秒；strict 会等待所有已安排的审查，不设墙钟上限。off 禁用追赶延迟。中止、失败和释放都会解除等待。",
	},
	"advisor.immuneTurns": {
		label: "顾问免疫轮次",
		description:
			"在顾问的关切或阻塞中断后，接下来这么多主代理轮次中，将后续关切作为非中断旁注发送。阻塞项不受冷却限制。",
		options: {
			"0": { label: "0 步", description: "无冷却。" },
			"1": { label: "1 步" },
			"2": { label: "2 步" },
			"3": { label: "3 步", description: "默认。" },
			"4": { label: "4 步" },
			"5": { label: "5 步" },
		},
	},
	"advisor.continueSeverity": {
		label: "顾问继续运行严重度",
		description:
			"在代理给出最终回答结束后，可唤醒代理继续运行的顾问笔记最低严重度。较低严重度的笔记会作为卡片留在记录末尾，并随你的下一条消息送达代理。",
		options: {
			nit: { label: "细微（Nit）", description: "每条笔记都会使运行继续。" },
			concern: { label: "关切（Concern）", description: "关切和阻塞项会使运行继续。默认。" },
			blocker: { label: "阻塞（Blocker）", description: "仅阻塞项会使运行继续。" },
		},
	},
	"advisor.reviewMode": {
		label: "顾问审查模式",
		description: "没有 WATCHDOG.yml 名册时的默认顾问节奏。turn 审查每个主代理轮次；agent-end 仅审查最终产出。",
		options: {
			turn: { label: "每轮", description: "审查每次主代理更新（工具调用回合）。" },
			"agent-end": { label: "代理结束", description: "仅在最终产出时审查（每次运行一次）。" },
		},
	},
	"advisor.reviewInterval": {
		label: "顾问审查间隔",
		description:
			"没有 WATCHDOG.yml 名册时的默认顾问节奏：每第 N 次符合条件的主代理更新审查一次。1 = 每次更新。跳过的更新会随下一次计划审查一起发送。",
		options: {
			"1": { label: "每次符合条件的更新", description: "默认。" },
			"2": { label: "每第 2 次" },
			"3": { label: "每第 3 次" },
			"5": { label: "每第 5 次" },
			"10": { label: "每第 10 次" },
		},
	},
	"advisor.maxNotesPerUpdate": {
		label: "每次更新的顾问笔记上限",
		description: "每次顾问提示更新可接受的非阻塞建议笔记上限（1–32；UI 提供 1–5 个快捷选项）。阻塞项不受限制。",
		options: {
			"1": { label: "1 条笔记", description: "防刷屏（严格）。" },
			"2": { label: "2 条笔记" },
			"3": { label: "3 条笔记" },
			"4": { label: "4 条笔记", description: "前沿推理模型。默认。" },
			"5": { label: "5 条笔记" },
		},
	},
	"advisor.evictStaleResults": {
		label: "顾问清除过期结果",
		description: "每次审查前，将顾问在较早审查中的 read/grep/glob 输出替换为简短占位符。最新审查结果保留。",
	},
	modelRoleStorage: {
		label: "模型角色存储",
		description: "模型选择器角色分配的保存位置",
		options: {
			global: { label: "全局", description: "将角色模型保存在当前配置档（当前行为）" },
			project: {
				label: "按项目",
				description: "将项目角色模型保存在 .reverse/config.yml；缺失的项目角色使用全局默认值",
			},
		},
	},
	"images.urls.enabled": {
		label: "将图片作为 URL 提供",
		description:
			"通过配置的后端链发布外发图片，并向支持 URL 获取的提供商发送短 URL，而不是内联 base64。当所有后端或提供商获取失败时自动回退到内联。",
	},
	"images.urls.backends": {
		label: "图片 URL 后端",
		description: "为提供商访问发布图片时按顺序尝试的目标",
		options: {
			imgur: { label: "Imgur", description: "上传需要 Imgur 访问令牌或客户端 ID。" },
			imageshack: { label: "ImageShack", description: "该 API 需要付费订阅。" },
			flickr: { label: "Flickr", description: "图床" },
			chevereto: { label: "Chevereto", description: "自托管" },
			vgyme: { label: "vgy.me", description: "图床" },
			dropbox: { label: "Dropbox", description: "云文件存储" },
			ftp: { label: "FTP / FTPS / SFTP", description: "文件传输" },
			onedrive: { label: "OneDrive", description: "云文件存储" },
			"google-drive": { label: "Google Drive", description: "云文件存储" },
			puush: { label: "puush 兼容端点", description: "公共服务已停止；需要替代端点。" },
			box: { label: "Box", description: "云文件存储" },
			"amazon-s3": { label: "Amazon S3", description: "S3 对象存储" },
			"google-cloud-storage": { label: "Google Cloud Storage", description: "对象存储" },
			"azure-storage": { label: "Azure Blob Storage", description: "对象存储" },
			"backblaze-b2": {
				label: "Backblaze B2",
				description: "可配置原生 B2 应用密钥或 S3 兼容访问密钥。",
			},
			owncloud: { label: "ownCloud / Nextcloud", description: "WebDAV" },
			mediafire: { label: "MediaFire 兼容端点", description: "公共 API 已弃用；需要替代端点。" },
			sendspace: { label: "SendSpace 兼容端点", description: "公共发现 API 已弃用；需要替代端点。" },
			localhostr: { label: "Hostr 兼容端点", description: "公共服务已离线；需要替代端点。" },
			lambda: { label: "Lambda 兼容端点", description: "公共服务已离线；需要替代端点。" },
			pomf: { label: "Pomf", description: "Pomf 兼容图床" },
			uguu: { label: "Uguu", description: "公开上传约三小时后过期。" },
			seafile: { label: "Seafile", description: "云文件存储" },
			"s-ul": { label: "s-ul", description: "文件托管" },
			lobfile: { label: "LobFile 兼容端点", description: "公共服务已离线；需要替代端点。" },
			"transfer-sh": {
				label: "transfer.sh 兼容端点",
				description: "已停止的公共端点被屏蔽；需要自托管替代服务。",
			},
			plik: { label: "Plik", description: "自托管" },
			"shared-folder": { label: "共享文件夹", description: "文件系统" },
			catbox: { label: "Catbox", description: "匿名托管" },
			litterbox: { label: "Litterbox", description: "上传内容为临时文件。" },
			"0x0": { label: "0x0.st", description: "公开上传会在按文件大小确定的保留期后过期。" },
			tmpfiles: { label: "tmpfiles.org", description: "公开上传为临时文件。" },
			discord: { label: "Discord", description: "即时消息" },
			"provider-files": {
				label: "模型提供商文件",
				description: "提供商文件引用是 API 本地引用，而非公开图片 URL。",
			},
			direct: { label: "直接公开 URL", description: "本地提供服务" },
			cloudflared: { label: "Cloudflare 快速隧道", description: "隧道" },
			ngrok: { label: "ngrok", description: "隧道" },
			tailscale: { label: "Tailscale Funnel", description: "隧道" },
			ssh: { label: "SSH 反向隧道", description: "隧道" },
			command: { label: "上传命令", description: "外部命令" },
			"localhost-run": { label: "localhost.run", description: "隧道" },
			pinggy: { label: "Pinggy", description: "隧道" },
			devtunnel: { label: "Microsoft dev tunnel", description: "devtunnel CLI 需在本地登录。" },
			zrok: { label: "zrok", description: "需启用本地 zrok 环境。" },
			bore: { label: "bore", description: "隧道" },
			"named-cloudflared": { label: "命名 Cloudflare Tunnel", description: "隧道" },
			r2: { label: "Cloudflare R2", description: "S3 对象存储" },
			tigris: { label: "Tigris", description: "S3 对象存储" },
			minio: { label: "MinIO", description: "S3 对象存储" },
			garage: { label: "Garage", description: "S3 对象存储" },
		},
	},
	"images.urls.command": {
		label: "图片上传命令",
		description:
			"command 后端的 argv 模板；{file} 是图片路径，{mime}/{ext} 可选。使用 stdout 上打印的最后一个 URL（例如 pasta -b -f {file}）",
	},
	"images.urls.publicBaseUrl": {
		label: "图片 URL 公共基址",
		description: "位于 blob 服务器前、可从外部访问的基址（ssh 必填，direct 可选）",
	},
	"images.urls.ttlHours": {
		label: "图片 URL 有效期（小时）",
		description:
			"本地托管图片 URL 的服务窗口，从会话最后一次发送它们时算起；恢复会话会以同一链接重新计时。0 表示 broker 运行期间链接始终有效",
	},
	"images.urls.bindHost": {
		label: "图片 URL 绑定主机",
		description: "blob 服务器绑定的主机；隧道使用回环地址，直接提供服务使用 0.0.0.0",
	},
	"images.urls.sshTarget": {
		label: "图片 URL SSH 目标",
		description: "SSH 反向转发的 user@host 目标",
	},
	"images.urls.sshRemotePort": {
		label: "图片 URL SSH 远程端口",
		description: "SSH 反向转发的远程监听端口，供你的 Web 服务器代理",
	},
};
