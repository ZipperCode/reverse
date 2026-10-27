import type { SettingTranslation } from "../../types";

export const contextSettingsZhCN: Record<string, SettingTranslation> = {
	"workspace.additionalDirectories": {
		label: "额外工作区目录",
		description:
			"作为额外根目录加入每个会话的附加工作区目录（多根工作区）。可通过 /add-dir 和 /remove-dir 实时管理。路径相对 cwd 解析；建议使用绝对路径。代理会被告知这些根目录存在，并可读取/grep/glob 它们。",
	},
	"contextFiles.extra": {
		label: "额外上下文文件",
		description:
			'与 AGENTS.md 一同加载的额外指令文件名。使用名称 JSON 列表而非路径，例如 ["AGENTS.local.md"]；[] 禁用额外文件。需开始新会话才能加载。',
	},
	"contextPromotion.enabled": {
		label: "自动提升上下文",
		description: "上下文溢出时提升到模型的 contextPromotionTarget，而不是压缩。重试回退切换由“重试模型回退”控制",
	},
	extendedContext: {
		label: "扩展上下文",
		description: "在支持时使用更大的上下文窗口；可能产生溢价。关闭时保持默认或标准价格窗口",
	},
	"compaction.enabled": {
		label: "自动压缩",
		description: "上下文过大时自动压缩",
	},
	"compaction.experimentalContextManagement": {
		label: "笔记支持的上下文窗口（实验性）",
		description: "跨上下文窗口保留持久笔记和可搜索的原始历史。",
	},
	"compaction.midTurnEnabled": {
		label: "轮次中压缩",
		description:
			"在下一个提供商请求之前，于安全的轮次中工具循环边界检查阈值；子代理始终检查，因为它们的整个任务就是一轮",
	},
	"compaction.methodOrder": {
		label: "压缩方法顺序",
		description: "自动上下文维护的首选回退顺序；不可用或失败的方法会推进到下一个选择",
		options: {
			remote: {
				label: "服务端压缩",
				description:
					"当前路由支持时，使用提供商原生服务端压缩（OpenAI Responses compact、Anthropic compaction beta）",
			},
			snapcompact: {
				label: "Snapcompact",
				description: "将历史归档为当前视觉模型可读取的稠密位图图像；不调用 LLM",
			},
			handoff: { label: "交接", description: "生成交接文档，并以其作为压缩摘要继续" },
			soft: { label: "软压缩", description: "使用压缩模型就地摘要，而不使用服务端压缩" },
			shake: { label: "抖动", description: "就地丢弃可恢复的重型内容，不调用 LLM" },
		},
	},
	"compaction.thresholdPercent": {
		label: "压缩阈值",
		description: "上下文维护的百分比阈值；设为“默认”以使用旧的基于余量的行为",
		options: {
			default: { label: "默认", description: "旧版基于余量的阈值" },
			"10": { label: "10%", description: "极早维护" },
			"20": { label: "20%", description: "很早维护" },
			"30": { label: "30%", description: "较早维护" },
			"40": { label: "40%", description: "偏早维护" },
			"50": { label: "50%", description: "中点" },
			"60": { label: "60%", description: "中等上下文用量" },
			"70": { label: "70%", description: "均衡" },
			"75": { label: "75%", description: "略激进" },
			"80": { label: "80%", description: "典型阈值" },
			"85": { label: "85%", description: "激进上下文用量" },
			"90": { label: "90%", description: "非常激进" },
			"95": { label: "95%", description: "接近上下文限制" },
		},
	},
	"compaction.thresholdTokens": {
		label: "压缩 token 上限",
		description: "上下文维护的固定 token 上限；设置后覆盖百分比",
		options: {
			default: { label: "默认", description: "使用基于百分比的阈值" },
			"25000": { label: "25K token", description: "200K 窗口的 1/8" },
			"50000": { label: "50K token", description: "200K 窗口的 1/4" },
			"100000": { label: "100K token", description: "200K 窗口的 1/2" },
			"150000": { label: "150K token", description: "200K 窗口的 3/4" },
			"200000": { label: "200K token", description: "完整标准上下文窗口" },
			"300000": { label: "300K token", description: "大上下文窗口" },
			"500000": { label: "500K token", description: "超大上下文窗口" },
		},
	},
	"compaction.handoffSaveToDisk": {
		label: "保存交接文档",
		description: "将生成的交接文档保存为 markdown 文件，供自动交接流程使用",
	},
	"compaction.remoteStreamingV2Enabled": {
		label: "远程压缩 V2",
		description: "对兼容的远程压缩模型使用 Responses 流式压缩",
	},
	"compaction.asyncEnabled": {
		label: "异步压缩",
		description: "当上下文接近压缩阈值时，在后台推测性摘要，越过阈值后拼接就绪结果",
	},
	"compaction.idleEnabled": {
		label: "空闲压缩",
		description: "空闲时若 token 数超过阈值则压缩上下文",
	},
	"compaction.idleThresholdTokens": {
		label: "空闲压缩阈值",
		description: "空闲压缩触发的 token 数下限",
		options: {
			"100000": { label: "100K token" },
			"200000": { label: "200K token" },
			"300000": { label: "300K token" },
			"400000": { label: "400K token" },
			"500000": { label: "500K token" },
			"600000": { label: "600K token" },
			"700000": { label: "700K token" },
			"800000": { label: "800K token" },
			"900000": { label: "900K token" },
		},
	},
	"compaction.idleTimeoutSeconds": {
		label: "空闲压缩延迟",
		description: "空闲后等待多少秒再压缩；对于 1 小时提示缓存，则改为在缓存即将过期前执行压缩",
		options: {
			"60": { label: "1 分钟" },
			"120": { label: "2 分钟" },
			"300": { label: "5 分钟" },
			"600": { label: "10 分钟" },
			"1800": { label: "30 分钟" },
			"3600": { label: "1 小时" },
		},
	},
	"compaction.supersedeReads": {
		label: "取代过期读取",
		description: "同一文件再次读取时清理较旧的读取结果（缓存感知，每轮运行）",
	},
	"compaction.dropUseless": {
		label: "省略无事件结果",
		description: "一旦消费，就清理被标记为上下文无用（无匹配、等待超时）的工具结果（缓存感知）",
	},
	"snapcompact.systemPrompt": {
		label: "Snapcompact 系统提示",
		description:
			"实验性：将选定的系统提示文本渲染为稠密 PNG 图像，并附加到第一条用户消息（仅视觉模型）。节省 token；但会使图像化文本失去提示缓存。",
		options: {
			none: { label: "无", description: "系统提示保持文本。" },
			"agents-md": { label: "AGENTS.md", description: "仅在节省 token 时，将已加载的上下文文件指令转为图像。" },
			all: { label: "全部", description: "仅在节省 token 时，将完整系统提示转为图像。" },
		},
	},
	"snapcompact.toolResults": {
		label: "Snapcompact 工具结果",
		description:
			"实验性：将大型工具结果（包括最新一条）渲染为稠密 PNG 图像而非文本（仅视觉模型）。可为累积的搜索和命令输出节省 token；读取结果保持文本，除非已知模型能精确根据图像编辑。",
	},
	"tools.format": {
		label: "工具调用模式",
		description:
			"控制向模型暴露工具的方式。Auto 使用提供商原生工具调用，除非所选模型被标记为不支持，此时回退到 GLM 自有方言。Native 强制使用提供商原生工具；其他值强制使用指定的自有方言。",
		options: {
			auto: { label: "自动", description: "使用原生工具调用，除非已知模型不支持。" },
			native: { label: "原生", description: "使用提供商原生工具调用。" },
			glm: { label: "GLM", description: "使用 GLM 风格带内工具调用。" },
			hermes: { label: "Hermes", description: "使用 Hermes 风格带内工具调用。" },
			kimi: { label: "Kimi", description: "使用 Kimi 风格带内工具调用。" },
			xml: { label: "XML", description: "使用通用 XML 带内工具调用。" },
			anthropic: { label: "Anthropic", description: "使用 Anthropic 风格带内工具调用。" },
			deepseek: { label: "DeepSeek", description: "使用 DeepSeek 风格带内工具调用。" },
			harmony: { label: "Harmony", description: "使用 Harmony 风格带内工具调用。" },
			qwen3: { label: "Qwen3", description: "使用 Qwen3 自有方言。" },
			gemini: { label: "Gemini", description: "使用 Gemini 自有方言。" },
			gemma: { label: "Gemma", description: "使用 Gemma 自有方言。" },
			minimax: { label: "MiniMax", description: "使用 MiniMax 自有方言。" },
		},
	},
	"snapcompact.shape": {
		label: "Snapcompact 形状",
		description: "snapcompact 打印文本时的帧形状（压缩归档和内联成像）。Auto 会选择针对当前模型调优的形状。",
		options: {
			auto: { label: "自动", description: "选择针对当前模型调优的形状，回退到其提供商系列。" },
			"8x8r-bw": {
				label: "8x8 重复，黑色",
				description: "unscii 方形单元，黑色墨水，每行打印两次，副本位于浅色高亮带上。",
			},
			"8x8r-sent": { label: "8x8 重复，句子色相", description: "重复网格，墨水在句子边界处循环六种色相。" },
			"8x8u-bw": { label: "8x8，黑色", description: "普通 unscii 方形单元，单次打印行，黑色墨水。" },
			"8x8u-sent": { label: "8x8，句子色相", description: "普通 unscii 方形单元，句子色相墨水。" },
			"6x6u-bw": { label: "6x6 稠密，黑色", description: "unscii 压缩到 6x6——最稠密可读单元、帧数最少——黑色墨水。" },
			"6x6u-sent": { label: "6x6 稠密，句子色相", description: "最稠密单元，句子色相墨水。" },
			"5x8-bw": { label: "5x8 旧版，黑色", description: "2576px 帧上的原始 X.org 5x8 字形，黑色墨水。" },
			"5x8-sent": {
				label: "5x8 旧版，句子色相",
				description: "原始 snapcompact 形状（形状表之前的会话使用此形状）。",
			},
			"6x12-dim": { label: "6x12，弱化停用词", description: "X.org 6x12 字形，黑色墨水，功能词弱化为灰色。" },
			"8x13-bw": { label: "8x13，黑色", description: "X.org 8x13 字形，黑色墨水。" },
			"8on16-bw": { label: "8x13，16px 行距，黑色", description: "8x16 单元上的 8x13 字形（额外行距），黑色墨水。" },
			"8on22-bw": {
				label: "8x13，22px 行距（前导），黑色",
				description: "8x22 单元上的 8x13 字形——额外行距，避免行拥挤。OpenAI/Google 的默认值。",
			},
			"11on16-bw": {
				label: "8x13，11px 字距（跟踪），黑色",
				description: "11x16 单元上的 8x13 字形——额外字距，避免字符粘连。Anthropic 的默认值。",
			},
			"silver16-bw": {
				label: "Silver 16，CJK",
				description: "16px 网格上的内嵌 Silver TrueType 字体，用于 CJK 和其他非拉丁文本。",
			},
			"doc-8on16-bw": {
				label: "Doc 8on16，黑色",
				description: "两栏自动换行的报纸式布局，8x13 字形按 16px 行距排列，黑色墨水。",
			},
			"doc-8on16-sent": { label: "Doc 8on16，句子色相", description: "两栏文档布局，句子色相墨水。" },
			"doc-8on16-sent-dim": {
				label: "Doc 8on16，句子色相 + 弱化停用词",
				description: "两栏文档布局，句子色相墨水，功能词弱化为灰色。",
			},
		},
	},
	"branchSummary.enabled": {
		label: "分支摘要",
		description: "离开分支时提示生成摘要",
	},
	"ttsr.enabled": {
		label: "TTSR",
		description: "当输出匹配规则模式时在流中途中断代理（时间旅行流规则）",
	},
	"ttsr.judge": {
		label: "评判规则",
		description:
			"让评判模型角色检查每个 `question` 规则对应的已完成回复、推理和工具调用；回答“是”会将规则作为警告注入",
		options: {
			auto: { label: "自动", description: "仅当评判角色解析为原生 TypeSafe jev 模型时评判" },
			on: { label: "开启", description: "无论评判角色解析为哪个模型都始终评判" },
			off: { label: "关闭", description: "从不评判；question 规则保持不活跃" },
		},
	},
	"ttsr.contextMode": {
		label: "TTSR 上下文模式",
		description: "TTSR 触发时如何处理部分输出",
	},
	"ttsr.interruptMode": {
		label: "TTSR 中断模式",
		description: "何时在流中途中断，何时在完成后注入警告",
		options: {
			always: { label: "always", description: "在散文和工具流上中断" },
			"prose-only": { label: "prose-only", description: "仅在回复/思考匹配时中断" },
			"tool-only": { label: "tool-only", description: "仅在工具调用参数匹配时中断" },
			never: { label: "never", description: "从不中断；完成后注入警告" },
		},
	},
	"ttsr.repeatMode": {
		label: "TTSR 重复模式",
		description: "规则如何重复：每会话一次，或在消息间隔后重复",
	},
	"ttsr.repeatGap": {
		label: "TTSR 重复间隔",
		description: "规则再次触发前的消息数",
		options: {
			"5": { label: "5 条消息" },
			"10": { label: "10 条消息" },
			"15": { label: "15 条消息" },
			"20": { label: "20 条消息" },
			"30": { label: "30 条消息" },
		},
	},
	"ttsr.builtinRules": {
		label: "内置规则",
		description: "加载代理附带的默认规则（可用 ttsr.disabledRules 单独覆盖）",
	},
	"ttsr.disabledRules": {
		label: "禁用规则",
		description: "要完全忽略的规则名称（适用于捆绑默认规则和你自己的规则）",
	},
};
