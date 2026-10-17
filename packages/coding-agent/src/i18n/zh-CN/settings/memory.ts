import type { SettingTranslation } from "../../types";

export const memorySettingsZhCN: Record<string, SettingTranslation> = {
	"autolearn.enabled": {
		label: "自动学习（实验性）",
		description: "代理停止后，提示它将经验教训写入记忆，并创建/增强隔离的托管技能",
	},
	"autolearn.autoContinue": {
		label: "停止时自动运行捕获",
		description: "开启时，在停止时自动运行一次私有捕获轮次（消耗额外 token）。关闭时，仅保留常驻的自动学习指导。",
	},
	"memory.backend": {
		label: "记忆后端",
		description: "关闭、本地摘要管道、Mnemopi SQLite、Hindsight 远程记忆或 Sharpshooter",
		options: {
			off: { label: "关闭", description: "不运行记忆子系统" },
			local: { label: "本地", description: "本地 rollout 摘要管道（memory_summary.md）" },
			hindsight: { label: "Hindsight", description: "Vectorize Hindsight 远程记忆服务" },
			mnemopi: { label: "Mnemopi", description: "本地 SQLite 召回/保留后端，可选嵌入" },
			sharpshooter: {
				label: "Sharpshooter",
				description: "按摩擦触发的项目决策文件（架构/产品/风格），在后台整合",
			},
		},
	},
	"sharpshooter.model": {
		label: "Sharpshooter 模型",
		description: "用于提取/整合的模型选择器，留空表示 smol 角色",
	},
	"mnemopi.dbPath": {
		label: "Mnemopi 数据库路径",
		description: "可选的 SQLite 数据库路径。默认使用代理记忆目录。",
	},
	"mnemopi.bank": {
		label: "Mnemopi 记忆库",
		description: "可选的共享记忆库基础名称。按项目模式会据此派生项目本地记忆库。",
	},
	"mnemopi.scoping": {
		label: "Mnemopi 作用域",
		description:
			"global = 单个共享记忆库；per-project = 每个 cwd 独立记忆库；per-project-tagged = 项目本地写入，同时召回可见全局记忆",
		options: {
			global: { label: "全局", description: "所有项目共用一个 Mnemopi 记忆库" },
			"per-project": { label: "按项目", description: "按 cwd 基名为每个项目建立本地 Mnemopi 记忆库" },
			"per-project-tagged": {
				label: "按项目（带标签）",
				description: "写入项目本地记忆库，但合并项目与共享召回结果",
			},
		},
	},
	"mnemopi.embeddingVariant": {
		label: "嵌入变体",
		description:
			"本地嵌入模型系列。en = 更强的英语模型；multilingual = 跨语言模型。更改后会在下次启动时重建现有记忆嵌入。",
		options: {
			en: { label: "英语（bge-base-en-v1.5）", description: "BAAI/bge-base-en-v1.5（768 维），仅英语" },
			multilingual: {
				label: "多语言（multilingual-e5-large）",
				description: "intfloat/multilingual-e5-large（1024 维），跨语言召回",
			},
		},
	},
	"mnemopi.autoRecall": {
		label: "Mnemopi 自动召回",
		description: "在每个会话的第一轮召回本地记忆",
	},
	"mnemopi.autoRetain": {
		label: "Mnemopi 自动保留",
		description: "将已完成的对话轮次保留到本地 Mnemopi 记忆",
	},
	"mnemopi.polyphonicRecall": {
		label: "Mnemopi 多声部召回",
		description: "融合图、事实、向量和时间声部进行召回，使关联记忆无需关键词匹配也能浮现",
	},
	"mnemopi.enhancedRecall": {
		label: "Mnemopi 增强召回",
		description: "以相同选项缓存重复和相似查询的召回结果；任何记忆写入都会清除缓存",
	},
	"mnemopi.proactiveLinking": {
		label: "Mnemopi 主动关联",
		description: "新记忆存储时将其纳入情景图，并链接到相关实体和记忆",
	},
	"mnemopi.noEmbeddings": {
		label: "Mnemopi 禁用嵌入",
		description: "强制使用确定性的仅 FTS 召回，而不使用向量嵌入",
	},
	"mnemopi.embeddingModel": {
		label: "Mnemopi 嵌入模型",
		description: "高级：显式嵌入模型 ID，会覆盖变体。留空以使用 mnemopi.embeddingVariant。",
	},
	"mnemopi.embeddingApiUrl": {
		label: "Mnemopi 嵌入 API URL",
		description: "可选的 OpenAI 兼容嵌入端点，传递给 Mnemopi",
	},
	"mnemopi.embeddingApiKey": {
		label: "Mnemopi 嵌入 API 密钥",
		description: "可选的嵌入 API 密钥，传递给 Mnemopi",
	},
	"mnemopi.llmMode": {
		label: "Mnemopi LLM 模式",
		description: "不使用 LLM、使用在线微型模型（/models 中的 TINY 角色，否则 @smol），或远程 OpenAI 兼容端点",
		options: {
			none: { label: "无", description: "禁用 Mnemopi 的 LLM 提取" },
			smol: { label: "在线（微型）", description: "使用在线微型模型（/models 中的 TINY 角色，否则 @smol）" },
			remote: { label: "远程", description: "使用下方的 Mnemopi 远程 LLM 设置" },
		},
	},
	"mnemopi.llmBaseUrl": {
		label: "Mnemopi LLM 基础 URL",
		description: "Mnemopi 远程模式可选使用的 OpenAI 兼容 LLM 端点",
	},
	"mnemopi.llmApiKey": {
		label: "Mnemopi LLM API 密钥",
		description: "Mnemopi 远程模式可选的 LLM API 密钥",
	},
	"mnemopi.llmModel": {
		label: "Mnemopi LLM 模型",
		description: "Mnemopi 远程模式可选的 LLM 模型名称",
	},
	"hindsight.apiUrl": {
		label: "Hindsight API URL",
		description: "Hindsight 服务器 URL（云端或自托管）",
	},
	"hindsight.apiToken": {
		label: "Hindsight API 令牌",
		description: "用于需要认证的 Hindsight 服务器的 Bearer 令牌",
	},
	"hindsight.bankId": {
		label: "Hindsight 记忆库 ID",
		description: "记忆库标识符（默认：项目名称）",
	},
	"hindsight.scoping": {
		label: "Hindsight 作用域",
		description:
			"global = 单个共享记忆库；per-project = 每个 cwd 独立记忆库；per-project-tagged = 共享记忆库加项目标签，使全局和项目记忆在召回时合并",
		options: {
			global: { label: "全局", description: "单个共享记忆库——每个项目看到相同记忆" },
			"per-project": {
				label: "按项目",
				description: "按 cwd 基名隔离记忆库——项目之间看不到彼此的记忆",
			},
			"per-project-tagged": {
				label: "按项目（带标签）",
				description: "共享记忆库，保留内容带 project:<cwd> 标签。召回时同时显示项目和未标记的全局记忆",
			},
		},
	},
	"hindsight.autoRecall": {
		label: "Hindsight 自动召回",
		description: "在每个会话的第一轮召回记忆",
	},
	"hindsight.autoRetain": {
		label: "Hindsight 自动保留",
		description: "每 N 轮以及会话边界处保留记录",
	},
	"hindsight.retainMode": {
		label: "Hindsight 保留模式",
		description: "full-session = 每个会话 upsert 一个文档，last-turn = 分块",
		options: {
			"full-session": { label: "完整会话", description: "每个会话 upsert 一个文档（推荐）" },
			"last-turn": { label: "最后一轮", description: "按轮次边界切分的分块保留" },
		},
	},
	"hindsight.mentalModelsEnabled": {
		label: "Hindsight 心智模型",
		description:
			"启动时将精选的反思摘要（心智模型）读入开发者指令。加载记忆库中已有的模型——不写入。搭配 hindsight.mentalModelAutoSeed 还可自动创建内置种子集。",
	},
	"hindsight.mentalModelAutoSeed": {
		label: "Hindsight 心智模型自动播种",
		description:
			"会话开始时，创建记忆库中尚不存在的内置心智模型（project-conventions、project-decisions、user-preferences）。",
	},
};
