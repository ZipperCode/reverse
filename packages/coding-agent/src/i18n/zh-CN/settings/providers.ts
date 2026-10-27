import type { SettingTranslation } from "../../types";

export const providersSettingsZhCN: Record<string, SettingTranslation> = {
	"providers.maxInFlightRequests": {
		label: "最大并发请求数",
		description:
			'每个提供商 ID（例如 "openai" 或 "anthropic"）的最大并发 LLM 请求数，在同一配置根下的本地 REVERSE 进程间共享。省略的提供商表示不限制。',
	},
	"providers.ollama-cloud.maxConcurrency": {
		label: "Ollama Cloud 最大并发",
		description: "每个进程的最大并发 Ollama Cloud 子代理运行数；0 禁用该提供商特定限制",
	},
	"providers.webSearchTimeoutSeconds": {
		label: "网络搜索超时",
		description: "每个提供商搜索传输的硬超时（秒），超时后 web_search 推进到下一个回退（最大 300）",
		options: {
			"30": { label: "30 秒" },
			"60": { label: "1 分钟" },
			"120": { label: "2 分钟" },
			"180": { label: "3 分钟" },
			"300": { label: "5 分钟" },
		},
	},
	"providers.antigravityEndpoint": {
		label: "Antigravity 端点模式",
		description: "google-antigravity 提供商的端点路由策略（聊天、搜索、图像、发现）",
		options: {
			auto: { label: "自动", description: "尝试生产端点，5xx/429 时故障转移到沙盒" },
			production: { label: "仅生产", description: "仅强制使用生产端点" },
			sandbox: { label: "仅沙盒", description: "仅强制使用沙盒端点" },
		},
	},
	"providers.fireworksTier": {
		label: "Fireworks 层级",
		description:
			'Fireworks 请求的服务路径。Priority 发送 `service_tier: "priority"`，在高峰流量时以更高价格获得更高可靠性；Standard 省略它。Fast（`-fast`）模型忽略此设置——Fast 有自己的服务路径。',
		options: {
			standard: { label: "Standard", description: "默认服务路径（无 service_tier）" },
			priority: { label: "Priority", description: "优先服务路径：更高可靠性，按 token 溢价" },
		},
	},
	"providers.tinyModelDevice": {
		label: "微型模型设备",
		description:
			"本地微型模型（标题 + 记忆）的推理后端：ONNX 执行提供程序，或 `mlx` 以下载 MLX 权重并通过 Apple 芯片上的 mlx-lm 运行。默认使用纯 CPU ONNX。PI_TINY_DEVICE 环境变量会覆盖此设置。",
		options: {
			default: { label: "默认", description: "纯 CPU 推理" },
			gpu: { label: "GPU", description: "加速提供程序（WebGPU/Metal、CUDA 或 DirectML）" },
			cpu: { label: "CPU", description: "纯 CPU 推理" },
			mlx: { label: "MLX", description: "通过 mlx-lm 使用 Apple 芯片 GPU（Python 子进程；macOS arm64）" },
			metal: { label: "Metal", description: "MLX 的别名" },
			webgpu: { label: "WebGPU", description: "WebGPU/Metal 后端" },
			cuda: { label: "CUDA", description: "NVIDIA CUDA（Linux x64）" },
			dml: { label: "DirectML", description: "DirectML 后端（Windows）" },
			coreml: { label: "CoreML", description: "Apple CoreML（需主动启用；可能加载失败）" },
			auto: { label: "自动", description: "让 ONNX Runtime 选择提供程序" },
			wasm: { label: "WASM", description: "WebAssembly 后端" },
			webnn: { label: "WebNN", description: "WebNN 后端" },
			"webnn-gpu": { label: "WebNN GPU", description: "WebNN GPU 设备" },
			"webnn-cpu": { label: "WebNN CPU", description: "WebNN CPU 设备" },
			"webnn-npu": { label: "WebNN NPU", description: "WebNN NPU 设备" },
		},
	},
	"providers.tinyModelDtype": {
		label: "微型模型精度",
		description:
			"本地微型模型的 ONNX 量化/精度。默认使用各模型随附的 dtype（q4）；较低精度更快，较高精度更保真。MLX 后端忽略此设置（其仓库已预量化 4 位）。PI_TINY_DTYPE 环境变量会覆盖此设置。",
		options: {
			default: { label: "默认", description: "各模型随附的 dtype（当前为 q4）" },
			q4: { label: "q4", description: "4 位权重；最小最快" },
			q4f16: { label: "q4f16", description: "4 位权重，fp16 激活" },
			q8: { label: "q8", description: "8 位量化" },
			fp16: { label: "fp16", description: "16 位浮点；更高保真，更大" },
			fp32: { label: "fp32", description: "全精度；最大最慢" },
			int8: { label: "int8", description: "有符号 8 位整数" },
			uint8: { label: "uint8", description: "无符号 8 位整数" },
			bnb4: { label: "bnb4", description: "bitsandbytes 4 位" },
			q2: { label: "q2", description: "2 位权重" },
			q2f16: { label: "q2f16", description: "2 位权重，fp16 激活" },
			q1: { label: "q1", description: "1 位权重" },
			q1f16: { label: "q1f16", description: "1 位权重，fp16 激活" },
			auto: { label: "自动", description: "让 transformers.js 按设备选择" },
		},
	},
	"providers.kimiApiFormat": {
		label: "Kimi API 格式",
		description: "Kimi Code 提供商的 API 格式（auto 跟随实时模型元数据）",
		options: {
			auto: { label: "自动", description: "使用模型服务器声明的协议" },
			openai: { label: "OpenAI", description: "api.kimi.com" },
			anthropic: { label: "Anthropic", description: "api.moonshot.ai" },
		},
	},
	"providers.openaiWebsockets": {
		label: "OpenAI WebSockets",
		description: "OpenAI Codex 模型的 WebSocket 策略（auto 使用模型默认值，on 强制，off 禁用）",
		options: {
			auto: { label: "自动", description: "使用模型/提供商默认 WebSocket 行为" },
			off: { label: "关闭", description: "对 OpenAI Codex 模型禁用 WebSocket" },
			on: { label: "开启", description: "对 OpenAI Codex 模型强制使用 WebSocket" },
		},
	},
	"providers.openaiLiveSteering": {
		label: "OpenAI 实时引导",
		description: "GPT-6 响应流式输出时，将你输入的消息通过 Codex WebSocket 送入该响应，而不是等到下一个工具边界",
	},
	"providers.muse-code.storeResponses": {
		label: "Muse Code 存储响应",
		description:
			"将 Muse Code 结果存储在 Meta 的服务器上，使连接中断的轮次可以恢复而不是重跑。存储的运行会在 Meta 侧保留提示和输出。",
	},
	"providers.cacheRetention": {
		label: "提示缓存保留",
		description: "转发给支持该功能的提供商的提示缓存保留策略（Anthropic、Bedrock、OpenRouter、OpenAI）",
		options: {
			auto: {
				label: "自动",
				description:
					"提供商默认——Anthropic OAuth 订阅会话默认 1 小时，API 密钥使用 5 分钟；PI_CACHE_RETENTION 仍适用",
			},
			short: {
				label: "短（5 分钟）",
				description: "缓存写入成本最低；可搭配缓存预热在空闲时保持短条目存活",
			},
			long: {
				label: "长（1 小时+）",
				description:
					"在受支持处使用更长 TTL（Anthropic/Bedrock 为 1 小时，OpenAI GPT-5.6+ Responses 为 12 小时）；写入更贵，仅在活动运行期间预热",
			},
			none: { label: "关闭", description: "禁用提示缓存和缓存亲和路由" },
		},
	},
	"providers.cacheWarming": {
		label: "缓存预热",
		description: "在提示缓存条目即将过期前，以单 token 输出预算重新发送上一次请求",
		options: {
			off: { label: "关闭", description: "禁用缓存预热" },
			streaming: { label: "流式", description: "在长时间工具执行期间保护昂贵前缀；代理稳定后停止" },
			idle: {
				label: "空闲",
				description: "在运行之间也刷新 5 分钟条目，只要预期节省仍高于成本下限",
			},
		},
	},
	"providers.streamFirstEventTimeoutSeconds": {
		label: "流首事件超时",
		description: "等待模型流第一个事件的秒数；-1 使用提供商/环境默认值，0 禁用看门狗",
		options: {
			"-1": { label: "自动", description: "使用提供商默认值和 PI_* 超时环境变量" },
			"0": { label: "关闭", description: "禁用首事件超时" },
			"300": { label: "5 分钟" },
			"600": { label: "10 分钟" },
			"1800": { label: "30 分钟" },
		},
	},
	"providers.streamIdleTimeoutSeconds": {
		label: "流空闲超时",
		description: "模型流在事件之间可保持静默的秒数；-1 使用提供商/环境默认值，0 禁用看门狗",
		options: {
			"-1": { label: "自动", description: "使用提供商默认值和 PI_* 超时环境变量" },
			"0": { label: "关闭", description: "禁用空闲超时" },
			"300": { label: "5 分钟" },
			"600": { label: "10 分钟" },
			"1800": { label: "30 分钟" },
		},
	},
	"providers.openrouterVariant": {
		label: "OpenRouter 路由",
		description: "追加到 OpenRouter 模型 ID 的默认路由变体后缀（选择器已指定变体时覆盖）",
		options: {
			default: { label: "默认", description: "无后缀；使用 OpenRouter 默认路由" },
			nitro: { label: ":nitro", description: "优先吞吐量/最低延迟" },
			floor: { label: ":floor", description: "优先最便宜的可用提供商" },
			online: { label: ":online", description: "启用 OpenRouter 的网络搜索插件" },
			exacto: { label: ":exacto", description: "精选高质量提供商（仅为部分模型定义）" },
		},
	},
	"providers.fetch": {
		label: "抓取提供商",
		description: "fetch/read URL 工具的读取器后端优先级",
		options: {
			auto: { label: "自动", description: "优先级：native > trafilatura > lynx > parallel > firecrawl > jina" },
			native: { label: "原生", description: "进程内 HTML→Markdown 转换器（始终可用）" },
			trafilatura: { label: "Trafilatura", description: "通过 uv/pip 自动安装" },
			lynx: { label: "Lynx", description: "需要 lynx 系统包" },
			parallel: { label: "Parallel", description: "需要 PARALLEL_API_KEY" },
			firecrawl: { label: "Firecrawl", description: "需要 FIRECRAWL_API_KEY" },
			jina: { label: "Jina", description: "使用 r.jina.ai 读取器（JINA_API_KEY 可选）" },
		},
	},
	"codexResets.autoRedeem": {
		label: "Codex 自动兑换已保存重置",
		description:
			"自动使用已保存的 Codex 速率限制重置：当轮次卡住且没有其他账户可接管时，恢复因 5 小时或每周窗口耗尽而被阻塞的账户，并挽救即将过期的额度。unset 在首次使用前询问（无提示 UI 时，仅使用 5 分钟内到期的重置），yes 不询问直接使用，no 禁用两项检查。",
		options: {
			unset: {
				label: "未设置",
				description: "检查资格，然后在首次使用已保存重置前询问。无提示 UI 时，仅使用 5 分钟内到期的重置。",
			},
			yes: { label: "是", description: "不询问直接使用符合条件的已保存重置。" },
			no: { label: "否", description: "不运行已保存重置的自动兑换检查。" },
		},
	},
	"codexResets.minBlockedMinutes": {
		label: "Codex 自动兑换最小阻塞",
		description:
			"仅当自然解除阻塞——耗尽的 5 小时/每周窗口中最晚的重置——至少还有这么多分钟时才自动兑换（不要为节省短暂等待而消耗稀缺额度）。调高（例如 360）可忽略仅 5 小时的阻塞。",
	},
	"codexResets.keepCredits": {
		label: "Codex 自动兑换保留",
		description:
			"绝不在低于这么多已保存重置时自动使用（0 = 最后一个额度也可自动使用）。即将过期的额度不受限制——保留的额度过期后不会保留任何价值。",
	},
	"codexResets.salvageHorizonHours": {
		label: "Codex 重置挽救窗口",
		description:
			"启用自动兑换后，当任一聊天窗口有可观用量时，在已保存 Codex 重置到期前这么多小时内使用它。0 禁用提前挽救；5 分钟内到期的额度仍会尝试，无论用量如何。",
	},
	"claudeResets.autoRedeem": {
		label: "Claude 自动兑换重置",
		description:
			"自动使用符合条件的 Claude Cedar 或 Juniper 重置。Cedar 仅用于覆盖的限制；Juniper 只能恢复单一的 5 小时阻塞。unset 在首次使用前询问（无提示 UI 时，仅使用 5 分钟内到期的重置），yes 不询问直接使用，no 禁用阻塞恢复和到期挽救。",
		options: {
			unset: {
				label: "未设置",
				description: "检查实时资格，然后在首次使用 Claude 重置前询问。无提示 UI 时，仅使用 5 分钟内到期的重置。",
			},
			yes: { label: "是", description: "不询问直接使用符合条件的 Claude 重置。" },
			no: { label: "否", description: "不运行 Claude 重置自动兑换检查。" },
		},
	},
	"claudeResets.minBlockedMinutes": {
		label: "Claude 自动兑换最小阻塞",
		description:
			"仅当自然解除阻塞——耗尽的覆盖窗口中最晚的重置——至少还有这么多分钟时才自动兑换。仅 5 小时的重置绝不用于每周或模型范围的阻塞。",
	},
	"claudeResets.keepCredits": {
		label: "Claude 自动兑换保留",
		description:
			"至少保留这么多 Claude 重置（0 允许最后一个符合条件的重置自动使用）。保留量适用于提前挽救，但不适用于 5 分钟内到期的符合条件的重置。",
	},
	"claudeResets.salvageHorizonHours": {
		label: "Claude 重置挽救窗口",
		description:
			"启用自动兑换后，当其覆盖窗口有可观用量时，在到期前这么多小时内使用服务器选定的 Cedar 重置。0 禁用提前挽救；5 分钟内到期的符合条件的 Cedar 或 Juniper 重置仍会尝试，无论用量或保留量如何。提供商限制要求仍然适用。",
	},
	"provider.appendOnlyContext": {
		label: "仅追加上下文",
		description:
			"缓存系统提示 + 工具规范，并保持仅追加的消息日志，使提供商前缀缓存（DeepSeek、Xiaomi/SGLang、Anthropic）以最高命中率工作。Auto 对已知前缀缓存提供商启用。",
		options: {
			auto: { label: "自动", description: "对已知前缀缓存提供商启用（推荐）" },
			on: { label: "开启", description: "始终启用仅追加上下文" },
			off: { label: "关闭", description: "禁用仅追加上下文" },
		},
	},
	"exa.enabled": {
		label: "Exa",
		description: "启用 Exa 网络搜索提供商",
	},
	"exa.searchDelayMs": {
		label: "Exa 搜索延迟",
		description: "Exa 网络搜索请求之间的最小延迟（毫秒）；设为 0 禁用节流",
	},
	"searxng.endpoint": {
		label: "SearXNG 端点",
		description: "用于网络搜索的自托管 SearXNG 实例基础 URL",
	},
	"secrets.enabled": {
		label: "隐藏机密",
		description: "在发送给 AI 提供商前混淆已配置的机密，并脱敏凭据形态的 token",
	},
	"tts.localVoice": {
		label: "本地 TTS 语音",
		description: "本地 TTS 后端使用的 Kokoro 语音（美式/英式，女声/男声）",
		options: {
			af_heart: { label: "Heart（美式女声）" },
			af_bella: { label: "Bella（美式女声）" },
			af_nicole: { label: "Nicole（美式女声）" },
			af_aoede: { label: "Aoede（美式女声）" },
			af_kore: { label: "Kore（美式女声）" },
			af_sarah: { label: "Sarah（美式女声）" },
			am_michael: { label: "Michael（美式男声）" },
			am_fenrir: { label: "Fenrir（美式男声）" },
			am_puck: { label: "Puck（美式男声）" },
			bf_emma: { label: "Emma（英式女声）" },
			bm_george: { label: "George（英式男声）" },
			bm_fable: { label: "Fable（英式男声）" },
		},
	},
	"tts.localSpeed": {
		label: "本地 TTS 速度",
		description: "本地 TTS 后端的语速（tts 工具、reverse say）。1 = 正常；限制在 0.5–2.5",
		options: {
			"0.5": { label: "0.5×" },
			"0.75": { label: "0.75×" },
			"1": { label: "1×（正常）" },
			"1.25": { label: "1.25×" },
			"1.5": { label: "1.5×" },
			"1.75": { label: "1.75×" },
			"2": { label: "2×" },
			"2.5": { label: "2.5×" },
		},
	},
	"speech.enabled": {
		label: "语音朗读",
		description: "助手输出流式生成时通过扬声器朗读",
	},
	"speech.mode": {
		label: "语音朗读模式",
		description: "朗读内容：all = 助手消息 + 思考；assistant = 仅消息；yield = 仅轮次结束时的最终消息",
		options: {
			all: { label: "全部（消息 + 思考）" },
			assistant: { label: "助手消息" },
			yield: { label: "仅最终消息" },
		},
	},
	"speech.enhanced": {
		label: "增强语音改写",
		description:
			"在合成前用 tiny/smol 模型将助手输出改写为自然口语散文（描述代码，去掉链接和 Markdown）。失败时回退到机械清理",
	},
	"speech.voice": {
		label: "语音朗读声音",
		description: "朗读助手输出时使用的 Kokoro 语音",
		options: {
			af_heart: { label: "Heart（美式女声）" },
			af_bella: { label: "Bella（美式女声）" },
			af_nicole: { label: "Nicole（美式女声）" },
			af_aoede: { label: "Aoede（美式女声）" },
			af_kore: { label: "Kore（美式女声）" },
			af_sarah: { label: "Sarah（美式女声）" },
			am_michael: { label: "Michael（美式男声）" },
			am_fenrir: { label: "Fenrir（美式男声）" },
			am_puck: { label: "Puck（美式男声）" },
			bf_emma: { label: "Emma（英式女声）" },
			bm_george: { label: "George（英式男声）" },
			bm_fable: { label: "Fable（英式男声）" },
		},
	},
	"speech.speed": {
		label: "语音朗读速度",
		description: "朗读助手输出时的语速。1 = 正常；限制在 0.5–2.5",
		options: {
			"0.5": { label: "0.5×" },
			"0.75": { label: "0.75×" },
			"1": { label: "1×（正常）" },
			"1.25": { label: "1.25×" },
			"1.5": { label: "1.5×" },
			"1.75": { label: "1.75×" },
			"2": { label: "2×" },
			"2.5": { label: "2.5×" },
		},
	},
	"live.voice": {
		label: "实时语音",
		description: "由 Codex 支持的实时语音会话使用的声音",
		options: {
			arbor: { label: "Arbor" },
			breeze: { label: "Breeze" },
			cove: { label: "Cove" },
			ember: { label: "Ember" },
			juniper: { label: "Juniper" },
			maple: { label: "Maple" },
			sol: { label: "Sol" },
			spruce: { label: "Spruce" },
			vale: { label: "Vale" },
		},
	},
	"telemetry.otlpExportEnabled": {
		label: "OTLP 遥测导出",
		description: "允许 REVERSE 使用 OTEL_* 端点导出追踪、日志和指标。更改在下次启动时生效。",
	},
};
