import type { SettingTranslation } from "../../types";

export const appearanceSettingsZhCN: Record<string, SettingTranslation> = {
	"task.showResolvedModelBadge": {
		label: "显示解析后的模型徽标",
		description: "在任务组件状态栏中显示每个子代理实际使用的模型 ID",
	},
	"theme.dark": {
		label: "深色主题",
		description: "终端使用深色背景时采用的主题",
	},
	"theme.light": {
		label: "浅色主题",
		description: "终端使用浅色背景时采用的主题",
	},
	symbolPreset: {
		label: "符号预设",
		description: "图标与符号使用的字形集（Unicode、Nerd Font 或 ASCII）",
		options: {
			unicode: { label: "Unicode", description: "标准符号（默认）" },
			nerd: { label: "Nerd Font", description: "需要 Nerd Font 或 Glyph Protocol 终端（图标随内容传输）" },
			ascii: { label: "ASCII", description: "最大兼容性" },
		},
	},
	colorBlindMode: {
		label: "色盲模式",
		description: "在差异新增内容中使用蓝色代替绿色",
	},
	"composer.shape": {
		label: "输入区布局",
		description: "输入编辑器与状态栏的视觉布局",
		options: {
			band: {
				label: "状态带（默认）",
				description: "弧形输入区上方的柔和状态带，无边框",
			},
			box: {
				label: "圆角框",
				description: "状态栏嵌入顶部边框，紧凑的两行输入区",
			},
			claude: {
				label: "Claude Code",
				description: "上下全宽水平分隔线，状态栏在底部",
			},
			pi: {
				label: "Pi",
				description: "带边框的水平分隔线，状态栏在底部",
			},
			borderless: {
				label: "无边框",
				description: "简洁输入符号，状态栏在底部，无框线",
			},
			rule: {
				label: "顶部分隔线停靠",
				description: "单条顶部分隔线，状态栏停靠在其上及其下方",
			},
			field: {
				label: "紧凑字段",
				description: "带强调色端帽的单行填充字段",
			},
			rail: {
				label: "强调轨道",
				description: "由单条强调轨道锚定的单行填充字段",
			},
		},
	},
	"composer.tokenRate": {
		label: "生成速率",
		description:
			"显示实时生成 tok/s：工作时显示在会话标题旁的一行，或在原生输入栏中思考级别之后；最后一读数会保留到下一轮。根据流式增量估算，并在每条消息完成时按提供商计费输出数校正。",
	},
	"statusLine.preset": {
		label: "状态栏预设",
		description: "预置的状态栏配置",
		options: {
			default: { label: "默认", description: "模型、路径、git、上下文、token、费用" },
			minimal: { label: "极简", description: "仅路径和 git" },
			compact: { label: "紧凑", description: "模型、git、费用、上下文" },
			full: { label: "完整", description: "包含时间在内的所有片段" },
			nerd: { label: "Nerd", description: "使用 Nerd Font 图标展示最多信息" },
			ascii: { label: "ASCII", description: "不使用特殊字符" },
			custom: { label: "自定义", description: "用户定义的片段" },
		},
	},
	"statusLine.separator": {
		label: "状态栏分隔符",
		description: "片段之间分隔符的样式",
		options: {
			powerline: { label: "Powerline", description: "实心箭头（Nerd Font）" },
			"powerline-thin": { label: "细箭头", description: "细箭头（Nerd Font）" },
			slash: { label: "斜杠", description: "正斜杠" },
			pipe: { label: "竖线", description: "竖线" },
			block: { label: "方块", description: "实心方块" },
			none: { label: "无", description: "仅空格" },
			ascii: { label: "ASCII", description: "大于号" },
		},
	},
	"statusLine.contextLine": {
		label: "上下文响应线",
		description: "左右片段之间的连线如何反映上下文用量（仅限方框输入区）",
		options: {
			off: { label: "关闭", description: "纯色强调线，不反馈上下文" },
			percentage: { label: "百分比", description: "已用部分用强调色，剩余部分变暗" },
			annotated: { label: "带刻度", description: "百分比，并在推测压缩与自动压缩边界处显示刻度" },
			embedded: { label: "嵌入", description: "带刻度的线，并将上下文百分比和窗口嵌入仪表" },
		},
	},
	"statusLine.sessionAccent": {
		label: "会话强调色",
		description: "使用会话名称颜色作为编辑器边框和状态栏间隙颜色",
	},
	"statusLine.transparent": {
		label: "透明状态栏",
		description:
			"状态栏使用终端默认背景而非主题的 `statusLineBg`。Powerline 端帽会被移除，因为它们需要对比填充色才能与周围终端衔接。",
	},
	"statusLine.compactThinkingLevel": {
		label: "紧凑思考级别",
		description:
			"将思考级别显示为模型名称上的单个图标，而不是单独的 ` · <level>` 后缀；在 Tern 输入区中显示为模型 chip 的图标而非独立 chip（点击图标可循环切换）。",
	},
	"statusLine.showHookStatus": {
		label: "显示钩子状态",
		description: "在状态栏下方显示钩子状态消息",
	},
	"terminal.showImages": {
		label: "显示内联图片",
		description: "在终端中内联渲染图片",
	},
	"images.autoResize": {
		label: "自动调整图片尺寸",
		description: "将大图片缩小到最大 2000x2000，以提高模型兼容性",
	},
	"images.blockImages": {
		label: "阻止图片",
		description: "阻止将图片发送给 LLM 提供商",
	},
	"tui.resizeScrollback": {
		label: "调整回滚缓冲区",
		description: "终端尺寸稳定变化后，如何刷新保留在终端回滚缓冲区中的记录行",
		options: {
			append: { label: "追加", description: "在保留的历史下方按新宽度重放记录" },
			rebuild: { label: "重建", description: "清除所有终端回滚内容，然后按当前宽度重放一份记录" },
			preserve: { label: "保留", description: "仅重绘视口，历史仍按旧宽度换行" },
		},
	},
	"tui.completeScrollback": {
		label: "完整回滚缓冲区",
		description:
			"将因 HUD 或对话框增长而被推离屏幕的记录行直接送入回滚缓冲区；当其缩小时，记录与输入区之间会保留空白行，直到新输出填满它们",
	},
	"terminal.showProgress": {
		label: "原生终端进度",
		description: "代理或上下文维护运行时发送 OSC 9;4 不确定进度（Tern 中始终开启）",
	},
	"terminal.programStatus": {
		label: "程序状态（OSC 7501）",
		description: "通过 OSC 7501 报告代理正在工作、等待你、已完成或失败，供终端标签指示器和代理收件箱使用",
	},
	"tui.textSizing": {
		label: "大标题（Kitty）",
		description:
			"使用 Kitty 的 OSC 66 文本缩放协议将 Markdown H1 标题渲染为 2 倍大小。仅在 Kitty 终端生效，其他终端忽略。默认关闭。",
	},
	"tui.renderMermaid": {
		label: "渲染 Mermaid 图",
		description: "将 Mermaid 围栏代码块渲染为 ASCII 图",
	},
	"tui.renderSvg": {
		label: "渲染 SVG 图形",
		description: "邀请代理以 SVG 绘制图表，并在支持图形显示的终端中内联渲染为图片",
	},
	"tui.autoGraph": {
		label: "表格自动成图",
		description: "在支持图形显示的终端中，用主题颜色为代理回答中的数值表格绘制图表",
		options: {
			smart: {
				label: "智能",
				description: "由评审模型细化每个图表：类型、列、行名与分组、比例尺、哪个方向更好以及标题",
			},
			always: { label: "始终", description: "使用内置最佳推测为每个数值表格绘图" },
			off: { label: "关闭", description: "保持表格原样" },
		},
	},
	"tui.reactions": {
		label: "代理表情回应",
		description: "邀请代理用气泡上的 emoji 徽标回应你的消息",
	},
	"tui.codexResetFireworks": {
		label: "Codex 重置烟花",
		description:
			"以占据屏幕上方三分之一的烟花覆盖层庆祝 Codex 周用量非计划重置和新存入的已保存重置，直到按 Esc 才消失",
	},
	"tui.titleState": {
		label: "终端标题运行状态",
		description:
			"在终端标题分隔符中显示代理运行状态——工作时为动画旋转指示器（WSL 下为静态 ':'），轮到你时为 '>'，代理等待你时为 '!'",
	},
	"tui.titleSpinner": {
		label: "终端标题旋转指示器",
		description: "终端标题中工作状态旋转指示器使用的字形集——盲文扫掠、月相填充、单点循环或 ASCII 安全线条",
		options: {
			braille: { label: "盲文", description: "经典 ⠋⠙⠹ 扫掠（默认）" },
			pulse: { label: "脉冲", description: "月相填充 ○◑● 后逐渐清空" },
			dots: { label: "点", description: "单个盲文点循环" },
			line: { label: "线条", description: "适用于无盲文字体覆盖的 ASCII 线条 - \\ | /" },
		},
	},
	"tui.hyperlinks": {
		label: "终端超链接",
		description: "用 OSC 8 超链接包裹路径和 URL，以支持终端原生点击打开（auto：检测支持；off：从不；always：无条件）",
	},
	"tui.mouse": {
		label: "鼠标交互",
		description:
			"默认关闭以保留终端原生滚轮滚动和文本选择（仍可按 Ctrl+O 展开详情）。开启后可点击可见的思考与工具标题或子代理卡片，但原生滚动和选区需要配合终端修饰键（支持的环境下按住 Shift）",
	},
	"tui.tight": {
		label: "紧凑布局",
		description: "移除终端输出左右两侧各 1 个字符的水平内边距",
	},
	"display.shimmer": {
		label: "微光效果",
		description: "工作/加载消息的动画样式",
		options: {
			classic: { label: "经典", description: "柔和余弦波扫过文本" },
			kitt: { label: "KITT 扫描灯", description: "1982 年《霹雳游侠》式红色灯光左右弹跳" },
			disabled: { label: "禁用", description: "无动画；静态弱化文本" },
		},
	},
	"display.pinnedAgents": {
		label: "固定代理",
		description: "编辑器上方的实时代理固定跳转列表（off 隐藏；collapsed 显示几行并带展开器；full 列出全部）",
		options: {
			off: { label: "关闭", description: "隐藏固定跳转列表" },
			collapsed: { label: "折叠", description: "显示几行并带展开器" },
			full: { label: "完整", description: "始终列出每个实时代理" },
		},
	},
	"display.subagentLivePreview": {
		label: "子代理实时预览",
		description: "在每个固定子代理行下方显示其当前（或最近一次）工具调用",
	},
	"display.smoothStreaming": {
		label: "平滑流式输出",
		description: "在数据块到达时平滑显示助手文本和流式工具输入",
	},
	"display.hideToolActivity": {
		label: "隐藏工具活动",
		description: "从记录中隐藏模型发起的工具调用和结果",
	},
	"display.showTokenUsage": {
		label: "显示 token 用量",
		description: "在助手消息上显示每轮 token 用量",
	},
	"display.showTurnTime": {
		label: "显示轮次耗时",
		description: "在助手消息用量行中显示从提示到让出的总耗时（包括工具调用）",
	},
	"display.cacheMissMarker": {
		label: "缓存未命中标记",
		description: "当某轮助手请求未命中提示缓存时，在其后显示分隔线",
	},
	"display.collapseCompacted": {
		label: "折叠已压缩历史",
		description: "在实时记录中将压缩前的历史折叠到摘要分隔线之后；禁用则在每个压缩点用分隔线保留完整记录",
	},
	showHardwareCursor: {
		label: "显示硬件光标",
		description: "显示终端光标以支持输入法",
	},
	"tui.imeSafeCursor": {
		label: "输入法安全提示布局",
		description: "将提示符底边框移到单独一行，避免 macOS 输入法预编辑内容顶开边框",
	},
	language: {
		label: "语言",
		description: "用于配置标签、描述和界面文本的语言",
		options: {
			en: { label: "English", description: "使用英文配置标签和描述" },
			"zh-CN": { label: "简体中文", description: "使用简体中文配置标签与说明" },
		},
	},
	"title.icons": {
		label: "标题图标",
		description: "新生成或 /rename 的会话标题前的图标和短代码",
		options: {
			"nf+emoji": {
				label: "Nerd Font + Emoji",
				description: "在 Nerd Font 符号预设可渲染时使用 Nerd Font 字形，否则使用 emoji（默认）",
			},
			emoji: { label: "Emoji", description: "始终使用 emoji" },
			boring: { label: "朴素", description: "纯标题：无图标或代码" },
		},
	},
};
