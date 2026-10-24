// oxlint-disable no-template-curly-in-string -- text intentionally carries ${name} placeholders.
/**
 * Chinese text for the `config` command's human-facing help, usage and status
 * messages. Values may contain `{name}` placeholders filled by the caller.
 */
export const CLI_TRANSLATIONS_ZH_CN: Record<string, string> = {
	"cli.config.description": "管理配置设置",
	"cli.config.arg.action": "配置操作",
	"cli.config.arg.key": "设置键",
	"cli.config.arg.value": "值（用于 set/reset）",
	"cli.config.flag.json": "以 JSON 输出",
	"cli.config.usage.get": "用法：{app} config get <key>",
	"cli.config.usage.set": "用法：{app} config set <key> <value>",
	"cli.config.usage.reset": "用法：{app} config reset <key>",
	"cli.config.unknownCommand": "未知配置命令：{action}",
	"cli.config.validCommands": "有效命令：{commands}",
	"cli.config.unknownSetting": "未知设置：{key}",
	"cli.config.runListHint": "运行 '{app} config list' 查看可用键",
	"cli.config.listTitle": "设置：",
	"cli.config.notSet": "（未设置）",
	"cli.config.setSuccess": "已设置 {path} = {value}",
	"cli.config.resetSuccess": "已将 {path} 重置为 {value}",
	"cli.config.shadow.fallback": "${name} 在保存值为空时作为回退使用。",
	"cli.config.shadow.override": "${name} 会覆盖此值；取消设置后才能应用保存值。",
	"cli.config.shadow.project": "项目设置会在此处覆盖此值；请在项目设置中编辑或移除以应用保存值。",
	"cli.config.shadow.overlay": "--config / PI_CONFIG_FILES 覆盖层会在当前进程中覆盖此值。",
	"cli.config.shadow.runtime": "运行时覆盖会为当前进程提供有效值。",
	"cli.setup.reverse.title": "通用逆向工具链安装面板",
	"cli.setup.reverse.description": "检查工具状态、批量选择并安装逆向工具与 MCP 辅助服务（交互式确认后执行）",
	"cli.setup.reverse.platform": "检测到平台：{platform}",
	"cli.setup.reverse.packageManagers": "可用包管理器：{managers}",
	"cli.setup.reverse.noPackageManagers": "无（需手动安装）",
	"cli.setup.reverse.statusInstalled": "已安装",
	"cli.setup.reverse.statusMissing": "未安装",
	"cli.setup.reverse.required": "必需",
	"cli.setup.reverse.optional": "可选",
	"cli.setup.reverse.promptSelect":
		"输入要安装的工具/服务序号或 ID（如 1, 3, jadx, r2mcp，'all-missing' 安装全部缺失项，输入 'q' 退出）：",
	"cli.setup.reverse.alreadyInstalled": "工具 {name} 已安装在 {path}。是否仍要重新安装？[y/N]：",
	"cli.setup.reverse.noManagerFound":
		"当前系统未检测到适用的包管理器（如 brew/apt/choco）。请参阅以下说明进行手动安装：",
	"cli.setup.reverse.manualUrl": "官方链接：{url}",
	"cli.setup.reverse.manualGuide": "安装指南：{guide}",
	"cli.setup.reverse.detailTool": "工具：{name} ({id})",
	"cli.setup.reverse.detailCategory": "分类：{category}",
	"cli.setup.reverse.detailType": "类型：{type}",
	"cli.setup.reverse.detailManager": "包管理器：{manager}",
	"cli.setup.reverse.detailCommand": "安装命令：{command}",
	"cli.setup.reverse.detailRisk": "风险与权限说明：{risk}",
	"cli.setup.reverse.confirmPrompt": "确认执行此安装命令？[y/N]：",
	"cli.setup.reverse.cancelled": "已取消 {name} 的安装。",
	"cli.setup.reverse.executing": "正在执行：{command}...",
	"cli.setup.reverse.execSuccess": "安装命令执行成功。",
	"cli.setup.reverse.execFailed": "安装命令执行失败（退出码：{code}）。",
	"cli.setup.reverse.verifiedFound": "已验证：{name} 已成功安装在 {path}！",
	"cli.setup.reverse.verifiedNotFound":
		"提示：命令执行完成，但在 PATH 中未检测到 {name} 可执行文件。您可能需要重启终端或配置环境变量。",
	"cli.setup.reverse.checkSummary": "逆向工程工具链检测概览：",
	"cli.setup.reverse.allReady":
		"核心系统工具已就绪（strings、file）。已安装 {installed} 项，另有 {missing} 项可选逆向工具可按需安装。",
	"cli.setup.reverse.missingRequiredNotice": "缺少核心系统基础工具：{tools}",
	"cli.setup.reverse.manualModeNotice":
		"【手动模式】请复制上述命令在终端中运行；如需在确认后辅助执行，请带参数 '--execute' 重新运行。",
	"cli.setup.reverse.executeRequiresTTY":
		"{app} setup reverse 需要交互式 TTY 终端。非交互环境请使用 --check 或 --json。",
	"cli.setup.reverse.noSelected": "未选择任何有效工具或服务。",
	"cli.setup.reverse.planTitle": "安装与配置计划（批量）",
	"cli.setup.reverse.planTargets": "目标项：",
	"cli.setup.reverse.planSteps": "执行步骤：",
	"cli.setup.reverse.planRisks": "风险与注意事项：",
	"cli.setup.reverse.planManualTitle": "需手动配置 / 暂无自动配方的项：",
	"cli.setup.reverse.planManualNotice": "以下工具需要手动配置或具有商业授权前提，未包含在自动安装中：",
	"cli.setup.reverse.batchConfirmPrompt": "确认执行上述安装计划？[y/N]：",
	"cli.setup.reverse.batchCancelled": "已取消批量安装。",
	"cli.setup.reverse.noInstallableSelected": "所选项目中没有可自动安装的项。",
	"cli.setup.reverse.executingTarget": "正在安装与配置 {name} ({id})...",
	"cli.setup.reverse.execFailedTarget": "{name} 安装/配置失败：{error}",
	"cli.setup.reverse.confirmServicePrompt": "确认安装 MCP 服务 {name}？[y/N]：",
	"cli.setup.reverse.alreadyInstalledService": "MCP 服务 {name} 已安装。是否重新检查并连接？[y/N]：",
	"cli.setup.reverse.executingService": "正在安装 MCP 服务 {name}...",
	"cli.setup.reverse.serviceInstallSuccess": "MCP 服务 {name} 安装与配置成功（配置文件：{path}，工具：{tools}）。",
	"cli.setup.reverse.serviceInstallFailed": "MCP 服务 {name} 安装失败：{error}",
	"cli.setup.reverse.jshookmcp.desc": "多领域 JavaScript 分析、CDP 调试、AST 反混淆与网络流量检查 MCP 服务",
	"cli.setup.reverse.jshookmcp.risk":
		"运行具有 CDP 与 JavaScript 审查能力的本地 Node.js 进程（AGPL-3.0）。通过带有 search profile 的本地 stdio 运行。",
	"cli.setup.reverse.managedInstallationLabel": "内置受管服务安装：",
	"cli.setup.reverse.managedInstallationDesc": "@jshookmcp/jshook（在 agent 目录中隔离安装的 stdio MCP 服务）",
	"cli.setup.reverse.managedStatusInstalled": "受管服务包已安装",
	"cli.setup.reverse.managedStatusMissing": "受管服务包未安装",
	"cli.setup.reverse.managerNotConnected": "当前会话未运行 MCP 管理器，请重载会话以激活",
	"cli.setup.reverse.selection.description": "说明",
	"cli.setup.reverse.selection.purpose": "用途",
	"cli.setup.reverse.selection.status": "状态",
	"cli.setup.reverse.tool.strings.description":
		"从二进制文件中提取可打印字符串，快速寻找网址、路径、报错信息与特征常量。",
	"cli.setup.reverse.tool.file.description": "识别样本的文件类型、格式与架构，确定后续应使用哪类分析工具。",
	"cli.setup.reverse.tool.jadx.description": "将 DEX 字节码反编译为 Java，支持查看 APK 代码、搜索调用和分析业务逻辑。",
	"cli.setup.reverse.tool.apktool.description": "解码 APK 资源与清单、反汇编 smali，并支持修改后的应用重新打包。",
	"cli.setup.reverse.tool.adb.description": "连接 Android 真机或模拟器，安装应用、执行设备命令并收集运行日志。",
	"cli.setup.reverse.tool.frida.description": "动态插桩与运行时 Hook 工具，可观察函数参数、返回值、模块和进程状态。",
	"cli.setup.reverse.tool.radare2.description": "二进制逆向框架，提供反汇编、符号、字符串、交叉引用与脚本化分析。",
	"cli.setup.reverse.tool.ghidra.description": "逆向分析与反编译框架，支持无界面批量分析和生成伪代码。",
	"cli.setup.reverse.tool.droidasc.description": "辅助检查 APK 结构与 Android 应用的逆向分析信息。",
	"cli.setup.reverse.tool.ast-grep.description":
		"按语法树结构搜索和改写代码，适合定位压缩 JavaScript 中的特定调用模式。",
	"cli.setup.reverse.tool.wabt.description": "WebAssembly 工具集，支持 WASM 与 WAT 文本转换、反汇编和模块检查。",
	"cli.setup.reverse.tool.upx.description": "可执行文件压缩与解包工具，用于检查和解开受 UPX 压缩的样本。",
	"cli.setup.reverse.tool.aapt2.description": "检查 APK 资源、清单和应用元信息，辅助还原资源与入口结构。",
	"cli.setup.reverse.tool.zipalign.description": "调整 APK 内部文件对齐，通常用于修改后重新打包应用的流程。",
	"cli.setup.reverse.tool.apksigner.description": "验证 APK 签名与签名方案，检查证书和包文件完整性。",
	"cli.setup.reverse.tool.dexdump.description": "输出 DEX 类、方法与字节码，辅助进行底层指令分析。",
	"cli.setup.reverse.tool.unidbg.description":
		"在主机 JVM 中模拟执行 Android ARM JNI 库，需要自行接入 Maven/Java 调用程序。",
	"cli.setup.reverse.tool.bundletool.description": "检查 AAB 应用包并生成 APK 集，便于提取和分析拆分安装包。",
	"cli.setup.reverse.tool.dex2jar.description": "把 DEX 转换为 Java JAR，供其他 Java 反编译器继续分析。",
	"cli.setup.reverse.tool.baksmali.description": "将 DEX 反汇编为 smali，用于寄存器追踪、字节码审查和指令修改。",
	"cli.setup.reverse.tool.scrcpy.description": "通过 USB 或网络显示并控制 Android 屏幕，辅助观察动态分析过程。",
	"cli.setup.reverse.tool.hermes-dec.description": "反汇编和反编译 Hermes JavaScript 字节码，适用于相关应用脚本分析。",
	"cli.setup.reverse.tool.hbctool.description": "Hermes 字节码汇编与反汇编工具，用于检查或修改 HBC 文件。",
	"cli.setup.reverse.tool.il2cppdumper.description": "从 Unity IL2CPP 二进制中恢复类型、方法元信息及辅助头文件。",
	"cli.setup.reverse.tool.wasm-tools.description": "验证、检查和转换 WebAssembly 二进制，辅助分析模块结构。",
	"cli.setup.reverse.tool.readelf.description": "检查 ELF 文件头、段、节、符号与备注信息，辅助判断二进制布局。",
	"cli.setup.reverse.tool.binwalk.description": "识别固件内嵌文件与文件系统，并辅助执行多层提取。",
	"cli.setup.reverse.tool.vbindiff.description": "以十六进制和 ASCII 并排比较二进制文件，定位字节差异。",
	"cli.setup.reverse.tool.cargo_auditable.description":
		"为 Rust 程序嵌入可审计依赖信息，并辅助检查已编译样本的依赖组成。",
	"cli.setup.reverse.tool.cast.description": "查询以太坊 RPC、编码调用参数并检查合约字节码与链上状态。",
	"cli.setup.reverse.tool.mitmproxy.description":
		"可拦截和修改 HTTP(S) 请求的代理，用于授权流量抓取、重放及接口协议分析。",
	"cli.setup.reverse.tool.tshark.description": "终端网络抓包与协议解析工具，适合实时流量捕获和深度报文分析。",
	"cli.setup.reverse.tool.sqlite3.description": "SQLite 数据库命令行工具，用于检查表结构、查询数据和分析本地存储。",
	"cli.setup.reverse.tool.node.description":
		"JavaScript 运行时及 npm/npx 工具链，为浏览器分析与 MCP 服务提供运行环境。",
	"cli.setup.reverse.tool.java.description": "Java 运行环境，是 JADX、Apktool、Unidbg 等工具的前置依赖。",
	"cli.setup.reverse.tool.python.description": "Python 3.9+ 运行环境，为 DEX 补丁与 APK 重新打包管线提供执行引擎。",
	"cli.setup.reverse.tool.ida.description":
		"通过 IDA 的 idalib 无头引擎进行反汇编与反编译；需相应授权及 Python 环境，无需打开桌面端。",
	"cli.setup.reverse.ida.name": "IDA Pro",
	"cli.setup.reverse.ida.repair.risk":
		"向 IDA idalib 使用的 Python 环境中安装 ida-domain==0.5.1 并按需更新 idapro 依赖。",
	"cli.setup.reverse.ida.unsupportedPython":
		"已检测到 IDA 安装及 idalib，但目标 Python 环境（{python} 版本 {version}）不受支持。ida-domain 要求 Python >= 3.10 且 IDA >= 9.1。请在设置中配置 ida.python 指向兼容的 Python >= 3.10 虚拟环境。",
	"cli.setup.reverse.ida.importError":
		"已检测到 IDA 安装及 idalib，但在 Python 环境中导入适配层时出错：{error}。请检查 IDA 授权许可、IDADIR 路径、系统依赖库以及 idapyswitch 配置。",
	"cli.setup.reverse.ida.noInterpreter":
		"已检测到 IDA 安装及 idalib，但未找到可用的 Python 解释器。请安装 Python >= 3.10 或在设置中配置 ida.python。",
	"cli.setup.reverse.tool.playwright-mcp.description": "通过 MCP 提供浏览器操作、页面状态读取和动态 Web 分析能力。",
	"cli.setup.reverse.tool.r2mcp.description": "通过 MCP 保持 radare2 分析会话，提供反汇编、交叉引用和脚本查询。",
	"cli.setup.reverse.tool.jshookmcp.description":
		"通过 MCP 提供 JavaScript 调试、Hook、AST 反混淆、签名实验与网络协议分析。",
	"cli.setup.reverse.tool.x64dbg-mcp.description": "x64dbg 自动化与调试 MCP 服务，支持本地 Windows 或跨平台远程分析。",
	"cli.setup.reverse.tool.ghidra-mcp.description": "Ghidra 软件逆向工程 MCP 服务，支持无头项目分析与反编译。",
	"cli.setup.reverse.tool.frida.purpose": "观察应用真实执行路径，追踪函数调用、运行时数据和动态加载的模块。",
	"cli.setup.reverse.tool.radare2.purpose":
		"需要无头二进制分析，或 IDA 不可用时，检查导入、符号、字符串及单函数汇编。",
	"cli.setup.reverse.tool.ghidra.purpose": "需要批量静态分析和伪代码，或使用免费的反编译方案时。",
	"cli.setup.reverse.tool.unidbg.purpose": "无需真机，在模拟环境中调用 JNI 算法，验证签名、加密或令牌计算。",
	"cli.setup.reverse.tool.bundletool.purpose": "将 AAB 转为可部署、可检查的 APK，分析拆分包中的代码与资源。",
	"cli.setup.reverse.tool.dex2jar.purpose": "把 Android 字节码交给 CFR、Fernflower 等 Java 反编译器处理。",
	"cli.setup.reverse.tool.baksmali.purpose": "需要精确检查或修改 DEX 指令、寄存器和分支逻辑时。",
	"cli.setup.reverse.tool.python.purpose":
		"执行基于 Python stdlib 的离线 DEX 结构校验、字节码语义补丁与 APK 容器重组。",
	"cli.setup.reverse.tool.scrcpy.purpose": "操作目标应用界面，观察真机上的运行行为并复现业务步骤。",
	"cli.setup.reverse.tool.readelf.purpose":
		"检查原始 ELF 元数据或 core dump 的备注段；常规崩溃分析可先用内置 crashdump_inspect。",
	"cli.setup.reverse.tool.binwalk.purpose": "需要深层固件签名识别和提取时；基础离线检查可先用内置 firmware_inspect。",
	"cli.setup.reverse.tool.vbindiff.purpose":
		"交互式查看两个样本的十六进制差异；确定性离线比较可先用内置 binary_diff。",
	"cli.setup.reverse.tool.cargo_auditable.purpose":
		"构建带审计元数据的 Rust 程序；已有样本可先用内置 binary_metadata_inspect。",
	"cli.setup.reverse.tool.cast.purpose": "需要查询链上合约状态或编码 ABI 参数时；离线字节码可先用内置 evm_inspect。",
	"cli.setup.reverse.tool.mitmproxy.purpose": "在授权环境中捕获、修改与重放接口请求，验证鉴权、参数和签名行为。",
	"cli.setup.reverse.tool.tshark.purpose": "实时抓包或使用专用协议解析器；已有 PCAP 可先用内置 pcap_inspect。",
	"cli.setup.reverse.tool.sqlite3.purpose": "手动执行数据库查询；安全有界的只读检查可先用内置 sqlite_inspect。",
	"cli.setup.reverse.tool.playwright-mcp.purpose": "需要持续浏览器会话来检查页面、控制台、网络和 SourceMap 时。",
	"cli.setup.reverse.tool.r2mcp.purpose": "在同一二进制会话中反复查看地址、交叉引用和脚本分析结果。",
	"cli.setup.reverse.tool.jshookmcp.purpose": "定位复杂前端签名、调试混淆脚本，或进行去混淆和协议实验。",
	"cli.setup.reverse.tool.x64dbg-mcp.purpose":
		"对 Windows PE 样本进行动态调试、断点追踪与内存分析，支持远程会话连接。",
	"cli.setup.reverse.tool.ghidra-mcp.purpose":
		"对目标二进制进行深度反编译、符号分析与交叉引用提取，支持通过项目持久化复用分析结果。",
	"cli.setup.reverse.x64dbg-mcp.risk":
		"运行本地 Python MCP 桥接进程并通过 ZeroMQ 与 x64dbg 通信。远程调试使用未加密 ZMQ，建议通过私有环回口或 SSH 隧道运行。",
	"cli.setup.reverse.ghidra-mcp.risk":
		"在 agent 目录中安装受管 GhidraMCP wheel 与扩展 JAR。无头分析需本地已安装 Ghidra (建议 12.1.4+) 与 JDK 21+。",
	"cli.setup.reverse.r2mcp.risk": "通过 r2pm 包管理器安装 radare2 MCP 插件。可执行文件由客户端以 stdio 方式调用。",
	"cli.setup.reverse.triton.name": "Triton 二进制符号分析",
	"cli.setup.reverse.vmpdump.name": "VMPDump 转储与导入修复",
	"cli.setup.reverse.mergen.name": "Mergen 函数级 LLVM 提升",
	"cli.setup.reverse.novmp.name": "NoVmp 旧版 VTIL 去虚拟化",
	"cli.setup.reverse.tool.triton.description":
		"在隔离 Python 环境中使用 triton-library 回放指令轨迹、执行符号分析与表达式化简，并检测可选 LLVM 功能。",
	"cli.setup.reverse.tool.vmpdump.description":
		"对已运行至原始入口点的 Windows x64 VMP 进程执行模块转储和导入表修复。",
	"cli.setup.reverse.tool.mergen.description":
		"将指定 x64 PE 函数提升为 LLVM IR，辅助去混淆与语义恢复；不支持自修改代码。",
	"cli.setup.reverse.tool.novmp.description": "对已解包的 VMP 3.0–3.5 x64 函数执行实验性静态去虚拟化，输出 VTIL。",
	"cli.setup.reverse.tool.triton.purpose":
		"从已捕获轨迹恢复输入输出关系、化简混合布尔算术表达式和检查路径约束，目标机器码仅在分析引擎中模拟。",
	"cli.setup.reverse.tool.vmpdump.purpose": "保存已解包模块并修复受保护导入，为后续静态函数分析准备输入。",
	"cli.setup.reverse.tool.mergen.purpose": "分析单个受保护函数的控制流与语义，保留 LLVM IR 并独立验证行为。",
	"cli.setup.reverse.tool.novmp.purpose":
		"分析具有已知 VM 入口 RVA 的旧版 VMP 样本，保留原始样本并输出 VTIL 中间表示。",
	"cli.setup.reverse.triton.manual":
		"通过受管安装器在隔离 Python 环境中安装 triton-library；Apple Silicon 使用固定源码和依赖原生构建，LLVM 支持单独探测。",
	"cli.setup.reverse.vmpdump.manual":
		"在 Windows x64 主机的逆向工具面板中安装固定版本 VMPDump；先观察并记录目标到达 OEP，再批准转储。",
	"cli.setup.reverse.mergen.manual":
		"受管预编译包适用于 Windows x64；其他平台需构建兼容的原生 lifter 并配置路径，或在 Windows 主机上分析。",
	"cli.setup.reverse.novmp.manual":
		"受管预编译包适用于 Windows x64；源码使用 x86-64 指令内建函数，需兼容构建环境。输入必须已解包。",
	"cli.setup.reverse.triton.risk":
		"在 agent 工具目录中创建隔离环境并安装固定版本 triton-library；Apple Silicon 下载固定源码及 Capstone/Z3 依赖进行原生编译。不修改全局 Python 和 shell 配置。",
	"cli.setup.reverse.vmpdump.risk":
		"下载并校验上游 GPL-3.0 可执行文件。转储操作会访问选定 Windows 进程并写入模块文件，须单独批准。",
	"cli.setup.reverse.mergen.risk": "下载并校验上游 GPL-3.0 函数提升器。分析副本并生成 LLVM IR，不自动运行目标样本。",
	"cli.setup.reverse.novmp.risk":
		"下载并校验上游 GPL-3.0 去虚拟化工具。原生重编译功能具有实验性，VTIL 结果需独立复核。",
	"cli.setup.reverse.capability.symbolic_trace_analysis.name": "符号轨迹分析",
	"cli.setup.reverse.capability.symbolic_trace_analysis.scenario": "从 x86/x64 已捕获执行轨迹恢复符号输入输出关系。",
	"cli.setup.reverse.capability.symbolic_trace_analysis.description":
		"使用 Triton 有界回放指令和状态证据，化简表达式；引擎支持时生成 LLVM IR。",
	"cli.setup.reverse.capability.symbolic_trace_analysis.why":
		"沿已观察路径分离目标语义和混淆逻辑，目标机器码仅在分析引擎中模拟。",
	"cli.setup.reverse.capability.vmp_dump_repair.name": "VMP 转储与导入修复",
	"cli.setup.reverse.capability.vmp_dump_repair.scenario": "在 Windows 上转储已解包的 VMP x64 模块并重建导入。",
	"cli.setup.reverse.capability.vmp_dump_repair.description":
		"观察 OEP 后，对明确选择的进程运行 VMPDump，并保存修复后的 PE 产物。",
	"cli.setup.reverse.capability.vmp_dump_repair.why": "为静态分析准备已解包输入，并保留原始模块与映像基址证据。",
	"cli.setup.reverse.capability.native_function_lifting.name": "原生函数 LLVM 提升",
	"cli.setup.reverse.capability.native_function_lifting.scenario": "恢复单个混淆 x64 PE 函数的 LLVM IR。",
	"cli.setup.reverse.capability.native_function_lifting.description":
		"使用 Mergen 分析副本并保留实际 IR 和诊断；不支持自修改代码与全程序恢复。",
	"cli.setup.reverse.capability.native_function_lifting.why": "利用编译器优化辅助理解受保护函数的语义和控制流。",
	"cli.setup.reverse.capability.vmp_legacy_devirtualization.name": "旧版 VMP VTIL 去虚拟化",
	"cli.setup.reverse.capability.vmp_legacy_devirtualization.scenario": "分析已解包的 VMP 3.0–3.5 x64 虚拟化函数。",
	"cli.setup.reverse.capability.vmp_legacy_devirtualization.description":
		"向 NoVmp 提供选定 VM 入口 RVA 和必要的原始映像基址，将真实 VTIL 产物保存到独立目录。",
	"cli.setup.reverse.capability.vmp_legacy_devirtualization.why":
		"补充旧版静态分析后端，实验性重编译结果仍需独立行为验证。",
	"cli.setup.reverse.lief.name": "LIEF 二进制格式分析库",
	"cli.setup.reverse.sofixer.name": "SoFixer 内存转储修复工具",
	"cli.setup.reverse.ghidra-findcrypt.name": "Ghidra FindCrypt 加密特征分析器",
	"cli.setup.reverse.tool.lief.description": "深度解析 ELF 文件头、段、节、动态条目、重定位表及构造函数数组。",
	"cli.setup.reverse.tool.sofixer.description": "重建并修复从 Android 内存转储的 .so 共享库的节区头与动态段。",
	"cli.setup.reverse.tool.ghidra-findcrypt.description":
		"Ghidra 自动化分析插件，扫描定位加密算法常量与常见密码学特征。",
	"cli.setup.reverse.tool.lief.purpose":
		"在不执行样本的前提下深入分析 Linux/Android 原生二进制的结构与 .init_array 初始化流程。",
	"cli.setup.reverse.tool.sofixer.purpose":
		"修复从内存 dump 下来的损坏 .so 文件，重建 section header 以供 IDA 或 Ghidra 正确反编译。",
	"cli.setup.reverse.tool.ghidra-findcrypt.purpose": "快速标注二进制中的对称密码、哈希算法和 CRC 查找表常量位置。",
	"cli.setup.reverse.lief.risk": "在 agent 目录创建隔离虚拟环境并安装固定版本 lief (1.0.0, Apache-2.0)。",
	"cli.setup.reverse.sofixer.risk": "使用 CMake 和本地编译器从固定上游源码编译 32 位与 64 位 SoFixer 原生可执行文件。",
	"cli.setup.reverse.ghidra-findcrypt.risk":
		"使用 Gradle 针对当前已安装的 Ghidra 版本编译 FindCrypt 扩展并安装至 Ghidra 插件目录。",
	"cli.setup.reverse.capability.native_elf_analysis.name": "原生 ELF 深度分析",
	"cli.setup.reverse.capability.native_elf_analysis.scenario":
		"检查 ELF 头、段、动态条目、重定位表、init/fini 数组与地址映射。",
	"cli.setup.reverse.capability.native_elf_analysis.description":
		"使用 LIEF Python 绑定深入分析 Linux 和 Android 原生 ELF 结构，提取符号与构造函数。",
	"cli.setup.reverse.capability.native_elf_analysis.why": "无需执行二进制即可发现早期初始化反调试逻辑与动态绑定信息。",
	"cli.setup.reverse.capability.native_elf_repair.name": "原生 ELF 内存转储修复",
	"cli.setup.reverse.capability.native_elf_repair.scenario": "从内存 dump 重建并修复损坏的 ELF 节区头与段对齐。",
	"cli.setup.reverse.capability.native_elf_repair.description":
		"使用 SoFixer (32 位或 64 位) 重建从内存导出的原始 ELF 的节表与字符串表，输出分析候选文件。",
	"cli.setup.reverse.capability.native_elf_repair.why":
		"内存转储常常丢失节区头，导致反编译器解析失败；重构能恢复可加载布局。",
	"cli.setup.reverse.capability.native_crypto_constant_analysis.name": "原生密码学常量与算法识别",
	"cli.setup.reverse.capability.native_crypto_constant_analysis.scenario":
		"在 Ghidra 中利用 FindCrypt 扫描定位原生二进制中的加密常量与已知算法特征。",
	"cli.setup.reverse.capability.native_crypto_constant_analysis.description":
		"在无头 Ghidra 分析期间运行 FindCrypt 自动分析器，扫描并标记密码学常量候选位置（AES S 盒、散列初始向量及查找表）。",
	"cli.setup.reverse.capability.native_crypto_constant_analysis.why":
		"快速获取密码学常量候选位置与交叉引用入口，辅助结合后续反编译流程验证算法实现，而非直接断言加密函数。",
	"cli.setup.menu.title": "系统与工具链配置 (Setup)",
	"cli.setup.panel.providers.label": "模型服务商 (providers)",
	"cli.setup.panel.providers.desc": "配置 OAuth 登录、API Key 及 Web 搜索服务",
	"cli.setup.panel.add.label": "添加自定义服务商 (add)",
	"cli.setup.panel.add.desc": "添加兼容 OpenAI / Anthropic 协议的自定义模型服务商并自动发现模型",
	"cli.setup.panel.reverse.label": "逆向工程工具链 (reverse)",
	"cli.setup.panel.reverse.desc": "检查并安装逆向工具 (JADX, Frida, Radare2, ADB 等) 及 MCP 辅助服务",
	"cli.setup.panel.python.label": "Python 执行环境 (python)",
	"cli.setup.panel.python.desc": "检查并配置 Python 3 解释器与代码执行环境",
	"cli.setup.panel.speech.label": "语音识别与合成 (speech)",
	"cli.setup.panel.speech.desc": "配置并下载语音转文字 (STT) 与文字转语音 (TTS) 本地模型",
	"cli.setup.menu.exit": "← 退出",
	"cli.setup.menu.exitDesc": "关闭设置菜单",
};
