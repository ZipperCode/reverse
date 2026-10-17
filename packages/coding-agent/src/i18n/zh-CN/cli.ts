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
};
