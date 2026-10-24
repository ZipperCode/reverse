# vmp_dump

调用 VMPDump 对已运行至原始入口点的 Windows x64 进程转储模块并修复导入表。虚拟化函数仍需另行分析。

## 安装

- CLI：`reverse setup reverse vmpdump --execute`，确认后安装固定上游发布包。
- TUI：`/setup` → 逆向工程工具链 → VMPDump。
- 能力 ID：`vmp_dump_repair`。
- 方法指导：`skill://vmp-reverse`。

受管安装会校验 SHA-256 和 AMD64 PE。`VMPDUMP_PATH` 可指定现有 Windows 可执行文件。macOS/Linux 返回不支持，不启动 Windows 程序。

## 调用

```js
vmp_dump({ action: "status" })
vmp_dump({
  action: "dump", pid: 4128,
  module_path: "C:\\targets\\sample.exe",
  observed_oep: true,
  entry_point: "0x1000",
  output_path: "C:\\analysis\\sample.dump.exe"
})
```

- `pid`：正的 32 位进程标识符，可用整数或十六进制字符串。
- `module_path`：磁盘上的目标模块路径。
- `module`：可选模块名；空字符串选择主映像。
- `process_image_path`：分析次级模块时提供宿主进程主可执行文件路径，用于确定上游输出目录。
- `observed_oep: true`：明确确认已观察到目标完成初始化/解包并到达 OEP。
- `entry_point`：可选 OEP **RVA**，位于目标映像范围内；优先使用字符串。
- `disable_reloc`：可选，将转储标记为剥离重定位。
- `output_path`：可选，独占发布验证后的转储副本，保留已有文件。
- `timeout`：秒，默认 60，上限 300。

次级模块示例：

```js
vmp_dump({
  action: "dump", pid: 4128, module: "target.dll",
  module_path: "C:\\plugins\\target.dll",
  process_image_path: "C:\\targets\\host.exe",
  observed_oep: true,
  output_path: "C:\\analysis\\target.dump.dll"
})
```

VMPDump 将文件写入**宿主进程主映像所在目录**，命名为 `<模块名>.VMPDump.<扩展名>`。工具检查真实新产物，保存字节数与 SHA-256，再按需发布副本。已有转储需要先保留并移开，避免覆盖原始样本或旧证据。

## 执行与证据

`status` 为读取操作。`dump` 需要执行审批、目标访问权限和 OEP 确认证据，并在计划模式中受阻。工具不会自动启动样本。

执行目标应为用户拥有或获准分析的样本，并使用隔离 Windows 实验环境。转储成功只证明产生了可检查的 PE 产物；导入完整性、可运行性与函数语义分别验证。
