# native_devirtualize

对 x64 PE 的指定函数执行 Mergen LLVM 提升，或使用 NoVmp 对旧版 VMP 函数执行 VTIL 去虚拟化。原始样本保持不变，每次运行分析独立副本。

## 安装

CLI：`reverse setup reverse mergen --execute`、`reverse setup reverse novmp --execute`。
TUI：`/setup` → 逆向工程工具链 → Mergen / NoVmp，选择后确认安装。

受管安装器下载固定 Windows x64 发布包并验证 SHA-256。其他平台可通过 `MERGEN_PATH` / `NOVMP_PATH` 指定兼容的原生构建；Windows PE 可执行文件不会被当作 macOS/Linux 原生程序。

能力 ID 分别为 `native_function_lifting` 和 `vmp_legacy_devirtualization`。完整路由和验证流程见 `skill://vmp-reverse`。

## Mergen

```js
native_devirtualize({ action: "status", backend: "mergen" })
native_devirtualize({
  action: "lift", backend: "mergen",
  path: "./artifacts/unpacked.exe",
  start_address: "0x140001000",
  output_dir: "./artifacts/mergen-run",
  timeout: 120
})
```

- `start_address` 是函数 **VA**，须落在目标映像中；地址优先使用字符串保留 64 位精度。
- `outline_addresses` 指定外部调用目标 VA；`enable_debug` 开启后端调试日志。
- 保存实际生成的 `output.ll`、可用的未优化 IR 和诊断结果。
- 面向函数级 x64 PE；自修改代码不受支持。VMP 3.8.x 有专项上游样本，3.6 为尽力支持。

## NoVmp

```js
native_devirtualize({ action: "status", backend: "novmp" })
native_devirtualize({
  action: "lift", backend: "novmp",
  path: "./artifacts/unpacked.exe",
  vms: ["0x12050"],
  image_base: "0x140000000",
  output_dir: "./artifacts/novmp-run",
  timeout: 120
})
```

- 输入为已解包的 VMP 3.0–3.5 x64 映像。
- `vms` 是 **VM 入口 RVA**；建议明确选择函数。`image_base` 在转储改变映像基址时提供原始基址。
- `sections` 指定实际保护节的前缀；`no_opt` 关闭优化；`strip_constant_obfuscation` 去除常量混淆。
- `experimental_recompile: true` 显式请求实验性原生重编译；该结果仍需独立执行验证。
- 保存真实 VTIL 产物和可用的实验性重编译 PE。

## 产物与边界

`status` 读取当前平台及后端可用性；`lift` 需要执行审批并在计划模式中受阻。工具有界运行分析后端，不运行样本自身。默认超时 120 秒，上限 600 秒。

产物包含路径、字节数和 SHA-256；指定输出路径保留已有文件，避免覆盖原始样本。异常、超时、缺失预期产物和后端失败会明确报告。IR/VTIL 是待复核证据；输出生成不等于完整恢复或行为等价。
