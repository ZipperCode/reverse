# elf_inspect

基于 LIEF 与 SoFixer 的原生 ELF 深度检查、运行时内存转储与节区结构重建工具。针对 Android `.so` 共享库及 Linux ELF 二进制提供结构化查询、可控内存提取与可分析候选产物重建。

## 能力概览

1. **LIEF 结构化深度查询 (`query`)**：
   - 提取段表 (`PT_LOAD`, `PT_DYNAMIC`, `PT_GNU_RELRO`, `PT_ARM_EXIDX` 等) 与内存权限。
   - 解析初始化例程与构造函数（`.init_array` 指针序列、`DT_INIT` 入口及符号归属）。
   - 解析动态重定位表与 PLT/GOT 条目（类型统计、目标虚拟地址、加数与符号过滤）。
   - 双向虚拟内存地址到文件偏移映射（`address_map`），定位所属段与节区。
   - 导出与导入符号表解析。
2. **可控运行时内存转储 (`dump`)**：
   - 基于 Frida 附加至目标进程，执行只读内存读取（不向目标进程写入任何数据）。
   - 遍历已映射可读内存段，未映射空洞与不可读页使用零填充对齐，避免跨段盲读异常；若目标进程存在并发内存修改或页换出，清单将如实记录实际捕获字节范围。
   - 产出不可变原始转储工件，生成伴生来源清单 (`.manifest.json`)，记录 PID、基址、分段覆盖率与 SHA-256 哈希。
3. **SoFixer 节区与头部重建 (`repair`)**：
   - 针对从内存转储出的 `.so` 镜像（由于加载时重定位与节区剥离），调用原生 SoFixer 工具根据 `PT_LOAD` 内存结构重建节头表 (`Shdr`)。
   - 严格限制架构与布局：仅支持 Android ARM (armeabi-v7a) 与 ARM64 (arm64-v8a) 小端 (LSB) 镜像，且仅支持最低 `PT_LOAD` 虚拟偏移为 `0x0` 的标准 `ET_DYN` 共享库。非 ARM 架构或非零虚拟基址镜像将被直接拒绝，保留原始转储以防破坏。
   - 重建完成后自动通过 LIEF 实施结构化一致性校验：检验段对齐、Android 15+ 16KB 页对齐风险与重定位有效性。
   - 明确标记为**可分析候选产物（Analyzable Candidate）**，严禁误报为已恢复可执行状态。

## 安装与环境

- **LIEF**：
  - 依赖 Python 3.9+ 运行环境中的 `lief` 库；受管环境锁定 `1.0.0`。
  - CLI：`reverse setup reverse lief --execute`
  - TUI：`/setup` → 逆向工程工具链 → LIEF
- **SoFixer**：
  - 上游来源：`F8LEFT/SoFixer` (BSD-3-Clause)。包含 32 位 (`SoFixer32`) 与 64 位 (`SoFixer64`) 专用二进制。
  - CLI：`reverse setup reverse sofixer --execute`
  - TUI：`/setup` → 逆向工程工具链 → SoFixer
  - 通用 `SOFIXER_PATH` 按 64 位工具解析；32 位工具使用 `SOFIXER32_PATH` / `SOFIXER_32_PATH`，或名称包含 `32` 的专用可执行文件。
- **Frida**：
  - 运行时转储依赖宿主 PATH 中的 `frida` CLI 或受管环境。

检查当前工具链可用性：

```js
elf_inspect({ action: "status" })
```

## 调用示例

### 1. 深度查询构造函数 (`constructors`)

查询 `.init_array` 与初始化函数链：

```js
elf_inspect({
  action: "query",
  path: "samples/libnative-lib.so",
  query_type: "constructors"
})
```

### 2. 过滤查询动态重定位表 (`relocations`)

分页查询并过滤 `RELATIVE` 类型的重定位条目：

```js
elf_inspect({
  action: "query",
  path: "samples/libnative-lib.so",
  query_type: "relocations",
  filter: "RELATIVE",
  limit: 20
})
```

### 3. 地址与文件偏移双向映射 (`address_map`)

将静态链接时虚拟地址（Link-time VA / RVA）转换为文件偏移（若在运行时观察到动态 ASLR 地址，需先扣除模块加载基址换算为链接时 VA 后传入）：

```js
elf_inspect({
  action: "query",
  path: "samples/libnative-lib.so",
  query_type: "address_map",
  address: "0x19d510"
})
```

### 4. 运行时内存转储 (`dump`)

从已启动的目标 Android 应用或本地进程中转储指定 `.so` 模块：

```js
elf_inspect({
  action: "dump",
  pid: 14285,
  module: "libnative-lib.so",
  usb: true,
  max_bytes: 67108864
})
```

### 5. 重建转储镜像并执行结构校验 (`repair`)

基于转储工件与基址调用 SoFixer 重建节头表：

```js
elf_inspect({
  action: "repair",
  dump_path: "artifacts/dump-libnative-lib.so",
  base_address: "0x7f12340000",
  arch: "arm64",
  output_path: "analysis/libnative-lib.fixed.so"
})
```

### 6. 一键转储与重建流水线 (`dump_and_repair`)

```js
elf_inspect({
  action: "dump_and_repair",
  pid: 14285,
  module: "libnative-lib.so",
  usb: true,
  output_path: "analysis/libnative-lib.reconstructed.so"
})
```

## 参数参考

| 参数名 | 类型 | 说明 |
| :--- | :--- | :--- |
| `action` | string | 操作类型：`status`、`query`、`dump`、`repair`、`dump_and_repair`。 |
| `path` | string | 待检查 ELF 文件的路径（`query` 必填）。单文件上限 1 GiB。 |
| `query_type` | string | 查询类型：`info`、`segments`、`dynamic`、`constructors`、`relocations`、`sections`、`symbols`、`address_map`、`all`。默认 `info`。 |
| `filter` | string | 可选的不区分大小写子串过滤器。 |
| `limit` | number | 分页返回数量上限（默认 50，最大 500）。 |
| `offset` | number | 分页偏移量（默认 0）。 |
| `address` | string \| number | 虚拟地址（十六进制字符串或安全整数），用于 `address_map`。 |
| `file_offset` | string \| number | 文件偏移，用于 `address_map` 换算回虚拟地址。 |
| `pid` | string \| number | 目标进程 PID（`dump` 与 `dump_and_repair` 必填）。 |
| `module` | string | 目标模块名称，如 `libfoo.so`（`dump` 必填）。 |
| `device` | string | Frida 设备序列号或标识符。 |
| `usb` | boolean | 快捷选择 USB 设备 / 模拟器 (`-U`)。 |
| `host` | string | 远程 frida-server 地址（如 `192.168.1.5:27042`）。 |
| `max_bytes` | number | 转储内存上限字节（默认 64 MB，最大 256 MB）。 |
| `chunk_size` | number | 内存读取分块大小（默认 64 KB，最大 1 MB）。 |
| `dump_path` | string | 待修复的内存转储二进制路径（`repair` 必填）。 |
| `base_address` | string \| number | 内存加载基址十六进制字符串（如 `0x7f12340000`）。 |
| `arch` | string | 目标架构：`arm` / `32` 或 `arm64` / `64`。省略时自动从转储头部推断。 |
| `output_path` | string | 验证后候选产物的安全独占发布路径（拒绝静默覆盖已有文件）。 |
| `timeout` | number | 执行看门狗超时秒数（默认 60，上限 300）。 |

## 审批与安全规则

1. **分级审批**：
   - `status` 与 `query` 归为只读 (`read`) 审批层，在计划模式 (Plan Mode) 下开放。
   - `dump`、`repair` 与 `dump_and_repair` 涉及附加进程、提取内存与执行外部原生二进制，归为执行 (`exec`) 审批层，在计划模式下拦截。
2. **不可变与来源追踪**：
   - 原始转储工件一旦生成即保持不可变，伴随生成 `.manifest.json` 清单并保存 SHA-256。
   - 修复过程决不覆写转储文件，候选产物独立写入专属临时目录或用户指定的独占输出路径。
   - 发布转储及伴随清单时均拒绝覆盖已有文件或符号链接；清单发布失败会报错，已生成的独立转储仍保留。
3. **架构与布局安全防线**：
   - SoFixer 严格适用于 Android ARM32 / ARM64 小端共享库，且要求最低 `PT_LOAD` 虚拟基址为 `0x0`（标准 `ET_DYN` 布局）。非 ARM 二进制或非零 PT_LOAD 基址布局将被明确拦截并报错，保留原始转储供其他分析引擎处理。
4. **有效性诚实汇报**：
   - 重建产物经由 LIEF 校验有效后，才允许向 `output_path` 发布；未通过校验或缺少 LIEF 时明确报告风险，绝不向用户伪造“修复成功”保证。
