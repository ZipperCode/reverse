# deobfuscate

多引擎反混淆与程序综合工具，支持 Android DEX 常量折叠与字符串解密、IDA Pro 9+ 微代码控制流平坦化恢复与 MBA 化简、Dalvik 有界虚拟执行反混淆、以及 MBA 表达式的 AST 综合与 SMT 形式化等价验证。所有输入样本保持不变，产物与诊断报告写入独立工件目录。

## 安装

CLI 安装命令：
- `reverse setup reverse jadx-string-decrypt --execute`：安装 JADX 字符串解密与常量折叠插件。
- `reverse setup reverse d810-ng --execute`：配置 IDA Pro 9+ 的 d810-ng 微代码反混淆套件环境。
- `reverse setup reverse simplify --execute`：安装 CalebFenton/simplify Dalvik 有界虚拟执行引擎。
- `reverse setup reverse msynth --execute`：配置基于 Miasm 与 Z3 的 msynth MBA 形式化综合虚拟环境。
- `reverse setup reverse blackdex --execute`：准备 Android 设备端 BlackDex 动态脱壳 APK 资产。

TUI：通过 `/setup` → 逆向工程工具链，选择对应反混淆引擎确认安装。

相关能力 ID 包含 `bytecode_deobfuscation`、`native_cfg_deobfuscation` 与 `mba_simplification`。

## 引擎详情与调用范例

### 1. msynth (Mixed Boolean-Arithmetic 表达式综合与 SMT 验证)

针对符号执行、反编译或混淆算法中抽取出的 MBA 复杂算术/位运算表达式执行 AST 语法树化简与随机程序综合，并通过 Z3 SMT 求解器证明语义等价性。解析器采用安全递归下降算法，**严禁执行用户输入的 Python 代码或字符串 `eval()`**。

```js
// 探测 msynth 与 SMT 求解器环境
deobfuscate({ action: "status", backend: "msynth" })

// 经典 MBA 表达式形式化化简
deobfuscate({
  action: "analyze",
  backend: "msynth",
  expression: "(x ^ y) + 2 * (x & y)",
  bit_width: 32,
  verify_smt: true
})

// 位运算混合表达式化简
deobfuscate({
  action: "analyze",
  backend: "msynth",
  expression: "(x | y) - (x & y)",
  bit_width: 32,
  verify_smt: true
})
```

- `expression`：待化简的算术/位运算表达式（支持 `+`, `-`, `*`, `&`, `|`, `^`, `~`, `<<`, `>>` 与变量名）。
- `bit_width`：显式指定变量位宽（8, 16, 32, 64，默认 32 位）。
- `mode`：`"ast"`（基于规则与预计算 Oracle 的子树化简）或 `"synthesis"`（随机程序综合）。
- `verify_smt`：启用 Z3 bitvector SMT 形式化等价性验证（默认 `true`）。

### 2. jadx (Arsylk/jadx-string-decrypt 字符串解密与常量折叠)

基于 JADX 插件体系，在反编译阶段静态折叠编译期常量、还原静态密钥表、解密常见块加密字符串例程，并自动重写反射调用为直接调用。

```js
deobfuscate({
  action: "analyze",
  backend: "jadx",
  path: "./samples/obfuscated.apk",
  out: "./artifacts/jadx_deobf",
  fold_consts: true,
  decrypt_strings: true,
  deindirect_reflection: true,
  cipher: "AES/ECB/PKCS5Padding"
})
```

- `fold_consts`：将编译期数字和布尔表达式折叠为直接字面量。
- `decrypt_strings`：自动识别并解密块密码字符串解密器调用。
- `deindirect_reflection`：将可解析的反射调用重写为直接方法调用。
- `comments`：在反编译源码对应方法上方添加解密字符串明细注释。

### 3. d810-ng (IDA Pro 9+ 微代码反平坦化与 MBA 化简)

通过 IDA Pro 9+ 批处理模式启动独立暂存副本，调用 d810-ng 的 `D810State` 加载规则项目、启停微代码优化钩子，并采集目标函数优化前后的 Hex-Rays 伪代码。

```js
deobfuscate({
  action: "analyze",
  backend: "d810-ng",
  path: "./samples/target.i64",
  function: "0x140001000",
  unflattener: "ollvm",
  rules: ["mba", "ollvm", "cst_simplification", "predicates"],
  out: "./artifacts/d810_report.json"
})
```

- `function`：目标函数虚拟地址（十六进制字符串如 `"0x401000"`）或符号名称。
- `unflattener`：控制流反平坦化器类型：`"ollvm"`、`"tigress"`、`"approov"`、`"hodur"` 或 `"generic"`。
- `rules`：激活的微代码优化规则分类列表。
- 报告优化前后的伪代码行数；控制流与算法恢复结论通过独立实验验证。

### 4. simplify (CalebFenton/simplify Dalvik 有界虚拟执行)

通过独立的 Dalvik 虚拟机对 DEX 方法进行有界虚拟执行，执行常量传播、计算不透明谓词并剪除死分支。

```js
deobfuscate({
  action: "analyze",
  backend: "simplify",
  path: "./samples/classes.dex",
  out: "./artifacts/simplified.dex",
  include_types: ["Lcom/target/security/.*"],
  max_address_visits: 10000,
  max_method_visits: 1000,
  max_call_depth: 50,
  timeout: 180
})
```

- `include_types` / `exclude_types`：限定反混淆的目标包名或类正则表达式，避免全量执行导致耗时失控。
- `max_address_visits`：单条指令地址最大访问次数限制（默认 10000），防止死循环。
- `max_method_visits`：单个方法执行次数上限。
- 产生独立的清洗后 DEX 文件，校验 DEX 头部魔数并比对 SHA-256。

### 5. blackdex (Android 设备端 ART 动态脱壳)

通过 ADB 连接真实 Android 设备或虚拟机，自动化部署并启动 BlackDex 脱壳应用，轮询提取解密后的 DEX 文件并回传至主机。

```js
deobfuscate({
  action: "analyze",
  backend: "blackdex",
  package_name: "com.target.app",
  out: "./artifacts/blackdex_dump",
  wait_timeout_seconds: 60,
  auto_launch: true
})
```

- `package_name`：需要脱壳的目标 Android 应用程序包名。
- `device`：可选的 ADB 设备序列号（多设备连接时指定）。
- `wait_timeout_seconds`：等待目标应用初始化并生成内存 DEX 转储的超时时间。
- 自动从 Android R+（`/sdcard/Download/dexDump/<package>/`）或预-R（`/sdcard/Android/data/<pkg>/dump/<package>/`）检索并拉取全部产生的 DEX 镜像并完成完整性校验。

## 研究型参考声明

D810G（overkazaf/D810G，基于微代码四维反混淆研究）与 vmp-devirt（实验性原生去虚拟化原型）属于学术与逆向探索性质的参考实现，不纳入生产环境依赖目录。本工具链专注于具备确定性工程落地能力的开源实现。

## 审批权限与安全边界

- `action: "status"`：属于 `read` 审批层级，允许在计划模式（Plan Mode）中直接运行。
- `action: "analyze"`：属于 `exec` 审批层级，在计划模式中会被拦截，执行需要显式授权。
- 所有产物均写入独立的临时或工件目录，使用独占模式写出，严禁覆盖原始输入样本。
- 外部进程树调用均绑定超时中止与流式输出上限截断，杜绝后台进程泄露。
