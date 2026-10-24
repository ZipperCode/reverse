# unidbg

管理 Unidbg 无头 ARM32/ARM64 CPU 模拟与 JNI 算法执行：生成参数化 Java Harness 脚手架、通过严格校验的 JDK 8 与 Maven 构建上游源码、拉起 Harness 并在进程内启动基于 SSE 的 McpServer，动态将模拟调试与自定义执行工具挂载进当前会话。

## 安装与发现

- CLI 安装：`reverse setup reverse unidbg`（按交互提示确认，自动克隆并编译上游源码）。
- TUI 入口：`/setup` → 逆向工程工具链 → Unidbg。
- 对应逆向能力：`android_native_emulation`。
- 独立 CLI 命令：`reverse unidbg [build|scaffold|launch|stop|status|probe]`。
- 方法指引：`skill://android-reverse`、`skill://reverse-lab`。

构建与执行**严格依赖 JDK 8 (Java 1.8)**。Java 9+ 引入的内置模块系统 `java.lang.Module` 与 Unidbg 核心包 `com.github.unidbg.Module` 存在类名冲突，无法在 JDK 9+ 下通过编译。可通过 `JAVA_HOME` 或 `javaHome` 参数指定 JDK 8 路径。

## 参数定义

| 参数 | 类型 | 适用动作 | 说明 |
| --- | --- | --- | --- |
| `action` | `scaffold \| build \| launch \| stop \| status \| probe` | 必填 | 执行的 Unidbg 操作。 |
| `type` | `jni \| ipa` | `scaffold`/`launch` 可选 | 模拟类型：`jni`（Android native 动态库，默认）或 `ipa`（iOS 应用包）。 |
| `target` | `string` | `scaffold`/`probe` 必填；`launch` 可选 | 目标二进制文件路径（`.so` 文件或 `.ipa` 包）。 |
| `entry` | `string` | `scaffold` 可选 | 目标函数入口名或 JNI native 方法名（如 `encrypt`、`calculateToken`）。 |
| `class` | `string` | `scaffold` 可选 | JNI Java 类名（如 `"com/example/Crypto"` 或 `"org/telegram/messenger/Utilities"`）。 |
| `signature` | `string` | `scaffold` 可选 | JNI 方法签名（如 `"([BI)[B"` 或 `"(Ljava/lang/String;)Ljava/lang/String;"`）。 |
| `arch` | `32 \| 64` | `scaffold`/`launch` 可选 | CPU 架构，`"32"` 或 `"64"`（默认 `"64"`）。 |
| `backend` | `unicorn2 \| dynarmic` | `scaffold`/`launch` 可选 | 模拟引擎后端（默认 `"unicorn2"`）。 |
| `port` | `number` | `scaffold`/`launch`/`stop` 可选 | McpServer SSE 监听端口（默认 `9239`）。 |
| `out` | `string` | `scaffold` 可选 | 生成的 Java Harness 源码文件保存路径。 |
| `overwrite` | `boolean` | `scaffold` 可选 | 生成脚手架时是否覆盖已有输出文件（默认 `false`）。 |
| `params` | `string` | `scaffold` 可选 | 逗号分隔的参数类型声明（如 `"bytes,int"`、`"int[],context"` 或 `"input:string"`）。 |
| `unidbgHome` | `string` | 可选 | Unidbg 源码根目录或安装路径（支持环境变量 `UNIDBG_HOME`）。 |
| `javaHome` | `string` | 可选 | JDK 8 安装根目录路径（支持环境变量 `JAVA_HOME`）。 |
| `mirror` | `aliyun \| default` | `build` 可选 | Maven 仓库镜像源（默认 `default`）。 |
| `skipTests` | `boolean` | `build` 可选 | 编译时是否跳过单元测试（默认 `true`）。 |
| `harness` | `string` | `launch` 必填 | 要启动的 Harness Java 源码路径（`.java`）或已编译类名。 |
| `timeoutMs` | `number` | `launch` 可选 | 等待 SSE 端点响应与健康检查的超时毫秒数（默认 `30000`）。 |
| `apk` | `string` | `scaffold`/`probe`/`launch` 可选 | 绑定的 APK 文件路径，用于包名/版本元数据与资源访问。 |
| `apiLevel` | `number` | `scaffold`/`probe` 可选 | Android API 级别（默认 `23`；上游 Unidbg 内置 `sdk19` 与 `sdk23` 依赖库）。 |
| `envProfile` | `string` | `scaffold`/`probe` 可选 | 显式环境配置文件路径或 JSON 字符串（自定义 JNI 覆盖与真实属性）。 |
| `callOnLoad` | `boolean` | `scaffold`/`probe` 可选 | 是否在加载后执行 `JNI_OnLoad`（默认 `true`）。 |

## 调用示例

### 1. 状态与环境探查 (`status`)

检查 JDK 8 有效性、Unidbg 检出与编译状态及当前活跃的 Harness 进程：
```js
unidbg({ action: "status" })
```

### 2. 生成 Java Harness 脚手架 (`scaffold`)

为指定 `.so` 生成参数化调用代码并保存至文件：
```js
unidbg({
  action: "scaffold",
  target: "./artifacts/extracted_so/libcrypto.so",
  type: "jni",
  class: "com/example/Crypto",
  entry: "encrypt",
  signature: "([BI)[B",
  params: "bytes,int",
  arch: "64",
  backend: "unicorn2",
  port: 9239,
  out: "./artifacts/Harness.java"
})
```

### 3. 源码编译与构建 (`build`)

使用验证的 JDK 8 编译 Unidbg 及其子模块（`unidbg-api`、`unidbg-android`、后端等）：
```js
unidbg({
  action: "build",
  javaHome: "/opt/jdk8",
  mirror: "aliyun",
  skipTests: true
})
```

### 4. 拉起 Harness 并挂载 MCP (`launch`)

运行 Harness，自动监听子进程输出并等待 SSE 服务就绪后，在当前会话内存中动态挂载调试工具与自定义执行工具：
```js
unidbg({
  action: "launch",
  harness: "./artifacts/Harness.java",
  target: "./artifacts/extracted_so/libcrypto.so",
  port: 9239,
  arch: "64",
  backend: "unicorn2",
  timeoutMs: 30000
})
```

成功拉起后，上游 McpToolkit 工具（寄存器状态、内存读写、单步调试、反汇编及针对 `entry` 生成的专用执行工具）自动注册进会话，供随后的逆向分析调用。

### 5. 终止与清理 (`stop`)

停止指定端口上的 Harness 进程并干净分离 MCP 连接：
```js
unidbg({ action: "stop", port: 9239 })
```
若省略 `port`，则停止当前会话持有的所有活动 Harness。


### 6. 无设备 JNI RegisterNatives 动态注册探查 (`probe`)

无需真机或模拟器设备，在无头 Unidbg 环境中加载目标 `.so`，Hook JNIEnv 虚表（Index 215）并在执行 `JNI_OnLoad` 时拦截真实的动态本地方法注册：
```js
unidbg({
  action: "probe",
  target: "./artifacts/extracted_so/libnative.so",
  apk: "./artifacts/app.apk",
  apiLevel: 23,
  arch: "64",
  backend: "unicorn2",
  out: "./artifacts/unidbg-registrations.json"
})
```

探查机制与保证：
1. **真实验证确认**：仅当底层 `RegisterNatives` 执行成功且 `retval === 0` 时标记 `status: "confirmed"`；失败则记录 `status: "rejected"`，不虚构注册事实。
2. **规范化输出**：输出事件结构与 Frida `jni_register_natives` 严格对齐，生成包含 `className`、`methodName`、`signature`、`functionAddress`、`moduleName`、`moduleBase` 与 `moduleOffset` 的规范化记录，产出的 JSON Artifact 可直接供 `ghidra_inspect` 与 JNI 静态富化工具使用。
3. **真实环境诊断**：支持通过 `envProfile` 传入显式环境参数（包名、路径、显式 JNI 覆盖）；对于未声明的服务或方法，输出真实诊断警告并上报缺失，绝不使用静默假 Context 掩盖依赖缺失。

### 7. 参数与数组类型支持

脚手架与 JNI 签名解析全面支持上游原生数组与对象类型：
- `int[]`（JNI `[I`）：映射为 Unidbg 原生 `com.github.unidbg.linux.android.dvm.array.IntArray`。
- `short[]`（JNI `[S`）：映射为 `ShortArray`。
- `float[]`（JNI `[F`）：映射为 `FloatArray`。
- `double[]`（JNI `[D`）：映射为 `DoubleArray`。
- `bytes` / `byte[]`（JNI `[B`）：映射为 `ByteArray`。
- `string[]`（JNI `[Ljava/lang/String;`）：映射为 `ArrayObject.newStringArray`。
- `context`（JNI `Landroid/content/Context;`）：显式解析为真实 `Context` 实例。
- 上游未包含的基元数组（如 `[Z`、`[J`、`[C`）明确报错并提示上游限制。

### 8. 显式环境配置文件 (`envProfile`) 规范

```json
{
  "packageName": "com.example.app",
  "appName": "ExampleApp",
  "versionName": "1.0.0",
  "versionCode": 1,
  "filesDir": "/data/data/com.example.app/files",
  "cacheDir": "/data/data/com.example.app/cache",
  "apiLevel": 23,
  "overrides": [
    {
      "signature": "com/example/Config->getApiKey()Ljava/lang/String;",
      "isStatic": false,
      "returnType": "string",
      "value": "custom-secret-token"
    },
    {
      "signature": "com/example/Security->checkFlag(I)Z",
      "isStatic": true,
      "returnType": "boolean",
      "value": true
    }
  ]
}
```
## 权限与会话安全隔离

- `status` 为只读探查操作 (`read`)。
- `scaffold` 为 Java Harness 源码生成操作 (`write`)。
- `build`、`launch`、`probe` 与 `stop` 为外部编译构建与进程执行/动态模拟操作 (`exec`)，受安全审批模式保护（`write` 审批模式下将触发提示确认）。
- 未知或缺省动作默认 fail-closed 归入 `exec` 审批层级。
- **会话级资源隔离**：通过 `launch` 启动的 Harness 进程与其 SSE MCP 挂载从属于发起调用的会话对象。会话结束或释放时，系统自动触发 `stopUnidbgHarness` 发送 `SIGTERM`（超时后升级为 `SIGKILL`），并断开 MCP 注册，杜绝后台残留孤儿进程或端口占用。
- **输入合法性保护**：脚手架参数对类名、方法名与入参做字符串转义与类型校验，防止源码注入。
