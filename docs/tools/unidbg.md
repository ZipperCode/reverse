# unidbg

管理 Unidbg 无头 ARM32/ARM64 CPU 模拟与 JNI 算法执行：生成参数化 Java Harness 脚手架、通过严格校验的 JDK 8 与 Maven 构建上游源码、拉起 Harness 并在进程内启动基于 SSE 的 McpServer，动态将模拟调试与自定义执行工具挂载进当前会话。

## 安装与发现

- CLI 安装：`reverse setup reverse unidbg`（按交互提示确认，自动克隆并编译上游源码）。
- TUI 入口：`/setup` → 逆向工程工具链 → Unidbg。
- 对应逆向能力：`android_native_emulation`。
- 独立 CLI 命令：`reverse unidbg [build|scaffold|launch|stop|status]`。
- 方法指引：`skill://android-reverse`、`skill://reverse-lab`。

构建与执行**严格依赖 JDK 8 (Java 1.8)**。Java 9+ 引入的内置模块系统 `java.lang.Module` 与 Unidbg 核心包 `com.github.unidbg.Module` 存在类名冲突，无法在 JDK 9+ 下通过编译。可通过 `JAVA_HOME` 或 `javaHome` 参数指定 JDK 8 路径。

## 参数定义

| 参数 | 类型 | 适用动作 | 说明 |
| --- | --- | --- | --- |
| `action` | `scaffold \| build \| launch \| stop \| status` | 必填 | 执行的 Unidbg 操作。 |
| `type` | `jni \| ipa` | `scaffold`/`launch` 可选 | 模拟类型：`jni`（Android native 动态库，默认）或 `ipa`（iOS 应用包）。 |
| `target` | `string` | `scaffold` 必填；`launch` 可选 | 目标二进制文件路径（`.so` 文件或 `.ipa` 包）。 |
| `entry` | `string` | `scaffold` 可选 | 目标函数入口名或 JNI native 方法名（如 `encrypt`、`calculateToken`）。 |
| `class` | `string` | `scaffold` 可选 | JNI Java 类名（如 `"com/example/Crypto"` 或 `"org/telegram/messenger/Utilities"`）。 |
| `signature` | `string` | `scaffold` 可选 | JNI 方法签名（如 `"([BI)[B"` 或 `"(Ljava/lang/String;)Ljava/lang/String;"`）。 |
| `arch` | `32 \| 64` | `scaffold`/`launch` 可选 | CPU 架构，`"32"` 或 `"64"`（默认 `"64"`）。 |
| `backend` | `unicorn2 \| dynarmic` | `scaffold`/`launch` 可选 | 模拟引擎后端（默认 `"unicorn2"`）。 |
| `port` | `number` | `scaffold`/`launch`/`stop` 可选 | McpServer SSE 监听端口（默认 `9239`）。 |
| `out` | `string` | `scaffold` 可选 | 生成的 Java Harness 源码文件保存路径。 |
| `overwrite` | `boolean` | `scaffold` 可选 | 生成脚手架时是否覆盖已有输出文件（默认 `false`）。 |
| `params` | `string` | `scaffold` 可选 | 逗号分隔的参数类型声明（如 `"bytes,int"` 或 `"input:string"`）。 |
| `unidbgHome` | `string` | 可选 | Unidbg 源码根目录或安装路径（支持环境变量 `UNIDBG_HOME`）。 |
| `javaHome` | `string` | 可选 | JDK 8 安装根目录路径（支持环境变量 `JAVA_HOME`）。 |
| `mirror` | `aliyun \| default` | `build` 可选 | Maven 仓库镜像源（默认 `default`）。 |
| `skipTests` | `boolean` | `build` 可选 | 编译时是否跳过单元测试（默认 `true`）。 |
| `harness` | `string` | `launch` 必填 | 要启动的 Harness Java 源码路径（`.java`）或已编译类名。 |
| `timeoutMs` | `number` | `launch` 可选 | 等待 SSE 端点响应与健康检查的超时毫秒数（默认 `30000`）。 |

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

## 权限与会话安全隔离

- `status` 为只读操作 (`read`)。
- `scaffold`、`build`、`launch` 与 `stop` 为写入与执行操作 (`write`)，受安全审批模式保护。
- **会话级资源隔离**：通过 `launch` 启动的 Harness 进程与其 SSE MCP 挂载从属于发起调用的会话对象。会话结束或释放时，系统自动触发 `stopUnidbgHarness` 发送 `SIGTERM`（超时后升级为 `SIGKILL`），并断开 MCP 注册，杜绝后台残留孤儿进程或端口占用。
- **输入合法性保护**：脚手架参数对类名、方法名与入参做字符串转义与类型校验，防止源码注入。
