# reverse_capability

能力驱动运行时调度与环境能力查询工具。

## 作用

在逆向会话中原生发现、解析和查询高层逆向工程能力（如 APK 反编译、原生二进制调试、Android JNI 模拟、浏览器 CDP 动态调试、WebSocket 抓包、JS 反混淆、流量拦截等）的就绪状态、推荐内置原生工具、可用降级方案、受信安装命令以及安装后的调用指引。

## Actions

- `list`：列出能力目录中的所有标准能力、对应场景与推荐工具。
- `resolve`：解析当前主机环境的可用性状态（`ready` / `available_with_fallbacks` / `missing`），检查外部工具与降级工具就绪情况。
- `get`：按能力 ID 查询指定能力的详细描述、Why 分析、环境状态与安装/调用指引。

## 调度规范

1. 优先使用推荐的原生零配置内置工具（如 `android_package_inspect`、`r2_inspect`、`websocket_observe`）。
2. 当外部工具缺失时，执行受信 setupCommand（如 `reverse setup reverse apktool`）并在安装后按 `postInstallInvocation` 调用。
