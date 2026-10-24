Execute custom Frida JavaScript scripts, hooks, and dynamic inspection against processes, devices, and remote hosts.

Capabilities:

1. Dynamic script execution & runtime hooks:
   - Run arbitrary user-authored Frida JavaScript via inline `script` or local `script_path` (mutually exclusive).
   - Full access to `Interceptor.attach`, `Java.perform`, `Java.use(...).method.implementation = ...`, `ObjC.classes`, `Memory.read*`, `Memory.write*`, and custom instrumentation without restrictions.
   - Pass script arguments via `script_args` (passed via `-P` / `--parameters JSON`, accessible inside the script via `Script.parameters` or global `parameters`).

2. Target selection:
   - Attach to existing process by PID: `pid: <number>`
   - Attach to existing process by name: `process: "<name>"`
   - Spawn new process: `spawn: "<path_or_package>"` (e.g. `com.example.app` or `/path/to/binary`). Resumes target execution automatically; pass `pause: true` (or `no_pause: false`) to leave the main thread paused via `--pause`.

3. Transport & connectivity:
   - Local system: default (omit device flags)
   - USB / connected emulator: `usb: true` (passes `-U`)
   - Specific device ID: `device: "<device_id>"` (passes `-D <device_id>`)
   - Remote frida-server host: `host: "<ip:port>"` (passes `-H <host>`), supports arbitrary remote network endpoints.

4. Quick observation & reconnaissance actions (`action` parameter):
   - `action: "devices"`: enumerate local and connected USB/remote devices (`frida-ls-devices`).
   - `action: "ps"`: list running processes (`frida-ps`), supports `usb: true`, `device`, `host`, `filter: "<text>"`, and `applications: true` (`-a`).
   - `action: "modules"` (or `"inspect"`): enumerate loaded modules/libraries in target process (`pid` or `process`).
   - `action: "trace"`: trace execution via custom script/script_path or built-in templates:
     - `template: "module_load"`: trace module loads across target lifetime.
     - `template: "exports"`: enumerate exported symbols of a target `module`.
     - `template: "jni_register"`: trace Android JNI `RegisterNatives` calls, capturing real Java class names, method names, signatures, and native function pointers with resolved module base and relative hex offsets. Automatically discovers `RegisterNatives` from `libart.so` symbols and real JNIEnv vtable index 215. Supports `module` or `symbol` override.
     - `template: "native_functions"`: trace native function calls with bounded argument decoding. Parameters: `symbol` / `symbols`, `offset` / `offsets`, `module`, `args_count` (default 4), `args_decode` (e.g. `{"0": "int", "1": "string"}`), `retval` (boolean), `backtrace` (`true`, `"accurate"`, `"fuzzy"`), `max_events`, `max_buffer_bytes`.
   - When `script`, `script_path`, or `spawn` is provided, `action` defaults to `"exec"`.

5. Native CLI pass-through:
   - `cli_args`: optional array of extra CLI arguments passed directly to the command (e.g. `["--runtime=v8", "--realm=native", "--pause"]`).

6. Execution control & artifacts:
   - `timeout`: execution watchdog timeout in seconds (default 30, no upper limit).
   - `max_bytes`: maximum stdout bytes captured before truncation (default 262144, no upper limit).
   - `to_artifact`: save complete output and script metadata to a session artifact.

<examples>
```
// Enumerate connected devices
frida(action: "devices")

// List application processes on USB device
frida(action: "ps", usb: true, applications: true)

// List loaded modules in a target process
frida(action: "modules", process: "com.example.app", usb: true)

// Spawn Android app on USB device and run hook script
frida(spawn: "com.example.app", usb: true, script_path: "hooks/trace_auth.js")

// Attach to running process by name and execute inline hook
frida(process: "com.example.app", usb: true, script: "Java.perform(function() { console.log('Attached'); });")

// Attach to local process by PID and execute script with arguments
frida(pid: 12345, script_path: "scripts/intercept.js", script_args: { verbose: true }, timeout: 15)

// Spawn binary on remote frida-server host with extra CLI arguments
frida(spawn: "/usr/local/bin/target_bin", host: "192.168.1.5:27042", script: "Interceptor.attach(Module.getGlobalExportByName('main'), { onEnter: function() { console.log('main reached'); } });", cli_args: ["--runtime=v8"])

// Trace Android JNI RegisterNatives bindings on USB device
frida(action: "trace", template: "jni_register", spawn: "com.example.app", usb: true)

// Trace native function calls with typed argument decoding and return value
frida(action: "trace", template: "native_functions", process: "target_process", symbol: "calculate_token", args_decode: { "0": "string", "1": "int" }, retval: true, max_events: 50)
```
</examples>
```
