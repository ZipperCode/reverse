Read-only Android device observation over fixed `adb` commands. It never accepts an arbitrary adb/shell command and never installs, pushes, pulls, reboots, or modifies the device.

Actions:
- `devices`: list attached devices and emulators (`adb devices -l`) with serial, state, and transport details. Start here when the device set is unknown.
- `packages`: list installed packages with APK paths (`pm list packages -f`). Optional `package` keeps only that exact application id.
- `processes`: list running processes (`ps -A -o PID,USER,NAME`). Optional `package` keeps lines mentioning that application id.
- `logcat`: dump the bounded logcat ring buffer (`logcat -d -v threadtime -t <lines>`). `lines` defaults to 200 (max 2000); optional `filter` is one tag with an optional priority, e.g. `ActivityManager` or `ActivityManager:I`.
- `props`: read system properties (`getprop`). Optional `filter` is a property key or prefix such as `ro.build`.
- `screencap`: capture a PNG (`exec-out screencap -p`) and save the raw bytes to an artifact. The result carries `artifactId`, `artifactPath`, and `bytes`; image bytes are never embedded in the text output.

Device selection:
- `serial` selects the target device. When exactly one device is attached it may be omitted; with several attached, `serial` is required and the tool never guesses.
- Unauthorized, offline, unavailable, missing, and multiple-device cases return structured `status` values (`device_unauthorized`, `device_offline`, `device_unavailable`, `device_not_found`, `device_required`) plus the attached-device list.
- `devices` lists all devices; it does not accept `serial`.

Input safety:
- `package` must be a dotted Android application id (e.g. `com.example.app`) and is applied locally, never spliced into a shell command.
- `filter` must be one logcat tag or one property key/prefix; spaces, shell metacharacters, and multiple filters are rejected.
- `lines` must be an integer from 1 to 2000. `timeout` defaults to 30 s (max 120 s).
- Output is capped by `max_bytes` (default 256 KiB, max 4 MiB; screencap default 16 MiB, max 64 MiB) and reported with `truncated: true` when capped.
- Use `read` on the screenshot `artifactPath` to view the PNG; the tool itself returns text plus artifact metadata.

When `adb` is not installed, returns `status: "missing_dependency"` with the trusted install hint for the platform and fallback actions such as `aapt2 dump badging` or `droidasc` for static APK inspection. Fallbacks are suggestions only; this tool does not execute them.

<examples>
```
adb_observe(action: "devices")
adb_observe(action: "packages", serial: "emulator-5554", package: "com.example.app")
adb_observe(action: "processes", serial: "emulator-5554", package: "com.example.app")
adb_observe(action: "logcat", serial: "emulator-5554", filter: "ActivityManager:I", lines: 300)
adb_observe(action: "props", serial: "emulator-5554", filter: "ro.build")
adb_observe(action: "screencap", serial: "emulator-5554")
```
</examples>
