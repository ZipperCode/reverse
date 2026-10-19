# javascript_application

> Read-only static inspection and reconnaissance for JavaScript, Electron, and ASAR applications: package metadata, main/preload/renderer roles, IPC channels, native (.node) addons, security indicators, and external dependencies.

## Source
- Entry: `packages/coding-agent/src/tools/javascript-application.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/javascript-application.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `path` | `string` | Yes* | Path to target JavaScript / Electron directory, `.asar` archive, or `.zip` container (*or alias `target`). |
| `target` | `string` | No | Alternative alias for `path`. |
| `limit` | `number >= 1` | No | Maximum items per list to display (modules, IPC channels, native addons) (default 50, capped at 500). |
| `max_files` | `number >= 1` | No | Maximum JavaScript/TypeScript files to analyze (default 200, capped at 2000). |
| `include_node_modules` | `boolean` | No | Whether to include `node_modules` in file inventory and static analysis. Defaults to `false`. |
| `channel_filter` | `string` | No | Optional case-insensitive substring filter for IPC channel names. |

## Capabilities & Analysis
- **Package Metadata**: Reads and parses `package.json` at root or application entry; extracts package name, version, description, entrypoint (`main`), scripts, dependencies, devDependencies, and detected Electron version.
- **Electron Role Classification**:
  - **Main Process**: Entrypoints defined by `package.json.main`, or scripts importing core Electron desktop modules (`app`, `BrowserWindow`, `ipcMain`, `Menu`, `Tray`, `dialog`, `protocol`, `autoUpdater`).
  - **Preload Scripts**: Scripts exposing APIs via `contextBridge.exposeInMainWorld`, referencing `contextBridge`, or named with `preload`.
  - **Renderer**: HTML templates, scripts referencing DOM globals (`window`, `document`, `ReactDOM`, `createRoot`), scripts matching `*renderer*`, or scripts using `ipcRenderer` without `contextBridge`.
- **IPC Channel Extraction**:
  - Identifies channels used in `ipcRenderer.send`, `ipcRenderer.sendSync`, `ipcRenderer.invoke`, `ipcRenderer.postMessage`, `ipcMain.on`, `ipcMain.handle`, `webContents.send`, and `contextBridge.exposeInMainWorld`.
  - Reports channel name, direction (`send`, `invoke`, `handle`, `on`, etc.), API method, file path, and line number.
- **Native Addons (.node)**:
  - Detects compiled binary `.node` addons present in the container or directory.
  - Catalogs dynamic loader calls: `require("*.node")`, `bindings(...)`, `node-gyp-build`, and `process.dlopen`.
- **Security & Configuration Indicators**:
  - Audits high-risk Electron configurations: `nodeIntegration: true`, `contextIsolation: false`, `enableRemoteModule: true`, `webSecurity: false`, `allowRunningInsecureContent: true`, and `shell.openExternal`.
- **Top External Imports**:
  - Aggregates external module dependencies to reveal third-party runtime frameworks and libraries.

## Outputs
- Single model-facing text block summarizing detected package information, target container kind, file count, total size, process roles, IPC channels, native addons, top imports, and security indicators.
- Structured `details` object (`JavascriptApplicationDetails`) containing raw arrays and parsed metadata.

## Limits & Caps
- `DEFAULT_LIST_LIMIT = 50`, `MAX_LIST_LIMIT = 500`: List outputs are capped to avoid excessive token consumption.
- `DEFAULT_MAX_FILES = 200`, `MAX_FILES_LIMIT = 2000`: Caps maximum analyzed script files.
- `MAX_FILE_SCAN_BYTES = 5 MiB`: Skips oversized minified script files to avoid regular expression backtracking.
- `MAX_DIRECTORY_DEPTH = 15`: Bounded recursive directory walk.

## Side Effects
- Purely read-only; never executes target code, never runs arbitrary shell commands, and never mutates filesystem files.
- Direct parsing of `.asar` and `.zip` archives via `@reverse/utils/ar` without temporary disk unpacking.

## Tool Attributes
- `approval`: `"read"`
- `loadMode`: `"discoverable"`
- `strict`: `true`
