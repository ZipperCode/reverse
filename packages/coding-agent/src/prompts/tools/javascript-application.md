Read-only inspection and reconnaissance for JavaScript, Electron, and ASAR applications.

Directly analyzes directories, `.asar` archives, and `.zip` containers without executing target code or requiring external decompilation packages.

Capabilities:
- **Package Metadata**: Extracts `package.json` identity, version, main entrypoint, scripts, dependencies, devDependencies, and detected Electron version.
- **Electron Roles**: Identifies and classifies Main process, Preload scripts, and Renderer entrypoints/pages based on entrypoints, DOM usage, and Electron APIs (`app`, `BrowserWindow`, `contextBridge`, `ipcRenderer`, etc.).
- **IPC Channels**: Discovers inter-process communication channels (`ipcRenderer.send`, `ipcRenderer.invoke`, `ipcMain.handle`, `ipcMain.on`, `webContents.send`, `contextBridge.exposeInMainWorld`, etc.) with file and line locations.
- **Native Addons**: Catalogs binary `.node` addons inside the package as well as dynamic requires (`require("*.node")`, `bindings(...)`, `node-gyp-build`).
- **Security & Configuration Indicators**: Flags hazardous configurations such as `nodeIntegration: true`, `contextIsolation: false`, `enableRemoteModule: true`, `webSecurity: false`, and `shell.openExternal`.
- **Top Imports**: Aggregates external module dependencies to reveal third-party runtime frameworks and libraries.

Inputs:
- `path`: Path to target directory, `.asar` archive, or `.zip` container (also supports `target` alias).
- `limit`: Maximum entries to report in lists (default 50, max 500).
- `max_files`: Maximum JS/TS files to inspect (default 200, max 2000).
- `include_node_modules`: Whether to traverse third-party `node_modules` (default false).
- `channel_filter`: Optional substring filter for IPC channel names.

<examples>
```
javascript_application(path: "/path/to/resources/app.asar")
javascript_application(path: "./electron-app", channel_filter: "auth")
javascript_application(path: "./dist/app.asar", limit: 100)
```
</examples>
