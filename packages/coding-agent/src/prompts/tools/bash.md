Persistent shell: one fact command/pipeline; dependencies use `&&`.
{{#if hasEval}}Scripts/heredocs/`$(…)`/complex pipelines → `eval`.{{else}}Scripts/heredocs/`$(…)`/complex flow → dedicated tool or checked-in script.{{/if}}
`cwd`, not `cd`; `pty` only interactive.
Internal URIs work as paths for builtins/coreutils, redirects, globs.
{{#if asyncEnabled}}`async` defers finite results but keeps the deadline (default {{defaultTimeoutSec}}s); `timeout: 0` for watchers and long jobs.{{/if}}
No `head`/`tail`/redirection; output trunc by default, full result at `artifact://<id>`.
{{#if hasLaunch}}Long-lived services: unique name; ready requires name; no async/timeout; pty defaults true. ready needs log regex or port (both if given); host defaults 127.0.0.1, ready.timeout 30s.{{/if}}
{{#if autoBackgroundEnabled}}Non-`pty` calls still running after {{autoBackgroundSeconds}}s (or 1s before `timeout`, if sooner) usually move to background job `bg_N` and keep running to `timeout` (not when the client terminal runs the command or the job cap is reached); the result arrives automatically as a follow-up message. NEVER poll.{{/if}}
Process safety: broad executable-name process termination (`taskkill /IM`, `killall`, `pkill`, `Get-Process | Stop-Process`, `Stop-Process -Name`) is blocked before execution. Use tracked session/job cancellation (`proc://<id>/kill` or cancellation handles for owned tasks); external name-based process termination is prohibited. Embedded host calls to `tool.bash` are protected by the same guard; direct in-process arbitrary Python subprocess execution is an opaque runtime risk state.
