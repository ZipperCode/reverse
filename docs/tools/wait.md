# wait

> Block until the next background result, peer message, or steering interrupt when there is no other work to do.

## Source

- Entry: `packages/coding-agent/src/tools/wait.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/wait.md`
- Job delivery: `packages/coding-agent/src/async/job-manager.ts`

## Input and availability

`wait` has no arguments. It is an essential, read-approved, interruptible tool available when async jobs, peer messaging, or supervised services are enabled; it does not select a particular peer or job.

## Behavior

- Returns on the first settled caller-owned job or incoming peer message. Job results delivered by this call are consumed so no duplicate async-result follows.
- A steering/tool interrupt returns `Wait interrupted by message.` with `details.interrupted=true`; other aborts propagate. Handle the incoming notice before calling `wait` again.
- Every wait has a 30-minute safety cap. There is no caller-selectable timeout.
- With no owned job or service running, `wait` blocks for a reply when the caller sent a direct message (not a broadcast) during its current run to an agent that has not answered it since and is still running. The agent answers by messaging the caller back, or by settling a job of it the caller owns (its spawn job, or the job of a turn the caller's message woke), which delivers its result. Any incoming message ends it, a woken subagent's relayed turn output included. It also ends, without an error, once no agent asked can still answer: each one finished its turn without replying, or is blocked on the caller (a `wait` only the caller's result can end, entered after the question; an inline `task` spawn of it; an untimed eval handle wait on it). A reply that cannot come is what would park both sides.
- A `?progress` message from an agent asked is not its answer: it ends the current wait like any message, but a later `wait` keeps blocking for that agent while it is still live (even idle), and from then on only an explicit message answers — not a settled job of the turn that sent the progress.
- Otherwise returns immediately with “Nothing to wait for”, naming any agent asked that finished without replying or cannot reply before the caller finishes.
- With no owned jobs, a service finishing returns a notice directing the caller to `proc://` for status/output; with jobs, the call returns their current snapshot/result instead.
- Results and peer messages also auto-deliver without calling `wait`. Continue useful work instead of polling.
- Queued peer messages are checked first. Already-settled but undelivered owned jobs are returned without another wait. A wake already queued before execution still lets `wait` drain its message or owned job instead of being skipped; host-owned notices inject at the next boundary after the normal wait result. If a peer message wins a race with job completion, that job remains eligible for normal async delivery.
- Job waits emit progress snapshots every 500 ms when an update callback is present. Job results/snapshots use `details: { op: "wait", jobs: ... }`; peer-message results use the messaging result shape.
- A running subagent's row carries its latest progress, e.g. ``- `AcpSurface` [task] — <label> — 5h7m · 90 req · $18.40 · ctx 160K/1M · stage: <stage>``: run time, requests, cost, context fill, self-estimated completion and stage, whichever its progress record reports. Bash and eval rows, and task rows without a progress record, stay ``- `<id>` [<type>] — <label>``. `read proc://` and `read proc://<id>` show the same progress on running task rows.
- While caller-owned asynchronous work is pending, bare `bash true`, `bash :`, and empty commands are intercepted before spawning. Unchanged running `agent://` progress is returned once per generation/progress snapshot; later identical reads return structured `details.waitPollGuard` guidance with `useless: true`. Two consecutive no-progress polls request the existing forced `wait` tool choice. Meaningful progress, completed output, and a new user prompt remain readable; unrelated agents and compound shell commands are unaffected.
- While caller-owned work remains pending, an explicit first-person/current-turn declaration to end the reply without tools holds every tool call in that same assistant batch as unexecuted and ends the turn without another model request. This bounded grammar covers the historical “We must stop. End reply with no tool call. I'll do that.” and “I must end reply without tool call. Let's do that.” declarations, plus direct Chinese equivalents; quoted examples, code, historical/conditional/negated statements, and other agents' jobs do not activate it. Independent work without a stop declaration remains dispatchable.
- Preflight-blocked calls retain synthetic tool results and structured reasons but emit no `tool_execution_start`; waiting acceptance counts those raw event/journal records. A sole real `wait` produces one start and consumes the actual completion or interrupt through the normal delivery path.

## Related surfaces

- `read proc://` lists caller-visible jobs and project services; `read proc://<id>` inspects state/output without consuming delivery.
- `write proc://<id>/kill` cancels a job or owned subagent, or stops a service; no `content` needed. Bare `proc://<id>` writes send stdin only to a service, including empty input.
- `write agent://<id>` sends a peer message; `agent://all` broadcasts to visible live peers. Bare `read history://` discovers registered agent transcripts. The final result of a subagent is delivered to its parent automatically.
- Start supervised services with `bash` `name` and optional `ready`; inspect and control them through `proc://`.
