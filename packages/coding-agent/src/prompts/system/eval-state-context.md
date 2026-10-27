<system-reminder>
Eval runtime state is host-retained, not reconstructed from transcript text.
{{#if stateSummary}}
{{stateSummary}}
{{else}}
No retained eval runtime is registered in this process. Eval variables, imports, and kernels referenced in earlier session history were not restored; re-run required setup before using them.
{{/if}}
Dead or absent kernel → re-run needed setup. Alive kernel → process available; required bindings still need current namespace verification after handoff or a failed cell. Reuse definitions confirmed present and initialize only missing dependencies after auditing partial side effects. Treat transcript and handoff definition lists as unverified until checked; code appearing in a failed cell establishes only the statements that actually executed. An omitted script path alone does not establish lost definitions. This snapshot reports runtime identity and observed bindings, not variable values.
</system-reminder>
