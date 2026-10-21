# Custom Tools Examples

Example custom tools for reverse-coding-agent.

## Examples

Each example uses the `subdirectory/index.ts` structure required for tool discovery.

### hello/

Minimal example showing the basic structure of a custom tool. The factory
registers one tool named `hello` that takes a name and returns a greeting.

## Usage

reverse discovers custom tools in two places: `.reverse/tools/` in the current project
and `~/.reverse/agent/tools/` in your home directory. Both locations pick up `.ts`
and `.js` modules, plus any immediate subdirectory that contains an `index.ts`.

From this directory, install the example into one project:

```bash
mkdir -p /path/to/your-project/.reverse/tools
cp -r hello /path/to/your-project/.reverse/tools/
cd /path/to/your-project
reverse --tools hello
```

Or install it for every project (default profile):

```bash
mkdir -p ~/.reverse/agent/tools
cp -r hello ~/.reverse/agent/tools/
```

With a named profile (`REVERSE_PROFILE` or `--profile`), use that profile's tools
dir instead: `~/.reverse/profiles/<name>/agent/tools`.

`--tools` selects registered tool names, never file paths. `hello` is the name
the factory in `hello/index.ts` returns. Without the flag the tool is still
discovered and loaded alongside the built-in tools. `--tools hello` restricts
the session's tools to just `hello`, which keeps the demo focused but drops
built-ins such as `read` and `bash`; list them too (`--tools read,bash,hello`)
to keep them.

Then in reverse:

```
> greet Ada with the hello tool
```

## Writing Custom Tools

See [docs/custom-tools.md](../../../../docs/custom-tools.md) for full documentation.

### Key Points

**Factory pattern:**

```typescript
import { Text } from "@reverse/tui";
import type { CustomToolFactory } from "@reverse/coding-agent";

const factory: CustomToolFactory = pi => ({
	name: "my_tool",
	label: "My Tool",
	description: "Tool description for LLM",
	parameters: pi.zod.object({
		action: pi.zod.enum(["list", "add"]),
	}),

	// Called on session start/switch/branch/clear
	onSession(event) {
		// Reconstruct state from event.entries
	},

	async execute(toolCallId, params) {
		return {
			content: [{ type: "text", text: "Result" }],
			details: {/* for rendering and state reconstruction */},
		};
	},
});

export default factory;
```

**Custom rendering:**

```typescript
renderCall(args, options, theme) {
  return new Text(
    theme.fg("toolTitle", theme.bold("my_tool ")) + args.action,
    0, 0  // No padding - Box handles it
  );
},

renderResult(result, { expanded, isPartial }, theme) {
  if (isPartial) {
    return new Text(theme.fg("warning", "Working..."), 0, 0);
  }
  return new Text(theme.fg("success", "✓ Done"), 0, 0);
},
```

**Use `z.enum` for discriminated string tool args:**

```typescript
const z = pi.zod;

parameters: z.object({
	action: z.enum(["list", "add"]),
});
```
