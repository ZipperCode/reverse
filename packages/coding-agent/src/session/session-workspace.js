import * as os from "node:os";
import * as path from "node:path";
/** Expand a leading `~`/`~/` and resolve to an absolute path (relative input resolves against `base`). */
export function normalizeWorkspaceDirectory(directory, base) {
    let expanded = directory;
    if (expanded === "~") {
        expanded = os.homedir();
    }
    else if (expanded.startsWith("~/") || expanded.startsWith(`~${path.sep}`)) {
        expanded = path.join(os.homedir(), expanded.slice(2));
    }
    return base ? path.resolve(base, expanded) : path.resolve(expanded);
}
/**
 * Build a normalized {@link SessionWorkspace} from a cwd and optional
 * additional directories. Additional entries are normalized (relative entries
 * resolve against the normalized cwd), deduplicated, and appended after `cwd`
 * preserving their supplied order.
 */
export function normalizeSessionWorkspace(args) {
    const cwd = normalizeWorkspaceDirectory(args.cwd);
    const directories = [cwd];
    for (const directory of args.directories ?? []) {
        const normalized = normalizeWorkspaceDirectory(directory, cwd);
        if (!directories.includes(normalized))
            directories.push(normalized);
    }
    return { cwd, directories };
}
/** The workspace directories beyond `cwd`, in order (ACP `additionalDirectories` shape). */
export function additionalWorkspaceDirectories(workspace) {
    return workspace.directories.filter(directory => directory !== workspace.cwd);
}
