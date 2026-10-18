/**
 * SSH Hosts Capability
 *
 * Canonical shape for SSH host entries, regardless of source format.
 */
import { defineCapability } from ".";
export const sshCapability = defineCapability({
    id: "ssh",
    displayName: "SSH Hosts",
    description: "SSH host entries for remote command execution",
    key: host => host.name,
    validate: host => {
        if (!host.name)
            return "Missing name";
        if (!host.host)
            return "Missing host";
        return undefined;
    },
});
