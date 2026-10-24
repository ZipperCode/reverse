import { describe, expect, it } from "bun:test";
import { resolveReverseCapabilities } from "../../src/extensibility/skill-tool-catalog";

describe("VMP backend readiness isolation", () => {
	it("keeps native recovery unavailable when only symbolic trace analysis is installed", () => {
		const capabilities = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [{ id: "triton", status: "installed" }],
			dapAdapters: [],
		});
		const byId = new Map(capabilities.map(capability => [capability.id, capability]));
		expect(byId.get("symbolic_trace_analysis")?.ready).toBe(true);
		expect(byId.get("vmp_dump_repair")?.ready).toBe(false);
		expect(byId.get("native_function_lifting")?.ready).toBe(false);
		expect(byId.get("vmp_legacy_devirtualization")?.ready).toBe(false);
	});

	it("does not advertise semantic recovery after installing only the dump/import repair backend", () => {
		const capabilities = resolveReverseCapabilities({
			platform: "win32",
			toolStatuses: [{ id: "vmpdump", status: "installed" }],
			dapAdapters: [],
		});
		const byId = new Map(capabilities.map(capability => [capability.id, capability]));
		expect(byId.get("vmp_dump_repair")?.ready).toBe(true);
		expect(byId.get("symbolic_trace_analysis")?.ready).toBe(false);
		expect(byId.get("native_function_lifting")?.ready).toBe(false);
		expect(byId.get("vmp_legacy_devirtualization")?.ready).toBe(false);
	});
});
