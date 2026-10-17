/**
 * Regression for a native build that installs an addon the host loader cannot
 * load. Ensures that an addon binary produced by the native build can be
 * successfully loaded by process.dlopen on the host platform, with version
 * verification and timeout protection against deadlocks.
 */
import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { detectHostAvx2Support, resolveLocalHostAddon } from "../../../scripts/host-detect";
import { hasVersionStampSlot, stampNativeVersion } from "../../../scripts/stamp-native-version";

export const ADDON_LOAD_FAILURE_EXPLANATION =
	"The build emitted an addon binary the host platform cannot load.\n" +
	"Check for dynamic linking against unavailable libraries, Mach-O/ELF alignment,\n" +
	"or target architecture mismatches.";

export async function verifyHostAddonLoads(
	destPath: string,
	timeoutMs: number = 10_000,
	expectedVersion?: string,
): Promise<void> {
	const versionCheck =
		expectedVersion === undefined
			? ""
			: `const reported = typeof m.exports.__piNativesBuildVersion === "function" ? m.exports.__piNativesBuildVersion() : undefined; ` +
				`if (reported !== ${JSON.stringify(expectedVersion)}) { console.error("addon reports build version " + JSON.stringify(reported) + ", expected " + ${JSON.stringify(JSON.stringify(expectedVersion))}); process.exit(1); }`;
	const probe =
		`const m = { exports: {} }; try { process.dlopen(m, ${JSON.stringify(destPath)}); } ` +
		"catch (error) { console.error(error && error.message ? error.message : String(error)); process.exit(1); } " +
		versionCheck;
	const proc = Bun.spawn([process.execPath, "-e", probe], { stdout: "ignore", stderr: "pipe" });
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		proc.kill("SIGKILL");
	}, timeoutMs);
	let exitCode: number;
	let stderr: string;
	try {
		[exitCode, stderr] = await Promise.all([proc.exited, new Response(proc.stderr).text()]);
	} finally {
		clearTimeout(timer);
	}
	const header = `built addon ${path.basename(destPath)} cannot be loaded on this host (${process.platform}-${process.arch})`;
	if (timedOut) {
		throw new Error(
			`${header}: loading did not finish within ${timeoutMs / 1000}s.\n${ADDON_LOAD_FAILURE_EXPLANATION}`,
		);
	}
	if (exitCode === 0) return;
	throw new Error(`${header}:\n${stderr.trim()}\n${ADDON_LOAD_FAILURE_EXPLANATION}`);
}

// x64 addon filenames carry an ISA suffix (-modern/-baseline), so the name must
// come from the same resolver the build uses, not `${platform}-${arch}`.
const hostAddon = path.join(
	import.meta.dir,
	"..",
	"native",
	resolveLocalHostAddon({ platform: process.platform, arch: process.arch, avx2: detectHostAvx2Support() }).filename,
);

async function failureOf(operation: Promise<void>): Promise<unknown> {
	return operation.then(
		() => undefined,
		(error: unknown) => error,
	);
}

describe("verifyHostAddonLoads", () => {
	test("rejects an installed addon the host loader refuses, naming the file and the loader message", async () => {
		const directory = await mkdtemp(path.join(tmpdir(), "rva-addon-load-"));
		const addon = path.join(directory, `pi_natives.${process.platform}-${process.arch}.node`);
		// Not a shared library: any host loader refuses it, which is the whole
		// class this guard exists for — bytes that install fine and load never.
		await writeFile(addon, "this is not a shared library\n");

		try {
			const failure = await failureOf(verifyHostAddonLoads(addon));

			expect(failure).toBeInstanceOf(Error);
			const message = failure instanceof Error ? failure.message : String(failure);
			expect(message).toContain(path.basename(addon));
			expect(message).toContain(`${process.platform}-${process.arch}`);
			const loaderOutput = message.split("\n").slice(1).join("\n").replace(ADDON_LOAD_FAILURE_EXPLANATION, "");
			expect(loaderOutput.trim()).not.toBe("");
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	});

	test("accepts the addon this checkout actually loads", async () => {
		expect(existsSync(hostAddon)).toBe(true);
		expect(await failureOf(verifyHostAddonLoads(hostAddon))).toBeUndefined();
	});

	// The compiled addon, not the Rust source, is the contract: a slot the stamp
	// tool can find and the addon then reports back. Skipped while the checkout
	// only has a prebuilt addon from before the stamp slot existed.
	test("requires the loaded addon to report the version stamped into it", async () => {
		expect(existsSync(hostAddon)).toBe(true);
		expect(hasVersionStampSlot(readFileSync(hostAddon))).toBe(true);
			const directory = await mkdtemp(path.join(tmpdir(), "rva-addon-load-"));
			const addon = path.join(directory, path.basename(hostAddon));
			try {
				await copyFile(hostAddon, addon);
				await stampNativeVersion(addon, "0.0.0-probe");

				expect(await failureOf(verifyHostAddonLoads(addon, undefined, "0.0.0-probe"))).toBeUndefined();
				const mismatch = await failureOf(verifyHostAddonLoads(addon, undefined, "9.9.9"));
				expect(mismatch instanceof Error ? mismatch.message : "").toContain(
					'addon reports build version "0.0.0-probe", expected "9.9.9"',
				);
			} finally {
				await rm(directory, { recursive: true, force: true });
			}
		},
	);

	// A FIFO with no writer blocks the loader's open() forever: a stand-in for
	// an addon whose init hangs. Windows has no FIFOs.
	test.skipIf(process.platform === "win32")(
		"fails a load that never finishes instead of hanging the build",
		async () => {
			const directory = await mkdtemp(path.join(tmpdir(), "rva-addon-load-"));
			const addon = path.join(directory, "pi_natives.hang.node");
			expect(Bun.spawnSync(["mkfifo", addon]).exitCode).toBe(0);

			try {
				const failure = await failureOf(verifyHostAddonLoads(addon, 500));

				expect(failure).toBeInstanceOf(Error);
				expect(failure instanceof Error ? failure.message : "").toContain("did not finish within 0.5s");
			} finally {
				await rm(directory, { recursive: true, force: true });
			}
		},
	);
});
