import { describe, expect, it } from "bun:test";
import { Settings } from "@reverse/coding-agent/config/settings";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { BashTool } from "@reverse/coding-agent/tools/bash";
import {
	checkProcessTerminationSafety,
	MANAGED_CANCELLATION_GUIDANCE,
} from "@reverse/coding-agent/tools/process-safety";

function createBashTool(isolatedSettings: Record<string, unknown> = {}): BashTool {
	const session = {
		cwd: "/tmp",
		hasUI: false,
		skills: [],
		getSessionFile: () => null,
		settings: Settings.isolated({
			"async.enabled": false,
			"bash.autoBackground.enabled": false,
			"bash.autoBackground.thresholdMs": 60_000,
			"bashInterceptor.enabled": false, // Even with interceptor disabled (yolo mode)
			...isolatedSettings,
		}),
	} as unknown as ToolSession;

	return new BashTool(session);
}

describe("Process Termination Safety Guard (#14)", () => {
	it("blocks taskkill with /IM, /im:, and -im", async () => {
		const cases = [
			"taskkill /IM java.exe",
			"taskkill /F /IM java.exe",
			"taskkill /im:notepad.exe /f",
			"taskkill -im java.exe",
			'taskkill "/IM" java.exe',
			'taskkill "/im:chrome.exe" /F',
			"taskkill /f /im:chrome.exe",
			"C:\\Windows\\System32\\taskkill.exe /IM java.exe",
		];
		for (const cmd of cases) {
			const res = await checkProcessTerminationSafety(cmd);
			expect(res.blocked).toBe(true);
			if (res.blocked) {
				expect(res.matchedPattern).toBe("taskkill /IM");
				expect(res.guidance).toBe(MANAGED_CANCELLATION_GUIDANCE);
				expect(res.unexecuted).toBe(true);
			}
		}
	});

	it("blocks killall and pkill variants", async () => {
		const cases = [
			"killall java",
			"killall -9 java",
			"killall -s KILL node",
			"/usr/bin/killall python3",
			"sudo killall java",
			"pkill java",
			"pkill -9 java",
			"pkill -f java",
			"pkill -0 java",
			"pkill -0 -9 java",
			"sudo pkill -u root java",
		];
		for (const cmd of cases) {
			const res = await checkProcessTerminationSafety(cmd);
			expect(res.blocked).toBe(true);
			if (res.blocked) {
				expect(["killall", "pkill"]).toContain(res.matchedPattern);
				expect(res.guidance).toBe(MANAGED_CANCELLATION_GUIDANCE);
				expect(res.unexecuted).toBe(true);
			}
		}
	});

	it("blocks PowerShell Stop-Process name termination and piped input", async () => {
		const cases = [
			"Get-Process java | Stop-Process -Force",
			"Get-Process -Name java | Stop-Process",
			"Get-Process | Stop-Process",
			"Stop-Process -Name java",
			"Stop-Process -ProcessName java -Force",
			"spps -Name java",
			"Stop-Process java", // positional non-numeric process name
		];

		for (const cmd of cases) {
			const res = await checkProcessTerminationSafety(cmd);
			expect(res.blocked).toBe(true);
			if (res.blocked) {
				expect(res.unexecuted).toBe(true);
				expect(res.guidance).toBe(MANAGED_CANCELLATION_GUIDANCE);
			}
		}
	});
	it("blocks wrapped/nested shell executions and compound chains", async () => {
		const cases = [
			'powershell -Command "Get-Process java | Stop-Process"',
			"pwsh -c 'Stop-Process -Name java'",
			"C:\\Windows\\System32\\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command 'killall java'",
			"bash -c 'killall java'",
			'sh -c "pkill -9 java"',
			"cmd /c 'taskkill /IM java.exe'",
			'C:\\Windows\\System32\\cmd.exe /c "taskkill /IM java.exe"',
			"cd /tmp && killall java",
			"ls -la; pkill java",
			"test -f app.jar || taskkill /IM java.exe",
		];
		for (const cmd of cases) {
			const res = await checkProcessTerminationSafety(cmd);
			expect(res.blocked).toBe(true);
			if (res.blocked) {
				expect(res.unexecuted).toBe(true);
			}
		}
	});

	it("does NOT block inert text, quoted docs, echo, or legitimate inspection commands", async () => {
		const safeCommands = [
			"echo 'taskkill /IM java.exe'",
			'echo "killall java"',
			"printf 'Stop-Process -Name java\\n'",
			"echo 'To stop java, run killall java in terminal'",
			"ps aux | grep java",
			"pgrep java",
			"pgrep -l java",
			'tasklist /FI "IMAGENAME eq java.exe"',
			"Get-Process java",
			"Get-Process java | Format-Table",
			"Get-Process java | Select-Object Id, ProcessName",
			"python3 -c 'print(\"killall\")'",
			"node -e 'console.log(\"taskkill\")'",
			"# killall java should not be used\necho safe",
		];
		for (const cmd of safeCommands) {
			const res = await checkProcessTerminationSafety(cmd);
			expect(res.blocked).toBe(false);
		}
	});

	it("BashTool returns explicit unexecuted structured error on blocked namekills", async () => {
		const tool = createBashTool();

		const result = await tool.execute("call-killall", { command: "killall java" });
		expect(result.isError).toBe(true);
		expect(result.details?.unexecuted).toBe(true);
		expect(result.details?.blockedReason).toContain("killall");
		expect(result.details?.guidance).toBe(MANAGED_CANCELLATION_GUIDANCE);

		const text = result.content.find(c => c.type === "text")?.text ?? "";
		expect(text).toContain("Execution blocked");
		expect(text).toContain("Guidance:");
		expect(text).toContain("Unexecuted command: killall in 'killall java'");
	});

	it("BashTool executes safe echo commands normally without interception", async () => {
		const tool = createBashTool();

		const result = await tool.execute("call-echo", { command: "echo 'To stop java run killall java'" });
		expect(result.isError).toBeUndefined();
		expect(result.details?.unexecuted).toBeUndefined();

		const text = result.content.find(c => c.type === "text")?.text ?? "";
		expect(text).toContain("To stop java run killall java");
	});

	it("blocks direct shell recursive deletion of tracked workspace paths or artifacts (#14)", async () => {
		const deletionCommands = [
			"rm -rf .reverse",
			"rm -r .reverse",
			"rm -rf .reverse/scripts",
			"rm -rf patch_artifacts",
			"rm -r .rea",
			"rmdir /s /q .reverse",
			"Remove-Item -Recurse -Force .reverse",
			"ri -r patch_artifacts",
		];

		for (const cmd of deletionCommands) {
			const res = await checkProcessTerminationSafety(cmd);
			expect(res.blocked).toBe(true);
			if (res.blocked) {
				expect(res.unexecuted).toBe(true);
				expect(res.reason).toContain("prohibited");
				expect(res.guidance).toContain("reverse_workspace");
			}
		}

		// Safe non-workspace deletions remain unblocked
		expect((await checkProcessTerminationSafety("rm test.txt")).blocked).toBe(false);
		expect((await checkProcessTerminationSafety("rm -rf /tmp/my_temp_dir")).blocked).toBe(false);
		expect((await checkProcessTerminationSafety("echo 'rm -rf .reverse'")).blocked).toBe(false);
	});

	it("blocks single-file direct deletion of protected artifacts and absolute POSIX paths (#14)", async () => {
		const projectDir = "/Users/zipper/test_proj";
		const protectedPaths = [
			"/Users/zipper/test_proj/.reverse",
			"/Users/zipper/test_proj/sample.bin",
			"/Users/zipper/test_proj/patch_artifacts/server.bin",
		];

		// 1. Single-file deletion of protected file (not recursive)
		const rmSingle = await checkProcessTerminationSafety(
			"rm sample.bin",
			undefined,
			0,
			projectDir,
			projectDir,
			protectedPaths,
		);
		expect(rmSingle.blocked).toBe(true);
		if (rmSingle.blocked) {
			expect(rmSingle.reason).toContain("Direct shell deletion");
			expect(rmSingle.matchedProtected).toContain("/Users/zipper/test_proj/sample.bin");
		}
		// 2. Absolute POSIX path recursive deletion
		const rmAbs = await checkProcessTerminationSafety(
			"rm -rf /Users/zipper/test_proj/patch_artifacts",
			undefined,
			0,
			projectDir,
			projectDir,
			protectedPaths,
		);
		expect(rmAbs.blocked).toBe(true);
		if (rmAbs.blocked) {
			expect(rmAbs.matchedProtected).toContain("/Users/zipper/test_proj/patch_artifacts/server.bin");
		}
		// 3. PowerShell single file deletion
		const rmPs = await checkProcessTerminationSafety(
			"Remove-Item sample.bin",
			undefined,
			0,
			projectDir,
			projectDir,
			protectedPaths,
		);
		expect(rmPs.blocked).toBe(true);

		// 4. Non-protected file deletion is NOT blocked
		const rmUnprotected = await checkProcessTerminationSafety(
			"rm other_scratch.txt",
			undefined,
			0,
			projectDir,
			projectDir,
			protectedPaths,
		);
		expect(rmUnprotected.blocked).toBe(false);
	});

	it("BashTool blocks direct rm -rf .reverse and directs to reverse_workspace clean", async () => {
		const tool = createBashTool();

		const result = await tool.execute("call-rm-ws", { command: "rm -rf .reverse" });
		expect(result.isError).toBe(true);
		expect(result.details?.unexecuted).toBe(true);
		expect(result.details?.guidance).toContain("reverse_workspace");

		const text = result.content.find(c => c.type === "text")?.text ?? "";
		expect(text).toContain("Execution blocked");
		expect(text).toContain("reverse_workspace");
	});
});
