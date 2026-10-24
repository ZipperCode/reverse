#!/usr/bin/env bun
/**
 * Real-Device Verification Entrypoint
 *
 * Exercises explicit Android application security verification scenarios
 * on connected physical or emulator devices using `AppExperimentTool`.
 *
 * Safety & Inviolables:
 * - Requires explicit `--serial` and `--package`.
 * - Never resets the device, clears package data, or escalates to root.
 * - Emits structured results artifacts; marks acceptance as pending verification by default.
 * - Fails safely if target device is offline or unattached.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { parseArgs } from "node:util";
import { parseAndValidatePackageSetManifest } from "../src/reverse-workflow/package-set";
import { hashFileSha256 } from "../src/reverse-workflow/lineage";
import { Settings } from "../src/config/settings";
import { AppExperimentTool } from "../src/tools/app-experiment";
import type { ToolSession } from "../src/tools";

function printHelp(): void {
	console.log(`
Usage:
  bun run packages/coding-agent/scripts/device-experiment-verify.ts [options]

Required Options:
  --serial <serial>          Target device serial (e.g. emulator-5554, 192.168.1.5:5555)
  --package <package>        Target application id (e.g. com.example.app)

Optional Scenario Options:
  --scenario <name>          Verification scenario:
                               preflight  - Probe device connectivity and package flags (default)
                               deeplink   - Invoke benign deep link component
                               provider   - Query verified package ContentProvider URI
                               webview    - Discover DevTools sockets for package PID
                               storage    - Extract private sandbox data via run-as
                               smoke      - Safe non-destructive preflight triage
  --apk <path>               Target APK file path
  --package-set <path>       Target split package set path
  --uri <content-or-web-uri> ContentProvider content:// URI or deep link URI
  --component <name>         Component name (e.g. com.example.app/.MainActivity)
  --subpath <rel-path>       Relative sandbox subpath (default: shared_prefs)
  --output-dir <dir>         Artifact directory (default: ./artifacts/device_experiments)
  --help, -h                 Show this help message

Examples:
  # Check device preflight and package installation
  bun run packages/coding-agent/scripts/device-experiment-verify.ts --serial emulator-5554 --package com.example.app --scenario preflight

  # Verify deep link invocation on benign target
  bun run packages/coding-agent/scripts/device-experiment-verify.ts --serial emulator-5554 --package com.example.app --scenario deeplink --uri "myapp://test/home"

  # Query package-owned ContentProvider
  bun run packages/coding-agent/scripts/device-experiment-verify.ts --serial emulator-5554 --package com.example.app --scenario provider --uri "content://com.example.app.provider/items"
`);
}
export interface SampleIdentityRecord {
	kind: "single_apk" | "package_set" | "unspecified";
	sha256?: string;
	setSha256?: string;
	manifestSha256?: string;
	package?: string;
	versionCode?: string | number;
	members?: Array<{ name: string; size: number; sha256: string }>;
}

async function main(): Promise<void> {
	let values: {
		serial?: string;
		package?: string;
		scenario?: string;
		apk?: string;
		"package-set"?: string;
		uri?: string;
		component?: string;
		subpath?: string;
		"output-dir"?: string;
		help?: boolean;
	};
	try {
		const parsed = parseArgs({
			args: process.argv.slice(2),
			options: {
				serial: { type: "string" },
				package: { type: "string" },
				scenario: { type: "string", default: "preflight" },
				apk: { type: "string" },
				"package-set": { type: "string" },
				uri: { type: "string" },
				component: { type: "string" },
				subpath: { type: "string", default: "shared_prefs" },
				"output-dir": { type: "string", default: "./artifacts/device_experiments" },
				help: { type: "boolean", short: "h" },
			},
			allowPositionals: false,
		});
		values = parsed.values;
	} catch (err) {
		console.error(`Argument error: ${err instanceof Error ? err.message : String(err)}`);
		printHelp();
		process.exit(1);
	}
	if (values.help) {
		printHelp();
		process.exit(0);
	}

	if (!values.serial || !values.package) {
		console.error("Error: Both --serial and --package are required.\n");
		printHelp();
		process.exit(1);
	}

	const serial = values.serial.trim();
	const packageName = values.package.trim();
	const scenario = values.scenario ?? "preflight";
	const baseOutputDir = path.resolve(process.cwd(), values["output-dir"] ?? "./artifacts/device_experiments");

	await fs.mkdir(baseOutputDir, { recursive: true, mode: 0o700 });
	const runOutputDir = await fs.mkdtemp(path.join(baseOutputDir, "run-"));
	if (values.apk && values["package-set"]) {
		console.error("Error: --apk and --package-set are mutually exclusive. Specify only one.");
		process.exit(1);
	}

	// Consume --apk or --package-set sample identity
	let sampleIdentity: SampleIdentityRecord = { kind: "unspecified" };
	if (values.apk) {
		const apkPath = path.resolve(process.cwd(), values.apk);
		try {
			const st = await fs.stat(apkPath);
			if (!st.isFile()) {
				console.error(`Error: --apk '${values.apk}' is not a regular file.`);
				process.exit(1);
			}
			const sha256 = await hashFileSha256(apkPath);
			sampleIdentity = {
				kind: "single_apk",
				sha256,
			};
			console.log(`[Target Sample] Local sample SHA-256 (unverified on device): ${apkPath} (${sha256})`);
		} catch (err) {
			console.error(`Error reading --apk '${values.apk}': ${err instanceof Error ? err.message : String(err)}`);
			process.exit(1);
		}
	} else if (values["package-set"]) {
		const setTarget = path.resolve(process.cwd(), values["package-set"]);
		try {
			let manifestPath = setTarget;
			const st = await fs.stat(setTarget);
			if (st.isDirectory()) {
				manifestPath = path.join(setTarget, "package-set.json");
			}
			const validated = await parseAndValidatePackageSetManifest(manifestPath);
			sampleIdentity = {
				kind: "package_set",
				setSha256: validated.manifest.set_sha256,
				manifestSha256: validated.manifestSha256,
				package: validated.manifest.package,
				versionCode: validated.manifest.versionCode,
				members: validated.manifest.members.map(m => ({ name: m.name, size: m.size, sha256: m.sha256 })),
			};
			console.log(
				`[Target Sample] Local package-set manifest (unverified on device): ${manifestPath} (set_sha256: ${validated.manifest.set_sha256}, ${validated.manifest.members.length} members)`,
			);
		} catch (err) {
			console.error(
				`Error validating --package-set '${values["package-set"]}': ${err instanceof Error ? err.message : String(err)}`,
			);
			process.exit(1);
		}
	}

	const session: ToolSession = {
		cwd: process.cwd(),
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		allocateOutputArtifact: async prefix => {
			const id = `${prefix}_${Date.now()}`;
			const artifactPath = path.join(runOutputDir, `${id}.dat`);
			return { id, path: artifactPath };
		},
	};

	const tool = new AppExperimentTool(session);
	console.log(`[Device Verification] Initializing scenario '${scenario}' on ${serial} (${packageName})...`);

	let result;
	try {
		switch (scenario) {
			case "preflight":
			case "smoke": {
				result = await tool.execute("call-preflight", {
					action: "preflight",
					serial,
					package: packageName,
				});
				break;
			}
			case "deeplink": {
				if (!values.uri && !values.component) {
					console.error("Error: Scenario 'deeplink' requires --uri or --component.");
					process.exit(1);
				}
				result = await tool.execute("call-deeplink", {
					action: "invoke_component",
					serial,
					package: packageName,
					component: values.component,
					intent_action: values.uri ? "android.intent.action.VIEW" : undefined,
					intent_data: values.uri,
				});
				break;
			}
			case "provider": {
				if (!values.uri) {
					console.error("Error: --uri is required for scenario 'provider'.");
					process.exit(1);
				}
				result = await tool.execute("call-provider", {
					action: "query_provider",
					serial,
					package: packageName,
					uri: values.uri,
				});
				break;
			}
			case "webview": {
				result = await tool.execute("call-webview", {
					action: "webview_debug",
					serial,
					package: packageName,
					webview_op: "discover",
				});
				break;
			}
			case "storage": {
				result = await tool.execute("call-storage", {
					action: "extract_sandbox_data",
					serial,
					package: packageName,
					subpath: values.subpath ?? "shared_prefs",
				});
				break;
			}
			default: {
				console.error(`Unknown scenario: ${scenario}`);
				printHelp();
				process.exit(1);
			}
		}
	} catch (err) {
		console.error(
			`[Execution Error] Scenario '${scenario}' failed: ${err instanceof Error ? err.message : String(err)}`,
		);
		process.exit(2);
	}

	// Output text
	for (const item of result.content) {
		if (item.type === "text" && item.text) {
			console.log(item.text);
		}
	}
	const details = result.details;
	if (!details) {
		console.error("Error: Tool execution returned no details payload.");
		process.exit(1);
	}

	// Persist structured verification record (acceptance remains pending_verification)
	const isOk = details.status === "ok";
	const reportFile = path.join(runOutputDir, `verify_${scenario}.json`);
	const note = isOk
		? "Live device observation recorded. Experimental acceptance requires evidence verification."
		: `Device or dependency unavailable (${details.status}). No live observations recorded.`;

	const record = {
		timestamp: new Date().toISOString(),
		scenario,
		serial,
		package: packageName,
		status: details.status,
		acceptance: "pending_verification",
		note,
		sampleIdentity,
		details,
	};
	await fs.writeFile(reportFile, JSON.stringify(record, null, 2), { mode: 0o600 });
	console.log(`\nVerification artifact written: ${reportFile}`);

	if (!isOk) {
		const codeMap: Record<string, number> = {
			missing_dependency: 3,
			device_not_found: 4,
			device_offline: 4,
			device_unauthorized: 4,
			device_unavailable: 4,
			package_not_found: 5,
		};
		const exitCode = codeMap[details.status] ?? 1;
		process.exit(exitCode);
	}
}

if (import.meta.main) {
	main().catch(err => {
		console.error("Fatal error:", err);
		process.exit(1);
	});
}
