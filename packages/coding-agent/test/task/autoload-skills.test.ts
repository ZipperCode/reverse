import { afterEach, describe, expect, it, type Mock, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import type { Skill } from "@reverse/coding-agent/extensibility/skills";
import * as skillsModule from "@reverse/coding-agent/extensibility/skills";
import type { CreateAgentSessionResult } from "@reverse/coding-agent/sdk";
import * as sdkModule from "@reverse/coding-agent/sdk";
import type { AgentSession, AgentSessionEvent, PromptOptions } from "@reverse/coding-agent/session/agent-session";
import { SKILL_PROMPT_MESSAGE_TYPE } from "@reverse/coding-agent/session/messages";
import * as discoveryModule from "@reverse/coding-agent/task/discovery";
import { runSubprocess } from "@reverse/coding-agent/task/executor";
import {
	isReverseTask,
	resolveAutoloadSkills,
	REVERSE_TASK_AUTOLOAD_SKILLS,
	runStructuredSubagent,
} from "@reverse/coding-agent/task/structured-subagent";
import type { AgentDefinition } from "@reverse/coding-agent/task/types";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { EventBus } from "@reverse/coding-agent/utils/event-bus";
import { createSessionDefaults } from "../helpers/session-defaults";

// ── Helpers ────────────────────────────────────────────────────────────────

function createMockSession(
	onPrompt: (params: {
		text: string;
		options?: PromptOptions;
		promptIndex: number;
		emit: (event: AgentSessionEvent) => void;
	}) => void,
): AgentSession {
	const listeners: Array<(event: AgentSessionEvent) => void> = [];
	let promptIndex = 0;
	const state = { messages: [] as unknown[] };

	const emit = (event: AgentSessionEvent) => {
		for (const listener of listeners) listener(event);
	};

	return {
		...createSessionDefaults(),
		state,
		agent: { state: { systemPrompt: ["test"] } },
		model: undefined,
		extensionRunner: undefined,
		sessionManager: {
			appendSessionInit: () => {},
		},
		getActiveToolNames: () => ["read", "yield"],
		getEnabledToolNames: () => ["read", "yield"],
		subscribe: (listener: (event: AgentSessionEvent) => void) => {
			listeners.push(listener);
			return () => {
				const index = listeners.indexOf(listener);
				if (index >= 0) listeners.splice(index, 1);
			};
		},
		prompt: async (text: string, options?: PromptOptions) => {
			promptIndex += 1;
			onPrompt({ text, options, promptIndex, emit });
			return true;
		},
		sendCustomMessage: vi.fn(async () => {}),
		getLastAssistantMessage: () => state.messages[state.messages.length - 1],
	} as unknown as AgentSession;
}

function createSessionResult(session: AgentSession): CreateAgentSessionResult {
	return {
		session,
		extensionsResult:
			{} as unknown as import("@reverse/coding-agent/extensibility/extensions/types").LoadExtensionsResult,
		setToolUIContext: () => {},
		eventBus: new EventBus(),
	};
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("autoloadSkills in executor", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	const baseAgent: AgentDefinition = {
		name: "task",
		description: "test",
		systemPrompt: "test",
		source: "bundled",
	};

	const baseOptions = {
		cwd: "/tmp",
		agent: baseAgent,
		task: "do work",
		index: 0,
		id: "subagent-1",
		settings: Settings.isolated(),
		modelRegistry: {
			refresh: async () => {},
		} as unknown as import("@reverse/coding-agent/config/model-registry").ModelRegistry,
		enableLsp: false,
	};

	it("calls sendCustomMessage for each autoloaded skill before prompt", async () => {
		const session = createMockSession(({ emit }) => {
			emit({
				type: "tool_execution_end",
				toolCallId: "tool-1",
				toolName: "yield",
				result: {
					content: [{ type: "text", text: "Result submitted." }],
					details: { status: "success", data: { ok: true } },
				},
				isError: false,
			});
		});

		vi.spyOn(sdkModule, "createAgentSession").mockResolvedValue(createSessionResult(session));

		const mockSkills: Skill[] = [
			{
				name: "user-created-skill-a",
				description: "Skill A",
				filePath: "/skills/user-created-skill-a/SKILL.md",
				baseDir: "/skills/user-created-skill-a",
				source: "user",
			},
			{
				name: "user-created-skill-b",
				description: "Skill B",
				filePath: "/skills/user-created-skill-b/SKILL.md",
				baseDir: "/skills/user-created-skill-b",
				source: "user",
			},
		];

		vi.spyOn(skillsModule, "buildSkillPromptMessage").mockImplementation(async skill => ({
			message: `Content of ${skill.name}\n\n---\n\nSkill: ${skill.filePath}`,
			details: {
				name: skill.name,
				path: skill.filePath,
				args: undefined,
				lineCount: 1,
			},
		}));

		await runSubprocess({
			...baseOptions,
			skills: mockSkills,
			autoloadSkills: mockSkills,
		});

		const sendCustomMessage = session.sendCustomMessage as Mock<any>;
		expect(sendCustomMessage).toHaveBeenCalledTimes(2);

		// Verify first skill
		expect(sendCustomMessage).toHaveBeenNthCalledWith(
			1,
			{
				customType: SKILL_PROMPT_MESSAGE_TYPE,
				content: expect.stringContaining("Content of user-created-skill-a"),
				display: false,
				details: { name: "user-created-skill-a", path: "/skills/user-created-skill-a/SKILL.md" },
			},
			{ triggerTurn: false },
		);

		// Verify second skill
		expect(sendCustomMessage).toHaveBeenNthCalledWith(
			2,
			{
				customType: SKILL_PROMPT_MESSAGE_TYPE,
				content: expect.stringContaining("Content of user-created-skill-b"),
				display: false,
				details: { name: "user-created-skill-b", path: "/skills/user-created-skill-b/SKILL.md" },
			},
			{ triggerTurn: false },
		);
	});

	it("does not call sendCustomMessage when autoloadSkills is empty", async () => {
		const session = createMockSession(({ emit }) => {
			emit({
				type: "tool_execution_end",
				toolCallId: "tool-1",
				toolName: "yield",
				result: {
					content: [{ type: "text", text: "Result submitted." }],
					details: { status: "success", data: { ok: true } },
				},
				isError: false,
			});
		});

		vi.spyOn(sdkModule, "createAgentSession").mockResolvedValue(createSessionResult(session));

		await runSubprocess(baseOptions);

		const sendCustomMessage = session.sendCustomMessage as Mock<any>;
		expect(sendCustomMessage).not.toHaveBeenCalled();
	});

	it("skill messages are sent before the task prompt", async () => {
		const callOrder: string[] = [];
		const session = createMockSession(({ emit }) => {
			emit({
				type: "tool_execution_end",
				toolCallId: "tool-1",
				toolName: "yield",
				result: {
					content: [{ type: "text", text: "Result submitted." }],
					details: { status: "success", data: { ok: true } },
				},
				isError: false,
			});
		});

		// Track sendCustomMessage call order
		(session.sendCustomMessage as Mock<any>).mockImplementation(async () => {
			callOrder.push("sendCustomMessage");
		});

		// Track the original prompt to capture order
		const originalPrompt = session.prompt;
		session.prompt = async (text: string, options?: PromptOptions) => {
			callOrder.push("prompt");
			return originalPrompt(text, options);
		};

		vi.spyOn(sdkModule, "createAgentSession").mockResolvedValue(createSessionResult(session));

		const mockSkill: Skill = {
			name: "user-created-skill",
			description: "A custom skill",
			filePath: "/skills/user-created-skill/SKILL.md",
			baseDir: "/skills/user-created-skill",
			source: "user",
		};

		vi.spyOn(skillsModule, "buildSkillPromptMessage").mockResolvedValue({
			message: "Skill content\n\n---\n\nSkill: /skills/user-created-skill/SKILL.md",
			details: { name: "user-created-skill", path: "/skills/user-created-skill/SKILL.md", lineCount: 1 },
		});

		await runSubprocess({
			...baseOptions,
			skills: [mockSkill],
			autoloadSkills: [mockSkill],
		});

		expect(callOrder).toEqual(["sendCustomMessage", "prompt"]);
	});
});

describe("autoloadSkills through task spawn", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("delivers a skill added after the parent session's skill list was loaded", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-late-skill-"));
		try {
			const baseDir = path.join(root, "late-skill");
			const filePath = path.join(baseDir, "SKILL.md");
			await fs.mkdir(baseDir);
			await Bun.write(
				filePath,
				"---\nname: late-skill\ndescription: Added after startup.\n---\n\nLate skill body.\n",
			);
			const lateSkill: Skill = {
				name: "late-skill",
				description: "Added after startup.",
				filePath,
				baseDir,
				source: "user",
			};

			let parentSkills: Skill[] = [];
			const refreshSkills = vi.fn(async () => {
				parentSkills = [lateSkill];
			});
			const parent = {
				cwd: root,
				hasUI: false,
				settings: Settings.isolated({ "task.isolation.enabled": false }),
				getSessionFile: () => null,
				getSessionSpawns: () => "*",
				getSessionAgents: () => [],
				getPlanModeState: () => undefined,
				get skills() {
					return parentSkills;
				},
				refreshSkills,
			} as unknown as ToolSession;

			vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({
				agents: [
					{
						name: "late-agent",
						description: "Autoloads a late skill",
						systemPrompt: "test",
						source: "project",
						autoloadSkills: ["late-skill"],
					},
				],
				projectAgentsDir: null,
			});
			const child = createMockSession(({ emit }) => {
				emit({
					type: "tool_execution_end",
					toolCallId: "tool-1",
					toolName: "yield",
					result: {
						content: [{ type: "text", text: "Result submitted." }],
						details: { status: "success", data: { ok: true } },
					},
					isError: false,
				});
			});
			vi.spyOn(sdkModule, "createAgentSession").mockResolvedValue(createSessionResult(child));

			await runStructuredSubagent({
				session: parent,
				invocationKind: "task",
				assignment: "do work",
				agent: "late-agent",
			});

			expect(refreshSkills).toHaveBeenCalledTimes(1);
			expect(child.sendCustomMessage).toHaveBeenCalledWith(
				expect.objectContaining({
					customType: SKILL_PROMPT_MESSAGE_TYPE,
					content: expect.stringContaining("Late skill body."),
				}),
				{ triggerTurn: false },
			);
		} finally {
			await fs.rm(root, { recursive: true, force: true });
		}
	});

	it("autoloads reverse-lab and native-binary-reverse for reverse tasks on task subagent", async () => {
		const mockReverseLab: Skill = {
			name: "reverse-lab",
			description: "Multi-platform reverse engineering orchestrator",
			filePath: "/skills/reverse-lab/SKILL.md",
			baseDir: "/skills/reverse-lab",
			source: "bundled",
		};
		const mockNativeBinary: Skill = {
			name: "native-binary-reverse",
			description: "Native binary reverse engineering skill",
			filePath: "/skills/native-binary-reverse/SKILL.md",
			baseDir: "/skills/native-binary-reverse",
			source: "bundled",
		};

		const parent = {
			cwd: "/tmp",
			hasUI: false,
			settings: Settings.isolated({ "task.isolation.enabled": false }),
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			getSessionAgents: () => [],
			getPlanModeState: () => undefined,
			skills: [mockReverseLab, mockNativeBinary],
		} as unknown as ToolSession;

		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({
			agents: [
				{
					name: "task",
					description: "General subagent",
					systemPrompt: "test",
					source: "bundled",
				},
			],
			projectAgentsDir: null,
		});

		vi.spyOn(skillsModule, "buildSkillPromptMessage").mockImplementation(async skill => ({
			message: `Content for ${skill.name}`,
			details: { name: skill.name, path: skill.filePath, lineCount: 1 },
		}));

		const child = createMockSession(({ emit }) => {
			emit({
				type: "tool_execution_end",
				toolCallId: "tool-1",
				toolName: "yield",
				result: {
					content: [{ type: "text", text: "Done" }],
					details: { status: "success", data: { ok: true } },
				},
				isError: false,
			});
		});
		vi.spyOn(sdkModule, "createAgentSession").mockResolvedValue(createSessionResult(child));

		// 1. Reverse task should autoload reverse skills
		await runStructuredSubagent({
			session: parent,
			invocationKind: "task",
			assignment: "分析目标 libtarget.so 的导出函数并进行逆向",
			agent: "task",
		});

		const sendCustomMessage = child.sendCustomMessage as Mock<any>;
		expect(sendCustomMessage).toHaveBeenCalledWith(
			expect.objectContaining({
				customType: SKILL_PROMPT_MESSAGE_TYPE,
				content: expect.stringContaining("Content for reverse-lab"),
			}),
			{ triggerTurn: false },
		);
		expect(sendCustomMessage).toHaveBeenCalledWith(
			expect.objectContaining({
				customType: SKILL_PROMPT_MESSAGE_TYPE,
				content: expect.stringContaining("Content for native-binary-reverse"),
			}),
			{ triggerTurn: false },
		);
	});

	it("does not autoload reverse skills for normal coding tasks on task subagent", async () => {
		const mockReverseLab: Skill = {
			name: "reverse-lab",
			description: "Multi-platform reverse engineering orchestrator",
			filePath: "/skills/reverse-lab/SKILL.md",
			baseDir: "/skills/reverse-lab",
			source: "bundled",
		};
		const mockNativeBinary: Skill = {
			name: "native-binary-reverse",
			description: "Native binary reverse engineering skill",
			filePath: "/skills/native-binary-reverse/SKILL.md",
			baseDir: "/skills/native-binary-reverse",
			source: "bundled",
		};

		const parent = {
			cwd: "/tmp",
			hasUI: false,
			settings: Settings.isolated({ "task.isolation.enabled": false }),
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			getSessionAgents: () => [],
			getPlanModeState: () => undefined,
			skills: [mockReverseLab, mockNativeBinary],
		} as unknown as ToolSession;

		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({
			agents: [
				{
					name: "task",
					description: "General subagent",
					systemPrompt: "test",
					source: "bundled",
				},
			],
			projectAgentsDir: null,
		});

		const child = createMockSession(({ emit }) => {
			emit({
				type: "tool_execution_end",
				toolCallId: "tool-1",
				toolName: "yield",
				result: {
					content: [{ type: "text", text: "Done" }],
					details: { status: "success", data: { ok: true } },
				},
				isError: false,
			});
		});
		vi.spyOn(sdkModule, "createAgentSession").mockResolvedValue(createSessionResult(child));

		// 2. Normal coding task should NOT autoload reverse skills
		await runStructuredSubagent({
			session: parent,
			invocationKind: "task",
			assignment: "fix typo in navigation bar and update css colors",
			agent: "task",
		});

		const sendCustomMessage = child.sendCustomMessage as Mock<any>;
		expect(sendCustomMessage).not.toHaveBeenCalled();
	});

	it("identifies reverse tasks accurately with isReverseTask", () => {
		expect(isReverseTask("reverse engineering of login routine")).toBe(true);
		expect(isReverseTask("decompile and inspect Android APK")).toBe(true);
		expect(isReverseTask("对二进制文件进行反编译")).toBe(true);
		expect(isReverseTask("inspect Mach-O export headers")).toBe(true);
		expect(isReverseTask("hook functions using frida script")).toBe(true);
		expect(isReverseTask("disassemble with radare2")).toBe(true);
		expect(isReverseTask("check libnative.so exports")).toBe(true);

		// Normal coding tasks should return false
		expect(isReverseTask("fix typo in index.html")).toBe(false);
		expect(isReverseTask("add new button to profile page")).toBe(false);
		expect(isReverseTask("refactor postgres sql query in user repository")).toBe(false);
		expect(isReverseTask("implement quicksort in typescript")).toBe(false);
		expect(isReverseTask("reverse a linked list in typescript")).toBe(false);
		expect(isReverseTask("reverse string order")).toBe(false);
		expect(isReverseTask("configure nginx reverse proxy for backend")).toBe(false);
		expect(isReverseTask("sort array in reverse order")).toBe(false);
		expect(isReverseTask("upload build assets to cloudflare r2 bucket")).toBe(false);
		expect(isReverseTask("实现二进制转十六进制转换工具")).toBe(false);
		expect(isReverseTask("二分查找算法优化")).toBe(false);
		expect(isReverseTask("处理 WebSocket 二进制流 ArrayBuffer")).toBe(false);
		// Reverse tasks including HAR/authz, APK, and AndroidManifest.xml
		expect(isReverseTask("analyze captured HAR trace for API authz tokens and authentication headers")).toBe(true);
		expect(isReverseTask("reverse sample target.apk and decompile manifest")).toBe(true);
		expect(isReverseTask("triage AndroidManifest.xml for exported components")).toBe(true);
		expect(isReverseTask("unpack DEX memory using dex_unpack and repair with dex_repair")).toBe(true);
		expect(isReverseTask("search classes with dex_search and dexkit")).toBe(true);
		expect(isReverseTask("deobfuscate OLLVM control-flow flattening and MBA expressions")).toBe(true);
		expect(isReverseTask("capture instruction trace with instruction_trace and recover with native_recover")).toBe(
			true,
		);
	});

	it("resolves autoloadSkills correctly with method- and target-aware selection", () => {
		const makeMockSkill = (name: string): Skill => ({
			name,
			description: `${name} mock skill`,
			filePath: `/skills/${name}/SKILL.md`,
			baseDir: `/skills/${name}`,
			source: "bundled",
		});

		const mockReverseLab = makeMockSkill("reverse-lab");
		const mockAndroidReverse = makeMockSkill("android-reverse");
		const mockNativeBinary = makeMockSkill("native-binary-reverse");
		const mockWebProtocol = makeMockSkill("web-protocol-reverse");
		const mockVmpReverse = makeMockSkill("vmp-reverse");
		const mockOtherSkill = makeMockSkill("other-skill");
		const mockWindowsReverse = makeMockSkill("windows-reverse");

		const session = {
			skills: [
				mockReverseLab,
				mockAndroidReverse,
				mockNativeBinary,
				mockWebProtocol,
				mockVmpReverse,
				mockOtherSkill,
				mockWindowsReverse,
			],
		} as unknown as ToolSession;

		const taskAgent: AgentDefinition = {
			name: "task",
			description: "General subagent",
			systemPrompt: "test",
			source: "bundled",
		};

		expect(REVERSE_TASK_AUTOLOAD_SKILLS).toEqual(["reverse-lab"]);

		// 1. APK task loads Android, NOT unnecessary native
		const apkResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "decompilation of sample.apk and inspect manifest",
		});
		const apkNames = apkResult.autoloadSkills.map(s => s.name);
		expect(apkNames).toContain("reverse-lab");
		expect(apkNames).toContain("android-reverse");
		expect(apkNames).not.toContain("native-binary-reverse");

		// 1b. AndroidManifest.xml task loads Android without native
		const manifestResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "triage AndroidManifest.xml for exported components and permissions",
		});
		const manifestNames = manifestResult.autoloadSkills.map(s => s.name);
		expect(manifestNames).toContain("reverse-lab");
		expect(manifestNames).toContain("android-reverse");
		expect(manifestNames).not.toContain("native-binary-reverse");
		// 2. APK task with JNI evidence adds native
		const jniResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "reverse target.apk, investigate JNI native methods in libcore.so",
		});
		const jniNames = jniResult.autoloadSkills.map(s => s.name);
		expect(jniNames).toContain("reverse-lab");
		expect(jniNames).toContain("android-reverse");
		expect(jniNames).toContain("native-binary-reverse");

		// 3. HAR / API authz task loads web
		const harResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "analyze captured HAR trace for API authz tokens and authentication headers",
		});
		const harNames = harResult.autoloadSkills.map(s => s.name);
		expect(harNames).toContain("reverse-lab");
		expect(harNames).toContain("web-protocol-reverse");
		expect(harNames).not.toContain("android-reverse");
		expect(harNames).not.toContain("native-binary-reverse");

		// 3b. Generic network replay task without device markers loads web, NOT Android
		const replayResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "network_replay comparison against allowed_origins baseline",
		});
		const replayNames = replayResult.autoloadSkills.map(s => s.name);
		expect(replayNames).toContain("reverse-lab");
		expect(replayNames).toContain("web-protocol-reverse");
		expect(replayNames).not.toContain("android-reverse");
		// 4. VMP devirtualization task loads VMP
		const vmpResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "analyze VMProtect virtualization trace and devirtualize bytecode handlers",
		});
		const vmpNames = vmpResult.autoloadSkills.map(s => s.name);
		expect(vmpNames).toContain("reverse-lab");
		expect(vmpNames).toContain("vmp-reverse");

		// 5. Pure native binary task loads native
		const nativeResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "reverse engineering of binary",
		});
		const nativeNames = nativeResult.autoloadSkills.map(s => s.name);
		expect(nativeNames).toContain("reverse-lab");
		expect(nativeNames).toContain("native-binary-reverse");

		// 5b. Android DEX unpack & repair task loads android-reverse without native
		const dexUnpackResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "unpack memory DEX using dex_unpack and repair stub methods via dex_repair",
		});
		const dexUnpackNames = dexUnpackResult.autoloadSkills.map(s => s.name);
		expect(dexUnpackNames).toContain("reverse-lab");
		expect(dexUnpackNames).toContain("android-reverse");
		expect(dexUnpackNames).not.toContain("native-binary-reverse");
		expect(dexUnpackNames).not.toContain("windows-reverse");

		// 5c. Android Custom VMP loads Android, Native, and VMP without loading Windows
		const androidVmpResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment:
				"reverse Android custom VMP protection in libcore.so, devirtualize handlers with instruction_trace and native_recover",
		});
		const androidVmpNames = androidVmpResult.autoloadSkills.map(s => s.name);
		expect(androidVmpNames).toContain("reverse-lab");
		expect(androidVmpNames).toContain("android-reverse");
		expect(androidVmpNames).toContain("native-binary-reverse");
		expect(androidVmpNames).toContain("vmp-reverse");
		expect(androidVmpNames).not.toContain("windows-reverse");

		// 5d. Native OLLVM & MBA deobfuscation loads native and vmp without Android or Windows
		const ollvmResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment:
				"deobfuscate OLLVM control-flow flattening and MBA expressions in sample.elf using native_recover and deobfuscate",
		});
		const ollvmNames = ollvmResult.autoloadSkills.map(s => s.name);
		expect(ollvmNames).toContain("reverse-lab");
		expect(ollvmNames).toContain("native-binary-reverse");
		expect(ollvmNames).toContain("vmp-reverse");
		expect(ollvmNames).not.toContain("android-reverse");
		expect(ollvmNames).not.toContain("windows-reverse");

		// 6. Normal non-reverse task on task agent
		const normalResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "fix css layout bug",
		});
		expect(normalResult.autoloadSkills).toEqual([]);

		// 7. Explicit autoloadSkills in request honored
		const explicitResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "fix css layout bug",
			autoloadSkills: ["other-skill"],
		});
		expect(explicitResult.autoloadSkills.map(s => s.name)).toEqual(["other-skill"]);
	});
});
