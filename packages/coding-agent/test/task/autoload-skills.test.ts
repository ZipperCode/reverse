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
	});

	it("resolves autoloadSkills correctly for reverse vs non-reverse requests", () => {
		const mockReverseLab: Skill = {
			name: "reverse-lab",
			description: "Reverse lab orchestrator",
			filePath: "/skills/reverse-lab/SKILL.md",
			baseDir: "/skills/reverse-lab",
			source: "bundled",
		};
		const mockNativeBinary: Skill = {
			name: "native-binary-reverse",
			description: "Native binary reverse skill",
			filePath: "/skills/native-binary-reverse/SKILL.md",
			baseDir: "/skills/native-binary-reverse",
			source: "bundled",
		};
		const mockOtherSkill: Skill = {
			name: "other-skill",
			description: "Other skill",
			filePath: "/skills/other-skill/SKILL.md",
			baseDir: "/skills/other-skill",
			source: "bundled",
		};

		const session = {
			skills: [mockReverseLab, mockNativeBinary, mockOtherSkill],
		} as unknown as ToolSession;

		const taskAgent: AgentDefinition = {
			name: "task",
			description: "General subagent",
			systemPrompt: "test",
			source: "bundled",
		};

		expect(REVERSE_TASK_AUTOLOAD_SKILLS).toEqual(["reverse-lab", "native-binary-reverse"]);

		// Reverse task on task agent
		const reverseResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "reverse engineering of binary",
		});
		expect(reverseResult.autoloadSkills.map(s => s.name)).toEqual(["reverse-lab", "native-binary-reverse"]);

		// Normal task on task agent
		const normalResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "fix css layout bug",
		});
		expect(normalResult.autoloadSkills).toEqual([]);

		// Explicit autoloadSkills in request
		const explicitResult = resolveAutoloadSkills(session, taskAgent, {
			session,
			invocationKind: "task",
			assignment: "fix css layout bug",
			autoloadSkills: ["other-skill"],
		});
		expect(explicitResult.autoloadSkills.map(s => s.name)).toEqual(["other-skill"]);
	});
});
