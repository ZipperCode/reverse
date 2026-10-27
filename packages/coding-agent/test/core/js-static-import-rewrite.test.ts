import { describe, expect, it } from "bun:test";

import { rewriteImports, wrapCode } from "@reverse/coding-agent/eval/js/context-manager";
import { indirectEval } from "@reverse/coding-agent/eval/js/shared/indirect-eval";

// Test fixtures embed user-supplied `import(...)` syntax that the rewriter must
// transform. The strings are split so static-analysis heuristics don't read them
// as real imports in this file.
const IMPORT = "import";
const dyn = (rest: string) => `${IMPORT}${rest}`;

describe("rewriteImports", () => {
	it("does not let a source filename inject executable lines", () => {
		const filename = 'cell.js\nthrow new Error("filename executed")';
		expect(indirectEval("40 + 2", filename)).toBe(42);
	});

	it("rewrites a top-level default import", async () => {
		const out = await rewriteImports(`${IMPORT} foo from "bar";\nconsole.log(foo);`);
		expect(out).toContain('await __reverse_import__("bar")');
		expect(out).not.toContain(`${IMPORT} foo from "bar"`);
	});

	it("rewrites destructured named imports with renames", async () => {
		const out = await rewriteImports(`${IMPORT} { foo, bar as baz } from "pkg";`);
		expect(out).toContain('await __reverse_import__("pkg")');
		expect(out).toContain("foo");
		expect(out).toContain("bar: baz");
	});

	it("rewrites namespace imports", async () => {
		const out = await rewriteImports(`${IMPORT} * as ns from "pkg";`);
		expect(out).toContain('const ns = await __reverse_import__("pkg")');
	});

	it("rewrites combined default + namespace", async () => {
		const out = await rewriteImports(`${IMPORT} def, * as ns from "pkg";`);
		expect(out).toContain('const ns = await __reverse_import__("pkg")');
		expect(out).toContain("const def = ns.default");
	});

	it("rewrites combined default + named", async () => {
		const out = await rewriteImports(`${IMPORT} def, { foo, bar as baz } from "pkg";`);
		expect(out).toContain('await __reverse_import__("pkg")');
		expect(out).toContain("default: def");
		expect(out).toContain("bar: baz");
	});

	it("rewrites side-effect-only imports", async () => {
		const out = await rewriteImports(`${IMPORT} "polyfill";`);
		expect(out).toContain('await __reverse_import__("polyfill")');
	});

	it("preserves import attributes via the dynamic import options bag", async () => {
		const out = await rewriteImports(`${IMPORT} data from "./d.json" with { type: "json" };`);
		expect(out).toContain('await __reverse_import__("./d.json", { with: { type: "json" } })');
		expect(out).toContain("const data =");
	});

	// Dynamic `import(...)` callees are swapped for a shim that prefers the worker-injected
	// `__reverse_import__` helper but falls back to native dynamic import. The fallback matters:
	// puppeteer serializes functions with `Function.prototype.toString()` and re-evaluates
	// them inside the browser page, where the helper global does not exist.
	const SHIM = '(typeof __reverse_import__ === "function" ? __reverse_import__ : (s, o) => import(s, o))';

	it("rewrites bare dynamic import() so its specifier resolves against the session cwd", async () => {
		const out = await rewriteImports(`const m = await ${dyn('("./foo.ts")')};`);
		expect(out).toContain(`await ${SHIM}("./foo.ts")`);
		expect(out).not.toContain(dyn('("./foo.ts")'));
	});

	it("rewrites dynamic import() with an options bag (passes options through unchanged)", async () => {
		const out = await rewriteImports(`const m = await ${dyn('("./d.json", { with: { type: "json" } })')};`);
		expect(out).toContain(`${SHIM}("./d.json", { with: { type: "json" } })`);
	});

	it("rewrites nested and chained dynamic import() calls", async () => {
		const out = await rewriteImports(
			`Promise.all([${dyn('("./a.ts")')}, ${dyn('("./b.ts")')}]).then(([a, b]) => a.run(b));`,
		);
		expect(out).toContain(`${SHIM}("./a.ts")`);
		expect(out).toContain(`${SHIM}("./b.ts")`);
		expect(out).not.toContain(dyn('("./a.ts")'));
	});

	it("rewrites dynamic import() with a non-literal specifier", async () => {
		const out = await rewriteImports(`const m = await ${dyn("(spec)")};`);
		expect(out).toContain(`${SHIM}(spec)`);
	});

	it("routes dynamic import through the helper when present and native import when serialized into a foreign realm", async () => {
		const out = await rewriteImports(`const load = async () => await ${dyn('("node:path")')}; load;`);
		const globals = globalThis as Record<string, unknown>;
		const hasOriginal = "__reverse_import__" in globals;
		const originalReverseImport = globals.__reverse_import__;
		if (hasOriginal) {
			delete globals.__reverse_import__;
		}

		expect("__reverse_import__" in globals).toBe(false);

		// Worker realm: helper global exists, call must route through it.
		const seen: string[] = [];
		globals.__reverse_import__ = async (source: string) => {
			seen.push(source);
			return { stubbed: true };
		};
		try {
			const load = indirectEval(out) as () => Promise<{ stubbed?: boolean }>;
			expect((await load()).stubbed).toBe(true);
			expect(seen).toEqual(["node:path"]);

			// Page realm: puppeteer ships `load.toString()` to a realm without the helper —
			// the shim must fall back to native dynamic import instead of throwing.
			const serialized = indirectEval(`(${load.toString()})`) as () => Promise<typeof import("node:path")>;
			delete globals.__reverse_import__;
			const mod = await serialized();
			expect(typeof mod.join).toBe("function");
		} finally {
			if (hasOriginal) {
				globals.__reverse_import__ = originalReverseImport;
			} else {
				delete globals.__reverse_import__;
			}
		}
	});

	it("does not rewrite import statements embedded in template literals (the bug)", async () => {
		const code = ["const generated = `", `${IMPORT} { foo } from "./foo";`, "export const bar = foo + 1;", "`;"].join(
			"\n",
		);
		const out = await rewriteImports(code);
		expect(out).toContain(`${IMPORT} { foo } from "./foo";`);
		expect(out).toContain("export const bar = foo + 1;");
		expect(out).not.toContain("await __reverse_import__(");
	});

	it("does not rewrite import statements inside block comments", async () => {
		const code = `/*\n${IMPORT} foo from "bar";\n*/\nconst x = 1;`;
		const out = await rewriteImports(code);
		expect(out).toContain(`${IMPORT} foo from "bar";`);
		expect(out).not.toContain('await __reverse_import__("bar")');
	});

	it("does not rewrite import statements inside double-quoted strings using line continuation", async () => {
		const code = `const code = "${IMPORT} foo from \\\n'bar'";\nconsole.log(code);`;
		const out = await rewriteImports(code);
		expect(out).not.toContain("await __reverse_import__");
	});

	it("rewrites real top-level imports while leaving template-embedded look-alikes alone", async () => {
		const code = [
			`${IMPORT} a from "alpha";`,
			"const code = `",
			`${IMPORT} b from "beta";`,
			"`;",
			`${IMPORT} c from "gamma";`,
		].join("\n");
		const out = await rewriteImports(code);
		expect(out).toContain('await __reverse_import__("alpha")');
		expect(out).toContain('await __reverse_import__("gamma")');
		expect(out).not.toContain('await __reverse_import__("beta")');
		expect(out).toContain(`${IMPORT} b from "beta";`);
	});

	it("returns the input unchanged when the parser cannot make sense of the code", async () => {
		const code = `${IMPORT} { foo from broken syntax 'unterminated`;
		// Should not reject; should fall through to the VM which will surface the syntax error.
		await expect(rewriteImports(code)).resolves.toBeDefined();
	});

	it("captures the final expression even when trailing empty statements follow", async () => {
		const wrapped = await wrapCode("await Promise.resolve(1);;");
		expect(wrapped.finalExpressionReturned).toBe(true);
		expect(wrapped.source).toContain("__reverse_set_final_expr__((await Promise.resolve(1)))");
	});

	it("strips type-only imports before rewriting imports and top-level return", async () => {
		const wrapped = await wrapCode(`${IMPORT} type { Thing } from "./types";\nreturn 42;`);
		expect(wrapped.finalExpressionReturned).toBe(true);
		expect(wrapped.source).toContain("__reverse_set_final_expr__(42)");
		expect(wrapped.source).not.toContain(`${IMPORT} type`);
	});
});

// Cross-cell persistence: cells run through indirect eval, so bindings survive only if
// they land on globalThis. Cells with top-level `await` run inside an async IIFE, where
// declarations are function-scoped — wrapCode must publish them back to the global object
// or the next cell sees ReferenceError.
describe("wrapCode cross-cell persistence", () => {
	it("publishes top-level function declarations and their sibling consts from async-wrapped cells", async () => {
		const globals = globalThis as Record<string, unknown>;
		const wrapped = await wrapCode(
			"async function reversePersistedFn(n) { return (await Promise.resolve(n)) + 1; }\nconst reversePersistedTotal = await reversePersistedFn(41);",
		);
		expect(wrapped.asyncWrapped).toBe(true);
		try {
			await indirectEval(wrapped.source);
			const fn = globals.reversePersistedFn as (n: number) => Promise<number>;
			expect(typeof fn).toBe("function");
			expect(await fn(1)).toBe(2);
			expect(globals.reversePersistedTotal).toBe(42);
		} finally {
			delete globals.reversePersistedFn;
			delete globals.reversePersistedTotal;
		}
	});

	it("keeps async-cell function closures attached to retained global bindings", async () => {
		const globals = globalThis as Record<string, unknown>;
		const wrapped = await wrapCode(
			"await Promise.resolve();\nvar reverseClosureTotal = 42;\nfunction reverseClosureAnswer() { return reverseClosureTotal; }",
		);
		expect(wrapped.asyncWrapped).toBe(true);
		try {
			await indirectEval(wrapped.source);
			expect((globals.reverseClosureAnswer as () => number)()).toBe(42);
			indirectEval("reverseClosureTotal += 1;");
			expect(globals.reverseClosureTotal).toBe(43);
			expect((globals.reverseClosureAnswer as () => number)()).toBe(43);
		} finally {
			delete globals.reverseClosureAnswer;
			delete globals.reverseClosureTotal;
		}
	});

	it("publishes explicit top-level var declarations from async-wrapped cells", async () => {
		const globals = globalThis as Record<string, unknown>;
		const wrapped = await wrapCode("await Promise.resolve();\nvar reversePersistedVar = 5;");
		expect(wrapped.asyncWrapped).toBe(true);
		try {
			await indirectEval(wrapped.source);
			expect(globals.reversePersistedVar).toBe(5);
		} finally {
			delete globals.reversePersistedVar;
		}
	});
	it("retains block var bindings after await without exposing block lexicals or function locals", async () => {
		const global = globalThis;
		const wrapped = await wrapCode(`await Promise.resolve();
if (true) { var reverseBranchVar = 47; let reverseBlockLet = 12; }
if (false) { var reverseSkippedVar = 1; }
function nested() { var reverseLocalVar = 9; return reverseLocalVar; }
function readBranch() { return reverseBranchVar; }
if (nested() !== 9) throw new Error("function local was lost");`);
		try {
			await indirectEval(wrapped.source);
			expect(indirectEval("reverseBranchVar")).toBe(47);
			expect(indirectEval("typeof reverseSkippedVar")).toBe("undefined");
			expect(Reflect.has(global, "reverseSkippedVar")).toBe(true);
			expect(indirectEval("typeof reverseBlockLet")).toBe("undefined");
			expect(indirectEval("typeof reverseLocalVar")).toBe("undefined");
			indirectEval("reverseBranchVar = 48");
			expect(indirectEval("readBranch()")).toBe(48);
		} finally {
			Reflect.deleteProperty(global, "reverseBranchVar");
			Reflect.deleteProperty(global, "reverseSkippedVar");
			Reflect.deleteProperty(global, "nested");
			Reflect.deleteProperty(global, "readBranch");
		}
	});

	it("keeps a catch-parameter var initializer on the catch binding after await", async () => {
		const global = globalThis;
		const wrapped = await wrapCode(`await Promise.resolve();
try { throw 0; } catch (reverseCaught) { var reverseCaught = 1; var reverseAfterCatch = reverseCaught + 1; }`);
		try {
			await indirectEval(wrapped.source);
			expect(indirectEval("[typeof reverseCaught, reverseAfterCatch]")).toEqual(["undefined", 2]);
			expect(Reflect.has(global, "reverseCaught")).toBe(true);
		} finally {
			Reflect.deleteProperty(global, "reverseCaught");
			Reflect.deleteProperty(global, "reverseAfterCatch");
		}
	});

	it("retains var bindings declared by top-level for loops after await", async () => {
		const global = globalThis;
		const wrapped = await wrapCode(`await Promise.resolve();
for (var reverseLoopIndex = 0; reverseLoopIndex < 2; reverseLoopIndex++) {}
for (var reverseLoopItem of [3, 5]) {}
for (var reverseLoopKey in { a: 1 }) {}`);
		try {
			await indirectEval(wrapped.source);
			expect(indirectEval("[reverseLoopIndex, reverseLoopItem, reverseLoopKey]")).toEqual([2, 5, "a"]);
		} finally {
			Reflect.deleteProperty(global, "reverseLoopIndex");
			Reflect.deleteProperty(global, "reverseLoopItem");
			Reflect.deleteProperty(global, "reverseLoopKey");
		}
	});
});

// Runtime call-site identity: wrapCode wraps bare `tool.read(...)` calls in
// `__reverse_with_call_site__("js:<offset>", () => ...)` so authoritative bridge calls can
// claim speculative results. A bare textual mention of the helper (comment, string)
// must not suppress that wrapping; only genuinely pre-instrumented code or a real
// user binding of the name skips it.
describe("wrapCode runtime call-site instrumentation", () => {
	it("still instruments tool.read when the helper name appears only in a comment", async () => {
		const wrapped = await wrapCode(
			'// mentions __reverse_with_call_site__ but is not instrumented\nawait tool.read({ path: "a.txt" });',
		);
		expect(wrapped.source).toContain('__reverse_with_call_site__("js:');
	});

	it("still instruments tool.read when the helper name appears only in a string literal", async () => {
		const wrapped = await wrapCode(
			'const label = "__reverse_with_call_site__";\nawait tool.read({ path: "a.txt" });',
		);
		expect(wrapped.source).toContain('__reverse_with_call_site__("js:');
	});

	it("does not double-wrap an already-instrumented call", async () => {
		const code = 'await __reverse_with_call_site__("js:0", () => tool.read({ path: "a.txt" }));';
		const wrapped = await wrapCode(code);
		expect(wrapped.source.match(/__reverse_with_call_site__\("js:/g) ?? []).toHaveLength(1);
	});

	it("skips instrumentation when user code declares the helper name", async () => {
		const wrapped = await wrapCode(
			'const __reverse_with_call_site__ = () => {};\nawait tool.read({ path: "a.txt" });',
		);
		expect(wrapped.source).not.toContain('__reverse_with_call_site__("js:');
	});

	it("skips instrumentation when user code assigns the helper name", async () => {
		const wrapped = await wrapCode('__reverse_with_call_site__ = null;\nawait tool.read({ path: "a.txt" });');
		expect(wrapped.source).not.toContain('__reverse_with_call_site__("js:');
	});

	it("skips instrumentation when user code takes the helper name as a parameter", async () => {
		const wrapped = await wrapCode(
			'function f(__reverse_with_call_site__) { return __reverse_with_call_site__; }\nawait tool.read({ path: "a.txt" });',
		);
		expect(wrapped.source).not.toContain('__reverse_with_call_site__("js:');
	});
});
