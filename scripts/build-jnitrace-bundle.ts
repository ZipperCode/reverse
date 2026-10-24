/**
 * Reproducible builder for jnitrace-engine bundled asset.
 *
 * Upstream Source Pin:
 * - Package: jnitrace-engine
 * - Version: 1.1.1
 * - gitHead: 463aab6ffdaf868a73490745979229174f9ee2bf
 * - License: MIT License, Copyright (c) 2019 chame1eon
 * - Upstream URL: https://github.com/chame1eon/jnitrace-engine
 * - npm Tarball: https://registry.npmjs.org/jnitrace-engine/-/jnitrace-engine-1.1.1.tgz
 * - Tarball SHA-1: 3549f6246c7bb41a8aa1f263672a04ac1b43d6b9
 * - Tarball SHA-512 (Integrity): sha512-L3nQZCEAe7hTfpzuA8tuEm8Owj6zeTPBBWbN7YCXHNytTZboJVhJsv2PNRgo9dm1l+XnDAQccPSJdS5yS+ixJQ==
 *
 * Modifications applied for reverse AGENT:
 * 1. Frida 16 / 17 global export resolution polyfill (Module.findGlobalExportByName / Process search).
 * 2. JavaVMInterceptor default export resolution fallback.
 * 3. Owned-hook discipline: use Interceptor.attach instead of Interceptor.replace for dlopen,
 *    avoiding global hook collisions and enabling clean listener.detach() without Interceptor.revert.
 * 4. Scan already-loaded modules for JNI_OnLoad and Java_* exports so pre-loaded libraries are traced.
 * 5. Variadic ABI discipline: on Darwin host, variadic C methods are unhooked to protect float/double/stack
 *    ABI from Apple Silicon APRR W^X panics; upstream AAPCS64 variadic assembly is preserved untouched for Android.
 */
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { execFileSync } from "node:child_process";

export const JNITRACE_ENGINE_PIN = {
	name: "jnitrace-engine",
	version: "1.1.1",
	gitHead: "463aab6ffdaf868a73490745979229174f9ee2bf",
	license: "MIT",
	copyright: "Copyright (c) 2019 chame1eon",
	upstreamUrl: "https://github.com/chame1eon/jnitrace-engine",
	npmTarball: "https://registry.npmjs.org/jnitrace-engine/-/jnitrace-engine-1.1.1.tgz",
	sha1: "3549f6246c7bb41a8aa1f263672a04ac1b43d6b9",
	integrity: "sha512-L3nQZCEAe7hTfpzuA8tuEm8Owj6zeTPBBWbN7YCXHNytTZboJVhJsv2PNRgo9dm1l+XnDAQccPSJdS5yS+ixJQ==",
};

/**
 * Strict occurrence-guarded patch replacer. Ensures patch targets match expected occurrences.
 */
function replaceRequired(content: string, search: string | RegExp, replacement: string, expectedCount = 1): string {
	if (typeof search === "string") {
		const count = content.split(search).length - 1;
		if (count !== expectedCount) {
			throw new Error(
				`replaceRequired failed: expected ${expectedCount} occurrence(s) of search pattern, found ${count}`,
			);
		}
		return content.replaceAll(search, replacement);
	}
	const matches = content.match(search);
	const count = matches ? matches.length : 0;
	if (count !== expectedCount) {
		throw new Error(
			`replaceRequired failed: expected ${expectedCount} occurrence(s) of RegExp pattern, found ${count}`,
		);
	}
	return content.replace(search, replacement);
}

async function build(): Promise<void> {
	const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "jnitrace-bundle-build-"));
	try {
		console.log(`Fetching ${JNITRACE_ENGINE_PIN.name}@${JNITRACE_ENGINE_PIN.version}...`);
		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), 30000);

		const response = await fetch(JNITRACE_ENGINE_PIN.npmTarball, { signal: controller.signal });
		clearTimeout(timeoutId);

		if (!response.ok) {
			throw new Error(`Failed to download tarball: ${response.status} ${response.statusText}`);
		}

		const arrayBuffer = await response.arrayBuffer();
		const buffer = Buffer.from(arrayBuffer);

		// 1. Verify SHA-1
		const actualSha1 = crypto.createHash("sha1").update(buffer).digest("hex");
		if (actualSha1 !== JNITRACE_ENGINE_PIN.sha1) {
			throw new Error(`SHA1 mismatch: expected ${JNITRACE_ENGINE_PIN.sha1}, got ${actualSha1}`);
		}
		console.log(`Tarball SHA1 verified: ${actualSha1}`);

		// 2. Verify SHA-512 integrity
		const actualSha512 = `sha512-${crypto.createHash("sha512").update(buffer).digest("base64")}`;
		if (actualSha512 !== JNITRACE_ENGINE_PIN.integrity) {
			throw new Error(`Integrity mismatch: expected ${JNITRACE_ENGINE_PIN.integrity}, got ${actualSha512}`);
		}
		console.log(`Tarball integrity verified: ${actualSha512}`);

		const tarballPath = path.join(tempDir, "jnitrace-engine-1.1.1.tgz");
		await fs.writeFile(tarballPath, buffer);

		execFileSync("tar", ["-xzf", tarballPath, "-C", tempDir], { stdio: "inherit" });

		const pkgDir = path.join(tempDir, "package");

		// Synchronize pinned upstream JNI metadata JSON to shared tool asset
		const envJsonPath = path.join(pkgDir, "dist", "data", "jni_env.json");
		const sharedMetadataPath = path.resolve(__dirname, "../packages/coding-agent/src/tools/jni-api-metadata.json");
		await fs.copyFile(envJsonPath, sharedMetadataPath);
		console.log(`Synchronized pinned upstream JNI metadata to ${sharedMetadataPath}`);

		// Patch 1: engine.js
		const engineJsPath = path.join(pkgDir, "dist", "engine.js");
		let engineJs = (await fs.readFile(engineJsPath, "utf8")).replace(/\r\n/g, "\n");

		// Safe JavaVMInterceptor import
		engineJs = replaceRequired(
			engineJs,
			'const java_vm_interceptor_1 = require("./jni/java_vm_interceptor");',
			'const java_vm_interceptor_1 = require("./jni/java_vm_interceptor");\nconst JavaVMInterceptor = java_vm_interceptor_1.JavaVMInterceptor || (java_vm_interceptor_1.default && java_vm_interceptor_1.default.JavaVMInterceptor);',
		);
		engineJs = replaceRequired(
			engineJs,
			"const javaVMInterceptor = new java_vm_interceptor_1.JavaVMInterceptor(references, threads, jniEnvInterceptor, callbackManager);",
			"const javaVMInterceptor = new JavaVMInterceptor(references, threads, jniEnvInterceptor, callbackManager);",
		);

		// Global export lookup & owned-hook attachment (using Interceptor.attach instead of Interceptor.replace for dlopen)
		const exportLookupAndTeardown = `
    const attachedListeners = [];

    function findGlobalExport(sym) {
        if (typeof Module !== "undefined" && typeof Module.findGlobalExportByName === "function") {
            try { var a = Module.findGlobalExportByName(sym); if (a) return a; } catch(e) {}
        }
        if (typeof Module !== "undefined" && typeof Module.findExportByName === "function") {
            try { var a = Module.findExportByName(null, sym); if (a) return a; } catch(e) {}
        }
        if (typeof Process !== "undefined" && typeof Process.findExportByName === "function") {
            try { var a = Process.findExportByName(null, sym); if (a) return a; } catch(e) {}
        }
        var common = ["libdl.so", "libc.so", "linker", "linker64", "libart.so"];
        for (var i = 0; i < common.length; i++) {
            try {
                var m = Process.findModuleByName(common[i]);
                if (m && typeof m.findExportByName === "function") {
                    var a = m.findExportByName(sym);
                    if (a) return a;
                }
            } catch(e) {}
        }
        return null;
    }

    function safeAttach(target, callbacks) {
        try {
            var l = Interceptor.attach(target, callbacks);
            attachedListeners.push(l);
            return l;
        } catch(e) {
            return null;
        }
    }

    function teardown() {
        for (var i = 0; i < attachedListeners.length; i++) {
            try { attachedListeners[i].detach(); } catch(e) {}
        }
        attachedListeners.length = 0;
        if (callbackManager && typeof callbackManager.clear === "function") {
            try { callbackManager.clear(); } catch(e) {}
        }
    }
    _1.teardownImpl = teardown;

    function hookModuleExports(mod) {
        if (!mod) return;
        try {
            var exps = mod.enumerateExports();
            for (var j = 0; j < exps.length; j++) {
                var exp = exps[j];
                if (exp.type === "function") {
                    if (exp.name === "JNI_OnLoad") {
                        interceptJNIOnLoad(exp.address);
                    } else if (exp.name.indexOf("Java_") === 0) {
                        interceptJNIFunction(exp.address);
                    }
                }
            }
        } catch(e) {}
    }

    function scanExistingModules() {
        try {
            var mods = Process.enumerateModules();
            for (var i = 0; i < mods.length; i++) {
                var mod = mods[i];
                if (checkLibrary(mod.path) || checkLibrary(mod.name)) {
                    trackedLibs.set(mod.name, true);
                    if (mod.path) trackedLibs.set(mod.path, true);
                    hookModuleExports(mod);
                }
            }
        } catch(e) {}
    }
`;
		engineJs = replaceRequired(
			engineJs,
			'const dlopenRef = Module.findExportByName(null, "dlopen");',
			`${exportLookupAndTeardown}\n    const dlopenRef = findGlobalExport("dlopen");`,
		);
		engineJs = replaceRequired(
			engineJs,
			'const dlsymRef = Module.findExportByName(null, "dlsym");',
			'const dlsymRef = findGlobalExport("dlsym");',
		);
		engineJs = replaceRequired(
			engineJs,
			'const dlcloseRef = Module.findExportByName(null, "dlclose");',
			'const dlcloseRef = findGlobalExport("dlclose");',
		);

		const dlopenOriginal = `        const dlopen = new NativeFunction(dlopenRef, "pointer", ["pointer", "int"]);
        Interceptor.replace(dlopen, new NativeCallback((filename, mode) => {
            const path = filename.readCString();
            const retval = dlopen(filename, mode);
            if (path !== null) {
                if (checkLibrary(path)) {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    trackedLibs.set(retval.toString(), true);
                }
                else {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    libBlacklist.set(retval.toString(), true);
                }
            }
            return retval;
        }, "pointer", ["pointer", "int"]));`;

		const dlopenAttachBlock = `        safeAttach(dlopenRef, {
            onEnter(args) {
                try { this.libPath = args[0].readCString(); } catch(e) { this.libPath = null; }
            },
            onLeave(retval) {
                if (this.libPath !== null && !retval.isNull()) {
                    if (checkLibrary(this.libPath)) {
                        trackedLibs.set(retval.toString(), true);
                    } else {
                        libBlacklist.set(retval.toString(), true);
                    }
                }
            }
        });`;
		engineJs = replaceRequired(engineJs, dlopenOriginal, dlopenAttachBlock);

		engineJs = replaceRequired(
			engineJs,
			"return Interceptor.attach(jniOnLoadAddr, {",
			"return safeAttach(jniOnLoadAddr, {",
		);
		engineJs = replaceRequired(
			engineJs,
			"return Interceptor.attach(jniFunctionAddr, {",
			"return safeAttach(jniFunctionAddr, {",
		);
		engineJs = replaceRequired(engineJs, "Interceptor.attach(dlsym, {", "safeAttach(dlsym, {");
		engineJs = replaceRequired(engineJs, "Interceptor.attach(dlclose, {", "safeAttach(dlclose, {");

		const lastBraceIndex = engineJs.lastIndexOf("}");
		if (lastBraceIndex === -1) {
			throw new Error("Failed to locate closing brace in engine.js");
		}
		engineJs = `${engineJs.slice(0, lastBraceIndex)}    scanExistingModules();\n}\nexports.teardown = function() { if (_1.teardownImpl) _1.teardownImpl(); };\nexports.run = run;\n`;
		await fs.writeFile(engineJsPath, engineJs, "utf8");

		// Patch 2: jni_env_interceptor.js
		const jniEnvInterceptorPath = path.join(pkgDir, "dist", "jni", "jni_env_interceptor.js");
		let jniEnvInterceptorJs = (await fs.readFile(jniEnvInterceptorPath, "utf8")).replace(/\r\n/g, "\n");

		// On Darwin (macOS host), leave variadics unhooked to protect float/double/stack ABI from Apple Silicon APRR W^X panics
		jniEnvInterceptorJs = replaceRequired(
			jniEnvInterceptorJs,
			'if (method.args[method.args.length - END_INDEX] === "...") {',
			'if (method.args[method.args.length - END_INDEX] === "...") {\n                if (Process.platform === "darwin") {\n                    newJNIEnvStruct.add(offset).writePointer(methodAddr);\n                    continue;\n                }',
		);

		// Wrap Interceptor.attach(text) in try/catch to avoid Frida 17 instruction intercept error on dynamically generated text
		const oldAttach = `        Interceptor.attach(text, function () {
            let backtraceType = Backtracer.ACCURATE;
            if (config.backtrace === "fuzzy") {
                backtraceType = config.backtrace;
            }
            self.vaArgsBacktraces.set(this.threadId, Thread.backtrace(this.context, backtraceType));
        });`;
		const newAttach = `        try {
            Interceptor.attach(text, function () {
                let backtraceType = Backtracer.ACCURATE;
                if (config.backtrace === "fuzzy") {
                    backtraceType = config.backtrace;
                }
                self.vaArgsBacktraces.set(this.threadId, Thread.backtrace(this.context, backtraceType));
            });
        } catch(e) {}`;
		jniEnvInterceptorJs = replaceRequired(jniEnvInterceptorJs, oldAttach, newAttach);
		await fs.writeFile(jniEnvInterceptorPath, jniEnvInterceptorJs, "utf8");

		// Patch 3: index.js (single consolidated write)
		const indexJsPath = path.join(pkgDir, "dist", "index.js");
		let indexJs = (await fs.readFile(indexJsPath, "utf8")).replace(/\r\n/g, "\n");
		indexJs = replaceRequired(
			indexJs,
			"exports.JNILibraryWatcher = JNILibraryWatcher;",
			"exports.JNILibraryWatcher = JNILibraryWatcher;\nexports.teardown = function() { if (exports.teardownImpl) exports.teardownImpl(); };\nJNIInterceptor.teardown = exports.teardown;",
		);
		indexJs = replaceRequired(
			indexJs,
			"function attach(method, callback) {",
			`function attach(method, callback) {
        if (Process.platform === "darwin") {
            for (let i = 4; i < jni_env_json_1.default.length; i++) {
                const el = jni_env_json_1.default[i];
                if (el.name === method && el.args[el.args.length - 1] === "...") {
                    throw new Error("Variadic JNI method '" + method + "' cannot be intercepted on Darwin host due to Apple Silicon ABI/W^X constraints; use Call*MethodA/Call*MethodV or run on Android target.");
                }
            }
        }`,
		);
		await fs.writeFile(indexJsPath, indexJs, "utf8");

		// Bundle using bun build with CommonJS format
		console.log("Bundling with bun build...");
		const bundleOutPath = path.join(tempDir, "jnitrace-bundle.js");
		execFileSync("bun", ["build", indexJsPath, "--target=browser", "--format=cjs", `--outfile=${bundleOutPath}`], {
			stdio: "inherit",
		});

		let bundleJs = await fs.readFile(bundleOutPath, "utf8");
		bundleJs = bundleJs.replace(/export\s+default\s+require_dist\(\);?/g, "module.exports = require_dist();");
		console.log(`Bundle generated: ${(bundleJs.length / 1024).toFixed(1)} KB`);

		// Extract JNI method names directly from upstream JSON data
		const vmJsonPath = path.join(pkgDir, "dist", "data", "java_vm.json");
		const envData = JSON.parse(await fs.readFile(envJsonPath, "utf8")) as Array<{ name: string }>;
		const vmData = JSON.parse(await fs.readFile(vmJsonPath, "utf8")) as Array<{ name: string }>;
		const allJniApis = [...envData.slice(4).map(m => m.name), ...vmData.slice(3).map(m => m.name)];

		const targetAssetPath = path.resolve(__dirname, "../packages/coding-agent/src/tools/jnitrace-engine-asset.ts");
		const header = `/**
 * Bundled jnitrace-engine v1.1.1 asset for Android JNI tracing.
 *
 * Generated by scripts/build-jnitrace-bundle.ts. Do not edit manually.
 *
 * Upstream Provenance:
 * - Package: ${JNITRACE_ENGINE_PIN.name}
 * - Version: ${JNITRACE_ENGINE_PIN.version}
 * - gitHead: ${JNITRACE_ENGINE_PIN.gitHead}
 * - License: ${JNITRACE_ENGINE_PIN.license} (${JNITRACE_ENGINE_PIN.copyright})
 * - Upstream URL: ${JNITRACE_ENGINE_PIN.upstreamUrl}
 * - npm Tarball: ${JNITRACE_ENGINE_PIN.npmTarball}
 * - Tarball SHA1: ${JNITRACE_ENGINE_PIN.sha1}
 * - Integrity: ${JNITRACE_ENGINE_PIN.integrity}
 *
 * Included Features:
 * - Complete JNIEnv (232 methods) and JavaVM struct virtual tables & offset tracking
 * - Architecture-specific trampolines: arm64, arm, x64, ia32
 * - Frida 16 / 17 global export resolution polyfill
 * - Owned-hook discipline: Interceptor.attach without Interceptor.replace for dlopen
 * - Clean teardown() detaching all listener handles
 * - Module pre-scan for pre-loaded libraries
 * - Java method signature parser and native-to-frida type conversions
 */

export const JNITRACE_ENGINE_PIN = ${JSON.stringify(JNITRACE_ENGINE_PIN, null, "\t")};

export const ALL_JNI_APIS = ${JSON.stringify(allJniApis, null, "\t")};

export const JNITRACE_ENGINE_BUNDLE = ${JSON.stringify(bundleJs)};
`;

		await fs.writeFile(targetAssetPath, header, "utf8");
		console.log(`Successfully wrote asset to ${targetAssetPath}`);
	} finally {
		await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
	}
}

build().catch(err => {
	console.error("Build failed:", err);
	process.exit(1);
});
