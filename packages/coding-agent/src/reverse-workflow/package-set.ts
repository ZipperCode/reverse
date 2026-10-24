import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { hashFileSha256 } from "./lineage";

export interface PackageSetMemberInfo {
	name: string;
	filename: string;
	size: number;
	sha256: string;
	alignment_ok?: boolean;
	signed?: boolean;
}

export interface PackageSetManifest {
	format: "apk_package_set";
	package: string;
	versionCode: string | number;
	set_sha256: string;
	members: PackageSetMemberInfo[];
	signed?: boolean;
}

export interface ValidatedPackageSetManifest {
	manifest: PackageSetManifest;
	manifestSha256: string;
	manifestDir: string;
	memberPaths: Map<string, string>;
}

export interface ResolvedPackageSetInput {
	manifestPath?: string;
	manifestSha256?: string;
	setSha256: string;
	package?: string;
	versionCode?: string | number;
	members: PackageSetMemberInfo[];
	memberPaths: Map<string, string>;
	isManifest: boolean;
}

/**
 * Deterministic SHA-256 aggregate identity for a package set.
 * Sorts members ascending by name and joins `name:sha256` with newlines.
 */
export function computePackageSetSha256(members: Array<{ name: string; sha256: string }>): string {
	const sorted = [...members].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
	const payload = sorted.map(m => `${m.name}:${m.sha256.toLowerCase()}`).join("\n");
	return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}

const MAX_MANIFEST_SIZE_BYTES = 1024 * 1024; // 1 MB upper bound for package set manifest

/**
 * Inspect whether a file is an APK package set manifest.
 * Bounded probe: rejects non-JSON extensions and files > 1MB immediately without full file reads,
 * avoiding memory regressions on multi-GB APKs or plain binaries.
 * Preserves ordinary JSON files as regular targets.
 */
export async function isPackageSetManifest(filePath: string): Promise<boolean> {
	try {
		const lower = filePath.toLowerCase();
		if (!lower.endsWith(".json")) {
			return false;
		}

		let stat;
		try {
			stat = await fs.stat(filePath);
		} catch {
			return false;
		}
		if (!stat.isFile()) {
			return false;
		}

		// Canonical package set manifest filename convention (when file exists) is always treated as a manifest candidate
		if (path.basename(lower) === "package-set.json") {
			return true;
		}

		if (stat.size === 0 || stat.size > MAX_MANIFEST_SIZE_BYTES) {
			return false;
		}
		const handle = await fs.open(filePath, "r");
		try {
			const probeLen = Math.min(stat.size, 16384);
			const probeBuf = Buffer.alloc(probeLen);
			const { bytesRead } = await handle.read(probeBuf, 0, probeLen, 0);
			const probeStr = probeBuf.subarray(0, bytesRead).toString("utf8");
			if (!probeStr.includes('"apk_package_set"')) {
				return false;
			}
		} finally {
			await handle.close();
		}
		const content = await fs.readFile(filePath, "utf8");
		const parsed = JSON.parse(content);
		return (
			typeof parsed === "object" &&
			parsed !== null &&
			(parsed as Record<string, unknown>).format === "apk_package_set"
		);
	} catch {
		return false;
	}
}

/**
 * Strict parser and validator for package-set.json manifest.
 * Enforces:
 * - format === "apk_package_set"
 * - directory containment & realpath symlink escape protection
 * - strict on-disk member existence, sizes, and streaming SHA-256 hashes
 * - deterministic aggregate set_sha256 match
 * - physical manifest SHA-256 computation
 */
export async function parseAndValidatePackageSetManifest(manifestPath: string): Promise<ValidatedPackageSetManifest> {
	const resolvedManifestPath = path.resolve(manifestPath);
	const manifestDir = path.dirname(resolvedManifestPath);
	const stat = await fs.stat(resolvedManifestPath).catch(() => null);
	if (!stat || !stat.isFile()) {
		throw new ToolError(`Package set manifest '${manifestPath}' does not exist or is not a regular file.`);
	}
	if (stat.size === 0) {
		throw new ToolError(`Package set manifest '${manifestPath}' is empty.`);
	}
	if (stat.size > MAX_MANIFEST_SIZE_BYTES) {
		throw new ToolError(
			`Package set manifest '${manifestPath}' exceeds maximum allowed size of ${MAX_MANIFEST_SIZE_BYTES} bytes (${stat.size} bytes).`,
		);
	}

	let content: string;
	try {
		content = await fs.readFile(resolvedManifestPath, "utf8");
	} catch (err) {
		throw new ToolError(
			`Package set manifest '${manifestPath}' unreadable: ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(content);
	} catch (err) {
		throw new ToolError(
			`Package set manifest '${manifestPath}' is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw new ToolError(`Package set manifest '${manifestPath}' must be a JSON object.`);
	}

	const raw = parsed as Record<string, unknown>;
	if (raw.format !== "apk_package_set") {
		throw new ToolError(
			`Invalid manifest format '${String(raw.format)}' in '${manifestPath}'. Expected 'apk_package_set'.`,
		);
	}

	if (typeof raw.package !== "string" || raw.package.trim().length === 0) {
		throw new ToolError(`Package set manifest '${manifestPath}' must declare a non-empty 'package' string.`);
	}

	if (raw.versionCode === undefined || raw.versionCode === null || String(raw.versionCode).trim().length === 0) {
		throw new ToolError(`Package set manifest '${manifestPath}' must declare a valid 'versionCode'.`);
	}

	if (typeof raw.set_sha256 !== "string" || !/^[0-9a-fA-F]{64}$/.test(raw.set_sha256)) {
		throw new ToolError(`Package set manifest '${manifestPath}' must declare a 64-character hex 'set_sha256'.`);
	}

	if (!Array.isArray(raw.members) || raw.members.length === 0) {
		throw new ToolError(`Package set manifest '${manifestPath}' must contain a non-empty 'members' list.`);
	}

	const realManifestDir = await fs.realpath(manifestDir);
	const memberPaths = new Map<string, string>();
	const validatedMembers: PackageSetMemberInfo[] = [];
	const seenNames = new Set<string>();

	for (const m of raw.members) {
		if (typeof m !== "object" || m === null || Array.isArray(m)) {
			throw new ToolError(`Package set member entry in '${manifestPath}' must be an object.`);
		}
		const mRec = m as Record<string, unknown>;
		const name = String(mRec.name ?? "").trim();
		const filename = String(mRec.filename ?? "").trim();
		const size = Number(mRec.size);
		const sha256 = String(mRec.sha256 ?? "")
			.trim()
			.toLowerCase();

		if (!name || !/^[a-zA-Z0-9._-]+$/.test(name)) {
			throw new ToolError(`Invalid member name '${name}' in package set manifest '${manifestPath}'.`);
		}

		if (seenNames.has(name)) {
			throw new ToolError(`Duplicate member name '${name}' declared in package set manifest '${manifestPath}'.`);
		}
		seenNames.add(name);

		if (!filename || path.isAbsolute(filename)) {
			throw new ToolError(
				`Member '${name}' filename must be a non-empty relative path in package set manifest '${manifestPath}'.`,
			);
		}

		const resolvedMember = path.resolve(manifestDir, filename);
		const rel = path.relative(manifestDir, resolvedMember);
		if (rel.startsWith("..") || path.isAbsolute(rel)) {
			throw new ToolError(
				`Member '${name}' filename '${filename}' escapes directory containment in manifest '${manifestPath}'.`,
			);
		}

		let realMember: string;
		try {
			realMember = await fs.realpath(resolvedMember);
		} catch (err) {
			throw new ToolError(
				`Package set member '${name}' file '${resolvedMember}' does not exist on disk: ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		const realRel = path.relative(realManifestDir, realMember);
		if (realRel.startsWith("..") || path.isAbsolute(realRel)) {
			throw new ToolError(
				`Package set member '${name}' symlink targets outside directory containment: '${realMember}'.`,
			);
		}

		const stat = await fs.stat(realMember);
		if (!stat.isFile()) {
			throw new ToolError(`Package set member '${name}' at '${realMember}' is not a regular file.`);
		}

		if (!Number.isSafeInteger(size) || size < 0) {
			throw new ToolError(`Invalid size ${mRec.size} declared for member '${name}' in '${manifestPath}'.`);
		}

		if (stat.size !== size) {
			throw new ToolError(
				`Package set member '${name}' size mismatch: declared ${size} bytes, disk has ${stat.size} bytes.`,
			);
		}

		if (!/^[0-9a-f]{64}$/.test(sha256)) {
			throw new ToolError(`Invalid SHA-256 hash declared for member '${name}' in '${manifestPath}'.`);
		}

		const diskSha256 = await hashFileSha256(realMember);
		if (diskSha256.toLowerCase() !== sha256) {
			throw new ToolError(
				`Package set member '${name}' SHA-256 mismatch (tampered/drifted): expected '${sha256}', actual disk '${diskSha256}'.`,
			);
		}

		memberPaths.set(name, realMember);
		validatedMembers.push({
			name,
			filename,
			size,
			sha256,
			alignment_ok: typeof mRec.alignment_ok === "boolean" ? mRec.alignment_ok : undefined,
			signed: typeof mRec.signed === "boolean" ? mRec.signed : undefined,
		});
	}

	const baseMembers = validatedMembers.filter(m => m.name === "base");
	if (baseMembers.length !== 1) {
		throw new ToolError(
			`Package set manifest '${manifestPath}' must contain exactly one 'base' member, found ${baseMembers.length}.`,
		);
	}

	const computedSetSha256 = computePackageSetSha256(validatedMembers);
	if (computedSetSha256.toLowerCase() !== raw.set_sha256.toLowerCase()) {
		throw new ToolError(
			`Package set manifest aggregate SHA-256 mismatch: manifest declared '${raw.set_sha256}', verified members aggregate '${computedSetSha256}'.`,
		);
	}

	const manifestSha256 = await hashFileSha256(resolvedManifestPath);

	const manifest: PackageSetManifest = {
		format: "apk_package_set",
		package: raw.package.trim(),
		versionCode: raw.versionCode as string | number,
		set_sha256: computedSetSha256,
		members: validatedMembers,
		signed: typeof raw.signed === "boolean" ? raw.signed : undefined,
	};

	return {
		manifest,
		manifestSha256,
		manifestDir,
		memberPaths,
	};
}

/**
 * Resolve canonical package set identity from manifest path or explicit { base, splits } dictionary.
 * When adjacent package-set.json exists next to base APK, strictly matches supplied members and verifies hashes.
 */
export async function resolvePackageSetInput(
	cwd: string,
	input: { base: string; splits?: Record<string, string> } | string,
): Promise<ResolvedPackageSetInput> {
	if (typeof input === "string") {
		const resolvedPath = path.isAbsolute(input) ? input : path.resolve(cwd, input);
		const stat = await fs.stat(resolvedPath).catch(() => null);
		if (!stat) {
			throw new ToolError(`Package set input path '${input}' does not exist.`);
		}
		if (stat.isDirectory()) {
			const candidateManifest = path.join(resolvedPath, "package-set.json");
			const isPkg = await isPackageSetManifest(candidateManifest);
			if (!isPkg) {
				const ownershipTokenPath = path.join(resolvedPath, ".apk_ownership_token");
				const hasToken = await fs
					.stat(ownershipTokenPath)
					.then(s => s.isFile())
					.catch(() => false);
				if (hasToken) {
					throw new ToolError(
						`Incomplete package set publication in directory '${input}': ownership token is present but package-set.json manifest is missing. Incomplete publication directories cannot be consumed as raw package sets.`,
					);
				}
				throw new ToolError(`Directory '${input}' does not contain a valid 'package-set.json' manifest.`);
			}
			const validated = await parseAndValidatePackageSetManifest(candidateManifest);
			return {
				manifestPath: candidateManifest,
				manifestSha256: validated.manifestSha256,
				setSha256: validated.manifest.set_sha256,
				package: validated.manifest.package,
				versionCode: validated.manifest.versionCode,
				members: validated.manifest.members,
				memberPaths: validated.memberPaths,
				isManifest: true,
			};
		}
		if (await isPackageSetManifest(resolvedPath)) {
			const validated = await parseAndValidatePackageSetManifest(resolvedPath);
			return {
				manifestPath: resolvedPath,
				manifestSha256: validated.manifestSha256,
				setSha256: validated.manifest.set_sha256,
				package: validated.manifest.package,
				versionCode: validated.manifest.versionCode,
				members: validated.manifest.members,
				memberPaths: validated.memberPaths,
				isManifest: true,
			};
		}
		throw new ToolError(`File '${input}' is not a valid package set manifest.`);
	}

	const baseResolved = path.isAbsolute(input.base) ? input.base : path.resolve(cwd, input.base);
	const baseDir = path.dirname(baseResolved);
	const candidateManifest = path.join(baseDir, "package-set.json");

	if (await isPackageSetManifest(candidateManifest)) {
		const validated = await parseAndValidatePackageSetManifest(candidateManifest);
		const manifestBase = validated.manifest.members.find(m => m.name === "base");
		if (!manifestBase) {
			throw new ToolError(`Package set manifest '${candidateManifest}' has no 'base' member.`);
		}
		const resolvedManifestBase = validated.memberPaths.get("base")!;
		if ((await fs.realpath(baseResolved)) !== (await fs.realpath(resolvedManifestBase))) {
			throw new ToolError(
				`Supplied base APK '${input.base}' does not match package-set.json base member '${manifestBase.filename}'.`,
			);
		}

		const suppliedSplits = input.splits ?? {};
		const manifestSplits = validated.manifest.members.filter(m => m.name !== "base");

		for (const [splitName, splitPath] of Object.entries(suppliedSplits)) {
			const member = manifestSplits.find(m => m.name === splitName);
			if (!member) {
				throw new ToolError(
					`Supplied split '${splitName}' is not present in package-set.json manifest '${candidateManifest}'.`,
				);
			}
			const resolvedMemberPath = validated.memberPaths.get(splitName)!;
			const resolvedSuppliedPath = path.isAbsolute(splitPath) ? splitPath : path.resolve(cwd, splitPath);
			if ((await fs.realpath(resolvedSuppliedPath)) !== (await fs.realpath(resolvedMemberPath))) {
				throw new ToolError(
					`Supplied split '${splitName}' path '${splitPath}' does not match manifest member '${member.filename}'.`,
				);
			}
		}

		for (const member of manifestSplits) {
			if (!(member.name in suppliedSplits)) {
				throw new ToolError(`Manifest member '${member.name}' is missing from supplied splits map in package_set.`);
			}
		}

		return {
			manifestPath: candidateManifest,
			manifestSha256: validated.manifestSha256,
			setSha256: validated.manifest.set_sha256,
			package: validated.manifest.package,
			versionCode: validated.manifest.versionCode,
			members: validated.manifest.members,
			memberPaths: validated.memberPaths,
			isManifest: true,
		};
	}

	// Guard: check if baseDir is an in-flight/incomplete publication directory with an ownership token
	const ownershipTokenPath = path.join(baseDir, ".apk_ownership_token");
	const hasOwnershipToken = await fs
		.stat(ownershipTokenPath)
		.then(s => s.isFile())
		.catch(() => false);
	if (hasOwnershipToken) {
		throw new ToolError(
			`Incomplete package set publication in directory '${baseDir}': ownership token is present but package-set.json manifest is missing. Incomplete publication directories cannot be consumed as raw package sets.`,
		);
	}

	const members: PackageSetMemberInfo[] = [];
	const memberPaths = new Map<string, string>();

	const baseStat = await fs.stat(baseResolved);
	const baseSha256 = await hashFileSha256(baseResolved);
	members.push({
		name: "base",
		filename: path.basename(baseResolved),
		size: baseStat.size,
		sha256: baseSha256,
	});
	memberPaths.set("base", baseResolved);

	if (input.splits) {
		for (const [sName, sPath] of Object.entries(input.splits)) {
			const resolvedSplit = path.isAbsolute(sPath) ? sPath : path.resolve(cwd, sPath);
			const sStat = await fs.stat(resolvedSplit);
			const sSha256 = await hashFileSha256(resolvedSplit);
			members.push({
				name: sName,
				filename: path.basename(resolvedSplit),
				size: sStat.size,
				sha256: sSha256,
			});
			memberPaths.set(sName, resolvedSplit);
		}
	}

	const setSha256 = computePackageSetSha256(members);
	return {
		setSha256,
		members,
		memberPaths,
		isManifest: false,
	};
}
