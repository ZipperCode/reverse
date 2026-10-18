/**
 * Version of a {@link SecretObfuscator}'s registry: every collection redaction
 * reads is a tracked collection bound to one revision, and each effective
 * write bumps it. Results reused across calls are keyed by `value`, so a write
 * can never leave a stale result in place — there is no separate invalidation
 * step to forget.
 */
export class RegistryRevision {
    value = 0;
    bump() {
        this.value++;
    }
}
// Both wrap a plain collection instead of subclassing it: reads are the hot
// path of redaction and stay on the engine's builtin Map/Set fast paths.
/** Map whose effective writes bump a {@link RegistryRevision}. */
export class TrackedMap {
    #map = new Map();
    #revision;
    #version = 0;
    constructor(revision) {
        this.#revision = revision;
    }
    /** Number of effective writes to this map alone; lets derived data follow just this map. */
    get version() {
        return this.#version;
    }
    get size() {
        return this.#map.size;
    }
    get(key) {
        return this.#map.get(key);
    }
    has(key) {
        return this.#map.has(key);
    }
    set(key, value) {
        if (this.#map.has(key) && this.#map.get(key) === value)
            return this;
        this.#map.set(key, value);
        this.#version++;
        this.#revision.bump();
        return this;
    }
    keys() {
        return this.#map.keys();
    }
    values() {
        return this.#map.values();
    }
    entries() {
        return this.#map.entries();
    }
    forEach(callback, thisArg) {
        for (const [key, value] of this.#map)
            callback.call(thisArg, value, key, this);
    }
    [Symbol.iterator]() {
        return this.#map[Symbol.iterator]();
    }
}
/** Set whose effective writes bump a {@link RegistryRevision}. */
export class TrackedSet {
    #set = new Set();
    #revision;
    constructor(revision) {
        this.#revision = revision;
    }
    get size() {
        return this.#set.size;
    }
    has(value) {
        return this.#set.has(value);
    }
    add(value) {
        if (this.#set.has(value))
            return this;
        this.#set.add(value);
        this.#revision.bump();
        return this;
    }
    [Symbol.iterator]() {
        return this.#set[Symbol.iterator]();
    }
}
