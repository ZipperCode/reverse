/**
 * Memory backend abstraction.
 *
 * Backends are mutually exclusive — `await resolveMemoryBackend(settings)` returns
 * exactly one. Implementations MUST be self-contained: they own the per-session
 * state they create in `start()` and tear it down on `clear()`.
 */
export {};
