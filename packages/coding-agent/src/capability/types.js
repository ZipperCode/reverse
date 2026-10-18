/**
 * Core types for the capability-based config discovery system.
 *
 * This architecture inverts control: instead of callers knowing about paths like
 * `.claude`, `.codex`, `.gemini`, they simply ask for `load("mcps")` and get back
 * a unified array of MCP servers.
 */
export {};
