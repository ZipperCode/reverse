/**
 * Sharpshooter memory types.
 *
 * Sharpshooter is the friction-gated project-decision memory backend: per-prompt
 * async extraction emits {@link SharpshooterDelta}s into a per-session queue, and
 * a shared 5-minute consolidation pass applies queued deltas per project into
 * three markdown decision files ({@link SHARPSHOOTER_MEMORY_FILES}).
 */
/** The project memory file set, in injection order. */
export const SHARPSHOOTER_MEMORY_FILES = ["architecture.md", "product.md", "style.md"];
/** Hard per-file line ceiling enforced on consolidation output. */
export const SHARPSHOOTER_MAX_FILE_LINES = 120;
