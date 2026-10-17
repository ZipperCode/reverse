/**
 * Wire types for terminal recording codec (`/record`, `rva play`).
 */

/** History rows retained per pane; older rows fall off the top. */
export const STREAM_HISTORY_LIMIT = 2000;

/** One terminal row: ANSI text limited to SGR + OSC 8, width-truncated. */
export type StreamRow = string;

export interface StreamChatMessage {
	/** Monotonic per channel-session; viewers use it for de-duplication. */
	id: number;
	name: string;
	text: string;
	/** Unix milliseconds. */
	ts: number;
	/** Set when the streamer sent it. */
	host?: boolean;
}
