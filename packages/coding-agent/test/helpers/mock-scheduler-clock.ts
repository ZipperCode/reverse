import { vi } from "bun:test";
import { scheduler } from "node:timers/promises";

const realPerformanceNow = performance.now.bind(performance);

/** Resolve scheduler waits immediately while advancing the monotonic clock by the requested delay. */
export function mockSchedulerWaitWithClock() {
	let advancedMs = 0;
	vi.spyOn(performance, "now").mockImplementation(() => realPerformanceNow() + advancedMs);
	return vi.spyOn(scheduler, "wait").mockImplementation(async (delayMs, options) => {
		options?.signal?.throwIfAborted();
		advancedMs += delayMs;
		options?.signal?.throwIfAborted();
	});
}
