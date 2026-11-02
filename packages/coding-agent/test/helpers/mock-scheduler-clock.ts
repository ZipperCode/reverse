import { vi } from "bun:test";
import { scheduler } from "node:timers/promises";

const realPerformanceNow = performance.now.bind(performance);
const realDateNow = Date.now.bind(Date);

/** Advance scheduler clocks, preserving a wall clock already controlled by the caller. */
export function mockSchedulerWaitWithClock() {
	let advancedMs = 0;
	vi.spyOn(performance, "now").mockImplementation(() => realPerformanceNow() + advancedMs);
	if (!("mock" in Date.now)) {
		vi.spyOn(Date, "now").mockImplementation(() => Math.floor(realDateNow() + advancedMs));
	}
	return vi.spyOn(scheduler, "wait").mockImplementation(async (delayMs, options) => {
		options?.signal?.throwIfAborted();
		advancedMs += delayMs;
		options?.signal?.throwIfAborted();
	});
}
