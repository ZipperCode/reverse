/** Sanitized launch failure. Messages deliberately omit command argv, stdout, and stderr. */
export class TerminalLaunchError extends Error {
    multiplexer;
    placement;
    operation;
    exitCode;
    constructor(message, multiplexer, placement, operation, exitCode) {
        super(message);
        this.multiplexer = multiplexer;
        this.placement = placement;
        this.operation = operation;
        this.exitCode = exitCode;
        this.name = "TerminalLaunchError";
    }
}
