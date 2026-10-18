export function defaultEvalSessionId(session) {
    const sessionFile = session.getSessionFile?.() ?? undefined;
    return sessionFile ? `session:${sessionFile}:cwd:${session.cwd}` : `cwd:${session.cwd}`;
}
