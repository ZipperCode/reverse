import { cfgEvalJs, cfgEvalPy } from "../eval/settings";
/** Active eval backend allowance (`eval.py` / `eval.js`; `PI_PY` / `PI_JS` override). */
export function resolveEvalBackends(session) {
    return {
        python: cfgEvalPy.get(session.settings),
        js: cfgEvalJs.get(session.settings),
    };
}
