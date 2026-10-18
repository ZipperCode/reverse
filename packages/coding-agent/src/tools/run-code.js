import { ToolError } from "@rva/tui/tools/tool-errors";
const NON_SERIALIZABLE_RUN_ARGUMENT = "Run argument is not JSON-serializable; pass plain data";
function isPlainObject(value) {
    if (value === null || typeof value !== "object")
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function hasSoleOwnKey(value, key) {
    const keys = Reflect.ownKeys(value);
    return keys.length === 1 && keys[0] === key;
}
/** Renders one host value as a JavaScript argument for an evaluated run. */
export function renderRunArg(value) {
    if (value === undefined)
        return "undefined";
    if (isPlainObject(value) && hasSoleOwnKey(value, "__omp_fn") && typeof value.__omp_fn === "string") {
        return `(${value.__omp_fn})`;
    }
    if (isPlainObject(value) && hasSoleOwnKey(value, "__omp_re")) {
        const marker = value.__omp_re;
        if (isPlainObject(marker) &&
            typeof marker.source === "string" &&
            (marker.flags === undefined || typeof marker.flags === "string")) {
            return `new RegExp(${JSON.stringify(marker.source)}, ${JSON.stringify(marker.flags ?? "")})`;
        }
    }
    let rendered;
    try {
        rendered = JSON.stringify(value);
    }
    catch {
        throw new ToolError(NON_SERIALIZABLE_RUN_ARGUMENT);
    }
    if (rendered === undefined)
        throw new ToolError(NON_SERIALIZABLE_RUN_ARGUMENT);
    return rendered;
}
/** Renders a helper call chain (`id(5).click()`) with arguments as JavaScript literals. */
export function renderCallChain(chain) {
    return chain.map(step => `${step.method}(${step.args.map(renderRunArg).join(", ")})`).join(".");
}
/** Renders a function invocation with the requested run scope and positional arguments. */
export function renderFunctionRun(fnSource, scopeNames, args) {
    const scope = scopeNames.join(", ");
    const renderedArgs = args.map(value => `, ${renderRunArg(value)}`).join("");
    return `return await (${fnSource})({ ${scope} }${renderedArgs});`;
}
