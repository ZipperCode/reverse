import { ToolError } from "@rva/tui/tools/tool-errors";
import { assertSelectorString, PLAYWRIGHT_ONLY_SELECTOR_RE, parseAriaRefSelector } from "../aria/aria-snapshot";
const SEMANTIC_ENGINES = ["label", "placeholder", "testid", "alt", "title", "role"];
const PREFIXED_ENGINES = ["text", "xpath", "pierce", ...SEMANTIC_ENGINES];
const LEGACY_PREFIXES = ["p-aria/", "p-text/", "p-xpath/", "p-pierce/"];
const ARIA_REF_PREFIXES = ["aria-ref=", "aria-ref/", "ariaref/"];
const ENGINE_PREFIXES = ["aria/", ...PREFIXED_ENGINES.map(engine => `${engine}/`), ...ARIA_REF_PREFIXES, "p-"];
/** Puppeteer's `parseARIASelector` attribute syntax: `[name="…"]` / `[role='…']`. */
const ARIA_ATTRIBUTE_RE = /\[\s*(?<attribute>\w+)\s*=\s*(?<quote>"|')(?<value>\\.|.*?(?=\k<quote>))\k<quote>\s*\]/g;
function parseAriaQuery(query) {
    if (query.length > 10000)
        throw new ToolError(`Selector ${query} is too long`);
    const options = {};
    const defaultName = query.replace(ARIA_ATTRIBUTE_RE, (_match, attribute, _quote, value) => {
        if (attribute !== "name" && attribute !== "role") {
            throw new ToolError(`Unknown aria attribute "${attribute}" in selector`);
        }
        options[attribute] = value;
        return "";
    });
    if (defaultName && !options.name)
        options.name = defaultName;
    return { engine: "aria", ...options };
}
function legacyToModern(selector) {
    if (selector.startsWith("p-aria/")) {
        const rest = selector.slice("p-aria/".length);
        const nameMatch = rest.match(/\[\s*name\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\]]+))\s*\]/);
        const name = nameMatch?.[1] ?? nameMatch?.[2] ?? nameMatch?.[3];
        return `aria/${name ? name.trim() : rest}`;
    }
    return selector.slice("p-".length);
}
/** Parse a browser-tool selector string into a {@link TernSelector}. Throws ToolError on unsupported syntax. */
export function parseTernSelector(selector) {
    assertSelectorString(selector);
    if (!ENGINE_PREFIXES.some(prefix => selector.startsWith(prefix)) && PLAYWRIGHT_ONLY_SELECTOR_RE.test(selector)) {
        throw new ToolError(`Playwright-only selector ${JSON.stringify(selector)} is not supported by the browser tool. ` +
            `Use a puppeteer text selector ("text/Allow all"), an aria selector ("aria/Name"), CSS, or "xpath/...".`);
    }
    if (selector.startsWith("p-")) {
        if (!LEGACY_PREFIXES.some(prefix => selector.startsWith(prefix))) {
            throw new ToolError(`Unsupported selector prefix. Use CSS or puppeteer query handlers (aria/, text/, xpath/, pierce/). Got: ${selector}`);
        }
        return parseTernSelector(legacyToModern(selector));
    }
    const ref = parseAriaRefSelector(selector);
    if (ref !== null)
        return { engine: "ariaRef", ref };
    if (ARIA_REF_PREFIXES.some(prefix => selector.trim().startsWith(prefix))) {
        throw new ToolError(`Invalid ARIA ref selector ${JSON.stringify(selector)}; expected e.g. "aria-ref=e5".`);
    }
    if (selector.startsWith("aria/"))
        return parseAriaQuery(selector.slice("aria/".length));
    for (const engine of PREFIXED_ENGINES) {
        if (selector.startsWith(`${engine}/`))
            return { engine, query: selector.slice(engine.length + 1) };
    }
    return { engine: "css", query: selector };
}
