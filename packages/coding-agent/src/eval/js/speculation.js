import { evaluateShadowExpression } from "../speculation/evaluator";
import { containsCallSiteHelperSyntax, loadBabelParser } from "./shared/rewrite-imports";
const MAX_STATIC_LOOP_ITERATIONS = 32;
function hasType(node, type) {
    return node?.type === type;
}
function isIdentifier(node, match) {
    return hasType(node, "Identifier") && (match === undefined || node.name === match.name);
}
function isStringLiteral(node) {
    return hasType(node, "StringLiteral");
}
function isNumericLiteral(node) {
    return hasType(node, "NumericLiteral");
}
function isBooleanLiteral(node) {
    return hasType(node, "BooleanLiteral");
}
function isNullLiteral(node) {
    return hasType(node, "NullLiteral");
}
function isArrayExpression(node) {
    return hasType(node, "ArrayExpression");
}
function isObjectExpression(node) {
    return hasType(node, "ObjectExpression");
}
function isObjectProperty(node) {
    return hasType(node, "ObjectProperty");
}
function isMemberExpression(node) {
    return hasType(node, "MemberExpression");
}
function isTemplateLiteral(node) {
    return hasType(node, "TemplateLiteral");
}
function isBinaryExpression(node, match) {
    return hasType(node, "BinaryExpression") && (match === undefined || node.operator === match.operator);
}
function isCallExpression(node) {
    return hasType(node, "CallExpression");
}
function isAwaitExpression(node) {
    return hasType(node, "AwaitExpression");
}
function isBlockStatement(node) {
    return hasType(node, "BlockStatement");
}
function isVariableDeclaration(node) {
    return hasType(node, "VariableDeclaration");
}
function isExpressionStatement(node) {
    return hasType(node, "ExpressionStatement");
}
function isAssignmentExpression(node, match) {
    return hasType(node, "AssignmentExpression") && (match === undefined || node.operator === match.operator);
}
function isIfStatement(node) {
    return hasType(node, "IfStatement");
}
function isForOfStatement(node) {
    return hasType(node, "ForOfStatement");
}
function isImportDeclaration(node) {
    return hasType(node, "ImportDeclaration");
}
function isFunctionDeclaration(node) {
    return hasType(node, "FunctionDeclaration");
}
function isClassDeclaration(node) {
    return hasType(node, "ClassDeclaration");
}
function isExpression(node) {
    return (isIdentifier(node) ||
        isStringLiteral(node) ||
        isNumericLiteral(node) ||
        isBooleanLiteral(node) ||
        isNullLiteral(node) ||
        isArrayExpression(node) ||
        isObjectExpression(node) ||
        isMemberExpression(node) ||
        isTemplateLiteral(node) ||
        isBinaryExpression(node) ||
        isCallExpression(node) ||
        isAwaitExpression(node) ||
        isAssignmentExpression(node));
}
function isDefinitelyString(expression) {
    if (expression.kind === "literal")
        return typeof expression.value === "string";
    if (expression.kind === "concat")
        return true;
    return (expression.kind === "transform" &&
        (expression.name === "String" || expression.name === "JSON.stringify" || expression.name === "Array.join"));
}
/**
 * Whether string-coercing this value may invoke a mutable intrinsic. Literals
 * of primitive type and intrinsics-gated transform outputs have fixed
 * conversions; arrays dispatch `Array.prototype.join` and every other opaque
 * value (snapshots, prior results, property reads, objects) may reach either
 * `join` or `Object.prototype.toString`. Callers refuse the projection unless
 * both flags report intact.
 */
function coercionNeedsIntrinsics(expression) {
    if (expression.kind === "literal")
        return false;
    if (expression.kind === "concat")
        return expression.items.some(coercionNeedsIntrinsics);
    if (expression.kind === "transform")
        return false;
    return true;
}
function span(node) {
    return { start: node.start ?? 0, end: node.end ?? node.start ?? 0 };
}
function siteId(node) {
    return `js:${node.start ?? 0}`;
}
function expressionDependencies(expression, output = new Set()) {
    switch (expression.kind) {
        case "operation_result":
            output.add(expression.operationId);
            break;
        case "property":
            expressionDependencies(expression.target, output);
            break;
        case "array":
        case "concat":
            for (const item of expression.items)
                expressionDependencies(item, output);
            break;
        case "object":
            for (const entry of expression.entries)
                expressionDependencies(entry.value, output);
            break;
        case "transform":
            expressionDependencies(expression.input, output);
            if (expression.argument)
                expressionDependencies(expression.argument, output);
            break;
        case "literal":
        case "snapshot":
            break;
    }
    return output;
}
function objectKey(property) {
    if (isIdentifier(property))
        return property.name;
    if (isStringLiteral(property) || isNumericLiteral(property))
        return String(property.value);
    return undefined;
}
/**
 * Whether a mutable global intrinsic still has its original identity in the
 * retained session. Same-cell shadows are tracked in the environment; retained
 * overrides are invisible to the snapshot values (functions are never JSON-safe,
 * `delete` removes the key), so the runtime reports them explicitly. Absent only
 * for hand-built snapshots, where intrinsics are assumed intact.
 */
function intrinsicIntact(state, name) {
    return state.initialGlobals[name] ?? true;
}
function projectExpression(expression, state) {
    if (isNullLiteral(expression))
        return { kind: "literal", value: null };
    if (isBooleanLiteral(expression) || isNumericLiteral(expression) || isStringLiteral(expression)) {
        return { kind: "literal", value: expression.value };
    }
    if (isIdentifier(expression)) {
        return state.environment.get(expression.name) ?? { kind: "snapshot", name: expression.name };
    }
    if (isArrayExpression(expression)) {
        const items = [];
        for (const item of expression.elements) {
            if (!item || !isExpression(item))
                return undefined;
            const projected = projectExpression(item, state);
            if (!projected)
                return undefined;
            items.push(projected);
        }
        return { kind: "array", items };
    }
    if (isObjectExpression(expression)) {
        const entries = [];
        for (const property of expression.properties) {
            if (!isObjectProperty(property) || property.computed || !isExpression(property.value)) {
                return undefined;
            }
            const key = objectKey(property.key);
            const value = projectExpression(property.value, state);
            if (key === undefined || !value)
                return undefined;
            entries.push({ key, value });
        }
        return { kind: "object", entries };
    }
    if (isMemberExpression(expression) && isExpression(expression.object)) {
        const target = projectExpression(expression.object, state);
        if (!target)
            return undefined;
        if (!expression.computed && isIdentifier(expression.property)) {
            return { kind: "property", target, property: expression.property.name };
        }
        if (expression.computed && isExpression(expression.property)) {
            const property = projectExpression(expression.property, state);
            if (property?.kind === "literal" &&
                (typeof property.value === "string" || typeof property.value === "number")) {
                return { kind: "property", target, property: property.value };
            }
        }
        return undefined;
    }
    if (isTemplateLiteral(expression)) {
        const items = [];
        for (let index = 0; index < expression.quasis.length; index++) {
            const text = expression.quasis[index]?.value.cooked;
            if (text === undefined)
                return undefined;
            items.push({ kind: "literal", value: text });
            const embedded = expression.expressions[index];
            if (embedded) {
                if (!isExpression(embedded))
                    return undefined;
                const projected = projectExpression(embedded, state);
                if (!projected)
                    return undefined;
                items.push(projected);
            }
        }
        // Implicit template coercion dispatches `Array.prototype.join` for
        // arrays and `Object.prototype.toString` for other objects; refuse the
        // projection unless both intrinsics report intact.
        if (items.some(coercionNeedsIntrinsics) &&
            (!intrinsicIntact(state, "Array.prototype.join") || !intrinsicIntact(state, "Object.prototype.toString"))) {
            return undefined;
        }
        return { kind: "concat", items };
    }
    if (isBinaryExpression(expression, { operator: "+" }) &&
        isExpression(expression.left) &&
        isExpression(expression.right)) {
        const left = projectExpression(expression.left, state);
        const right = projectExpression(expression.right, state);
        if (!(left && right && (isDefinitelyString(left) || isDefinitelyString(right))))
            return undefined;
        // Same implicit coercion as templates: either side may dispatch `join`
        // or `toString` when it is not a statically fixed primitive.
        if ((coercionNeedsIntrinsics(left) || coercionNeedsIntrinsics(right)) &&
            (!intrinsicIntact(state, "Array.prototype.join") || !intrinsicIntact(state, "Object.prototype.toString"))) {
            return undefined;
        }
        return { kind: "concat", items: [left, right] };
    }
    if (isCallExpression(expression) && expression.arguments.every(argument => isExpression(argument))) {
        const args = expression.arguments;
        if (isIdentifier(expression.callee, { name: "String" }) &&
            !state.environment.has("String") &&
            intrinsicIntact(state, "String") &&
            args.length === 1) {
            const input = projectExpression(args[0], state);
            if (!input)
                return undefined;
            // String() coerces its input: arrays dispatch join, objects toString.
            if (coercionNeedsIntrinsics(input) &&
                (!intrinsicIntact(state, "Array.prototype.join") || !intrinsicIntact(state, "Object.prototype.toString"))) {
                return undefined;
            }
            return { kind: "transform", name: "String", input };
        }
        if (isMemberExpression(expression.callee) &&
            !expression.callee.computed &&
            isIdentifier(expression.callee.object, { name: "JSON" }) &&
            !state.environment.has("JSON") &&
            intrinsicIntact(state, "JSON") &&
            intrinsicIntact(state, "JSON.stringify") &&
            isIdentifier(expression.callee.property, { name: "stringify" }) &&
            args.length === 1) {
            const input = projectExpression(args[0], state);
            return input ? { kind: "transform", name: "JSON.stringify", input } : undefined;
        }
        if (isMemberExpression(expression.callee) &&
            !expression.callee.computed &&
            isArrayExpression(expression.callee.object) &&
            isIdentifier(expression.callee.property, { name: "join" }) &&
            intrinsicIntact(state, "Array.prototype.join") &&
            args.length <= 1) {
            const input = projectExpression(expression.callee.object, state);
            const argument = args[0] ? projectExpression(args[0], state) : undefined;
            if (!input || (args[0] && !argument))
                return undefined;
            // Elements and the separator stringify: objects reach toString
            // (nested arrays stay under the join gate above).
            const elements = input.kind === "array" ? input.items : [input];
            const coerced = argument === undefined ? elements : [...elements, argument];
            if (coerced.some(coercionNeedsIntrinsics) && !intrinsicIntact(state, "Object.prototype.toString")) {
                return undefined;
            }
            return { kind: "transform", name: "Array.join", input, ...(argument ? { argument } : {}) };
        }
    }
    return undefined;
}
function unwrapAwait(expression) {
    return isAwaitExpression(expression) && isExpression(expression.argument) ? expression.argument : expression;
}
function callKind(expression) {
    const value = unwrapAwait(expression);
    if (!isCallExpression(value))
        return undefined;
    if (isMemberExpression(value.callee) &&
        !value.callee.computed &&
        isIdentifier(value.callee.object, { name: "tool" }) &&
        isIdentifier(value.callee.property, { name: "read" })) {
        return "read";
    }
    return undefined;
}
function addOperation(expression, state, dynamicPath, controlDependencies) {
    const call = unwrapAwait(expression);
    if (!isCallExpression(call))
        return undefined;
    const name = callKind(call);
    if (name !== "read" || call.arguments.length !== 1)
        return undefined;
    // The prelude tool proxy resolves the bridge dispatcher per call, so admit
    // reads only while the runtime reports its installed identity: a poisoned
    // installation must degrade to unadmitted dependents, never to speculative
    // I/O against a bridge the authoritative cell cannot reach.
    if (!intrinsicIntact(state, "__omp_call_tool__"))
        return undefined;
    const argument = call.arguments[0];
    if (!argument || !isExpression(argument))
        return undefined;
    const projectedArgs = projectExpression(argument, state);
    if (!projectedArgs)
        return undefined;
    const evaluatedArgs = staticValue(projectedArgs, state);
    if (evaluatedArgs &&
        (typeof evaluatedArgs.value !== "object" ||
            evaluatedArgs.value === null ||
            Array.isArray(evaluatedArgs.value) ||
            typeof evaluatedArgs.value.path !== "string")) {
        return undefined;
    }
    const staticSite = siteId(call);
    const pathKey = `${staticSite}:${dynamicPath.join("/")}`;
    const occurrence = state.occurrences.get(pathKey) ?? 0;
    state.occurrences.set(pathKey, occurrence + 1);
    const id = `${pathKey}:${occurrence}`;
    const operation = {
        kind: "tool",
        call: {
            id,
            siteId: staticSite,
            dynamicPath: [...dynamicPath],
            occurrence,
            name,
            args: projectedArgs,
            dependencies: [...expressionDependencies(projectedArgs)],
            controlDependencies: [...controlDependencies],
            sourceOrder: state.sourceOrder++,
            span: span(call),
        },
    };
    state.operations.push(operation);
    return operation;
}
function staticValue(expression, state) {
    try {
        return evaluateShadowExpression(expression, { snapshot: state.snapshot, results: new Map() });
    }
    catch {
        return undefined;
    }
}
function statements(node) {
    return isBlockStatement(node) ? node.body : [node];
}
/**
 * Every identifier bound by a declaration pattern: plain identifiers plus names
 * nested in object/array/rest/assignment patterns. Only the names matter here —
 * default expressions execute at the declaration, so reads before it are
 * unaffected by them while the hoisted binding itself shadows retained state.
 */
function collectPatternNames(node, names) {
    if (isIdentifier(node)) {
        names.push(node.name);
    }
    else if (hasType(node, "ObjectPattern")) {
        for (const property of node.properties) {
            if (hasType(property, "RestElement"))
                collectPatternNames(property.argument, names);
            else if (hasType(property, "ObjectProperty"))
                collectPatternNames(property.value, names);
        }
    }
    else if (hasType(node, "ArrayPattern")) {
        for (const element of node.elements)
            collectPatternNames(element, names);
    }
    else if (hasType(node, "RestElement")) {
        collectPatternNames(node.argument, names);
    }
    else if (hasType(node, "AssignmentPattern")) {
        collectPatternNames(node.left, names);
    }
}
function addBarrier(state, reason, node) {
    state.barrier ??= { kind: "barrier", reason, span: span(node) };
    return false;
}
function hasToolBinding(statements) {
    return statements.some(statement => {
        if (isVariableDeclaration(statement)) {
            return statement.declarations.some(declaration => {
                const names = [];
                collectPatternNames(declaration.id, names);
                return names.includes("tool");
            });
        }
        if (isImportDeclaration(statement)) {
            return statement.specifiers.some(specifier => specifier.local.name === "tool");
        }
        if (isFunctionDeclaration(statement) || isClassDeclaration(statement)) {
            return statement.id !== null && isIdentifier(statement.id, { name: "tool" });
        }
        return false;
    });
}
function hasLexicalBindings(statements) {
    return statements.some(statement => (isVariableDeclaration(statement) && statement.kind !== "var") ||
        isFunctionDeclaration(statement) ||
        isClassDeclaration(statement));
}
/**
 * Every top-level binding that ends up hoisted-as-undefined after wrapCode demotion,
 * seeded into the projection environment so earlier reads never see a retained snapshot
 * value. Covers `var` declarators (natively hoisted), `let`/`const` declarators and class
 * declarations (demoted to `var`), import locals (rewritten to `const` declarations), and
 * function declarations (hoisted). Direct `program.body` children only: nested-block
 * `let`/`const`/`function`/`class` bindings are block-scoped and leave earlier reads alone.
 * `var` alone hoists through `if`/`for-of` bodies, so only `var` is collected recursively.
 */
function demotedTopLevelBindings(nodes) {
    const bindings = [];
    for (const statement of nodes) {
        if (isVariableDeclaration(statement) &&
            (statement.kind === "var" || statement.kind === "let" || statement.kind === "const")) {
            for (const declaration of statement.declarations) {
                const names = [];
                collectPatternNames(declaration.id, names);
                for (const name of names)
                    bindings.push([name, statement.kind]);
            }
        }
        else if (isImportDeclaration(statement)) {
            for (const specifier of statement.specifiers)
                bindings.push([specifier.local.name, "const"]);
        }
        else if (isFunctionDeclaration(statement)) {
            // Pre-declaration assignment to a hoisted function binding is legal and later
            // overwritten, so "var" keeps the const-assignment barrier off; the declaration
            // statement itself still barriers in projectStatement, so post-declaration reads
            // never project.
            if (statement.id && isIdentifier(statement.id))
                bindings.push([statement.id.name, "var"]);
        }
        else if (isClassDeclaration(statement)) {
            // TDZ: pre-declaration access/assignment throws, so the "const" barrier is exact.
            if (statement.id && isIdentifier(statement.id))
                bindings.push([statement.id.name, "const"]);
        }
        else if (isIfStatement(statement)) {
            for (const branch of statement.alternate
                ? [statement.consequent, statement.alternate]
                : [statement.consequent]) {
                for (const [name, kind] of demotedTopLevelBindings(statements(branch))) {
                    if (kind === "var")
                        bindings.push([name, kind]);
                }
            }
        }
        else if (isForOfStatement(statement)) {
            if (isVariableDeclaration(statement.left) && statement.left.kind === "var") {
                for (const declaration of statement.left.declarations) {
                    const names = [];
                    collectPatternNames(declaration.id, names);
                    for (const name of names)
                        bindings.push([name, "var"]);
                }
            }
            for (const [name, kind] of demotedTopLevelBindings(statements(statement.body))) {
                if (kind === "var")
                    bindings.push([name, kind]);
            }
        }
    }
    return bindings;
}
function restoreLexicalEnvironment(environment, state) {
    const outerBindings = new Map([...environment.keys()]
        .filter(name => state.environment.has(name))
        .map(name => [name, state.environment.get(name)]));
    state.environment.clear();
    for (const [name, value] of environment)
        state.environment.set(name, outerBindings.get(name) ?? value);
    for (const name of state.bindingKinds.keys()) {
        if (!environment.has(name))
            state.bindingKinds.delete(name);
    }
}
function projectStatement(statement, state, dynamicPath, controlDependencies) {
    if (isVariableDeclaration(statement)) {
        for (const declaration of statement.declarations) {
            if (!isIdentifier(declaration.id) || !declaration.init || !isExpression(declaration.init)) {
                return addBarrier(state, "unsupported JavaScript declaration", declaration);
            }
            if (declaration.id.name === "tool") {
                return addBarrier(state, "JavaScript tool binding changed", declaration);
            }
            state.bindingKinds.set(declaration.id.name, statement.kind);
            const operation = addOperation(declaration.init, state, dynamicPath, controlDependencies);
            if (operation) {
                if (!isAwaitExpression(declaration.init)) {
                    return addBarrier(state, "unawaited JavaScript tool result", declaration.init);
                }
                state.environment.set(declaration.id.name, { kind: "operation_result", operationId: operation.call.id });
                continue;
            }
            const value = projectExpression(declaration.init, state);
            if (!value || (!staticValue(value, state) && expressionDependencies(value).size === 0)) {
                return addBarrier(state, "unsupported JavaScript declaration value", declaration.init);
            }
            state.environment.set(declaration.id.name, value);
        }
        return true;
    }
    if (isExpressionStatement(statement)) {
        const expression = statement.expression;
        if (isAssignmentExpression(expression, { operator: "=" }) &&
            isIdentifier(expression.left) &&
            isExpression(expression.right)) {
            if (!state.bindingKinds.has(expression.left.name) && !state.environment.has(expression.left.name)) {
                return addBarrier(state, "undeclared JavaScript assignment", expression);
            }
            if (state.bindingKinds.get(expression.left.name) === "const") {
                return addBarrier(state, "JavaScript const binding changed", expression);
            }
            if (expression.left.name === "tool") {
                return addBarrier(state, "JavaScript tool binding changed", expression);
            }
            const operation = addOperation(expression.right, state, dynamicPath, controlDependencies);
            if (operation) {
                if (!isAwaitExpression(expression.right)) {
                    return addBarrier(state, "unawaited JavaScript tool result", expression.right);
                }
                state.environment.set(expression.left.name, { kind: "operation_result", operationId: operation.call.id });
                return true;
            }
            const value = projectExpression(expression.right, state);
            if (!value || (!staticValue(value, state) && expressionDependencies(value).size === 0)) {
                return addBarrier(state, "unsupported JavaScript assignment", expression);
            }
            state.environment.set(expression.left.name, value);
            return true;
        }
        if (isCallExpression(expression) &&
            isIdentifier(expression.callee, { name: "display" }) &&
            !state.environment.has("display") &&
            !("display" in state.snapshot) &&
            expression.arguments.every(argument => isExpression(argument) && projectExpression(argument, state))) {
            return true;
        }
        if (addOperation(expression, state, dynamicPath, controlDependencies))
            return true;
        const projected = projectExpression(expression, state);
        if (projected && staticValue(projected, state))
            return true;
        return addBarrier(state, "unsupported JavaScript statement", statement);
    }
    if (isIfStatement(statement) && isExpression(statement.test)) {
        const test = projectExpression(statement.test, state);
        if (!test)
            return addBarrier(state, "unsupported JavaScript condition", statement.test);
        const conditionalId = `${siteId(statement)}:if`;
        const evaluated = staticValue(test, state);
        if (evaluated) {
            if (evaluated.origins.some(origin => origin.kind === "persistent_state")) {
                return addBarrier(state, "persistent state cannot select speculative JavaScript operations", statement.test);
            }
            const selected = evaluated.value ? statement.consequent : statement.alternate;
            if (!selected)
                return true;
            const environment = new Map(state.environment);
            if (hasToolBinding(statements(selected))) {
                return addBarrier(state, "JavaScript tool binding changed", selected);
            }
            if (hasLexicalBindings(statements(selected))) {
                return addBarrier(state, "JavaScript block binding changed", selected);
            }
            for (const child of statements(selected)) {
                if (!projectStatement(child, state, [...dynamicPath, evaluated.value ? "if:true" : "if:false"], controlDependencies)) {
                    restoreLexicalEnvironment(environment, state);
                    return false;
                }
            }
            restoreLexicalEnvironment(environment, state);
            return true;
        }
        const control = {
            kind: "conditional",
            id: conditionalId,
            test,
            consequentPath: "if:true",
            alternatePath: "if:false",
            span: span(statement),
        };
        state.controls.push(control);
        // Block-hoisted `function` and TDZ `class` declarations cannot be modeled by projecting
        // children in order: an earlier read in the same block sees the hoisted function (or
        // throws for a class), never the outer value. `let`/`const`/`var` stay inline — the
        // per-statement projection below already models those.
        if (statements(statement.consequent).some(child => isFunctionDeclaration(child) || isClassDeclaration(child))) {
            return addBarrier(state, "JavaScript block binding changed", statement.consequent);
        }
        const environment = new Map(state.environment);
        for (const child of statements(statement.consequent)) {
            if (!projectStatement(child, state, [...dynamicPath, "if:true"], [...controlDependencies, conditionalId])) {
                state.environment.clear();
                for (const [name, value] of environment)
                    state.environment.set(name, value);
                return false;
            }
        }
        state.environment.clear();
        for (const [name, value] of environment)
            state.environment.set(name, value);
        if (statement.alternate) {
            if (statements(statement.alternate).some(child => isFunctionDeclaration(child) || isClassDeclaration(child))) {
                return addBarrier(state, "JavaScript block binding changed", statement.alternate);
            }
            for (const child of statements(statement.alternate)) {
                if (!projectStatement(child, state, [...dynamicPath, "if:false"], [...controlDependencies, conditionalId])) {
                    state.environment.clear();
                    for (const [name, value] of environment)
                        state.environment.set(name, value);
                    return false;
                }
            }
        }
        state.environment.clear();
        for (const [name, value] of environment)
            state.environment.set(name, value);
        return true;
    }
    if (isForOfStatement(statement) && isVariableDeclaration(statement.left) && isExpression(statement.right)) {
        const declaration = statement.left.declarations[0];
        if (statement.left.declarations.length !== 1 ||
            !declaration ||
            !isIdentifier(declaration.id) ||
            declaration.id.name === "tool") {
            return addBarrier(state, "unsupported JavaScript loop binding", statement.left);
        }
        const iterable = projectExpression(statement.right, state);
        const evaluated = iterable ? staticValue(iterable, state) : undefined;
        if (!iterable ||
            !evaluated ||
            !Array.isArray(evaluated.value) ||
            evaluated.value.length > MAX_STATIC_LOOP_ITERATIONS) {
            return addBarrier(state, "unbounded or dynamic JavaScript loop", statement);
        }
        const loop = {
            kind: "loop",
            id: `${siteId(statement)}:loop`,
            iterable,
            iterations: evaluated.value.length,
            span: span(statement),
        };
        state.controls.push(loop);
        // The loop header shadows any outer binding for the loop duration; capture
        // the outer state now so it can be restored after the final iteration.
        const outerValue = state.environment.get(declaration.id.name);
        const outerKind = state.bindingKinds.get(declaration.id.name);
        for (const [index, value] of evaluated.value.entries()) {
            state.bindingKinds.set(declaration.id.name, statement.left.kind);
            state.environment.set(declaration.id.name, { kind: "literal", value });
            if (hasToolBinding(statements(statement.body))) {
                return addBarrier(state, "JavaScript tool binding changed", statement.body);
            }
            if (hasLexicalBindings(statements(statement.body))) {
                return addBarrier(state, "JavaScript block binding changed", statement.body);
            }
            for (const child of statements(statement.body)) {
                if (!projectStatement(child, state, [...dynamicPath, `loop:${index}`], controlDependencies))
                    return false;
            }
            // Preserve loop-carried outer assignments across iterations: bodies
            // with their own bindings barrier out above, so anything left in the
            // environment is either outer state (mutations persist, as at runtime)
            // or the loop variable (overwritten next iteration).
        }
        // The loop variable ceases to exist after the loop unless the header is
        // function-scoped `var` (which genuinely leaks its final value). For
        if (evaluated.value.length === 0)
            return true;
        // `let`/`const`, restore the shadowed outer binding when one existed;
        // otherwise seed hoisted-undefined so later reads fail validation the way
        // authoritative execution throws ReferenceError instead of consuming a
        // retained snapshot value.
        if (statement.left.kind === "var") {
            return true;
        }
        if (outerValue !== undefined) {
            state.environment.set(declaration.id.name, outerValue);
            if (outerKind !== undefined)
                state.bindingKinds.set(declaration.id.name, outerKind);
            else
                state.bindingKinds.delete(declaration.id.name);
        }
        else {
            state.environment.set(declaration.id.name, { kind: "literal", value: undefined });
            state.bindingKinds.set(declaration.id.name, "const");
        }
        return true;
    }
    return addBarrier(state, "unsupported JavaScript statement", statement);
}
/** Projects a closed, non-executing IR for the supported eval source subset. */
export async function projectJavaScriptShadowPlan(code, options = {}) {
    let program;
    try {
        const { parse } = await loadBabelParser();
        program = parse(code, { sourceType: "module", errorRecovery: false }).program;
    }
    catch {
        return { operations: [], barrier: { kind: "barrier", reason: "incomplete or invalid JavaScript" } };
    }
    // Mirror the runtime: instrumentRuntimeCallSites skips the whole program when
    // real helper syntax is present (already-instrumented call or shadowing
    // binding), so the planner must not admit operations it cannot claim.
    if (containsCallSiteHelperSyntax(program)) {
        return {
            operations: [],
            barrier: { kind: "barrier", reason: "JavaScript call-site helper present" },
        };
    }
    const state = {
        snapshot: options.snapshot ?? {},
        // Absent only for hand-built snapshots: treat modeled intrinsics as intact
        // (production snapshots always carry the map; see ShadowInitialGlobals).
        initialGlobals: options.initialGlobals ?? {},
        environment: new Map(),
        bindingKinds: new Map(),
        operations: [],
        controls: [],
        occurrences: new Map(),
        sourceOrder: 0,
    };
    if (hasToolBinding(program.body)) {
        return {
            operations: [],
            barrier: { kind: "barrier", reason: "JavaScript tool binding changed" },
        };
    }
    for (const [name, kind] of demotedTopLevelBindings(program.body)) {
        state.environment.set(name, { kind: "literal", value: undefined });
        state.bindingKinds.set(name, kind);
    }
    for (const statement of program.body) {
        if (!projectStatement(statement, state, [], []))
            break;
    }
    return {
        operations: Object.freeze(state.operations),
        ...(state.controls.length > 0 ? { controls: Object.freeze(state.controls) } : {}),
        ...(state.barrier ? { barrier: state.barrier } : {}),
    };
}
