import { AsyncLocalStorage } from "node:async_hooks";
const activeCell = new AsyncLocalStorage();
export function runWithEvalShadowCell(cell, action) {
    return cell ? activeCell.run(cell, action) : action();
}
export function getActiveEvalShadowCell() {
    return activeCell.getStore();
}
