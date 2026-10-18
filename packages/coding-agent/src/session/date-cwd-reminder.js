import { prompt } from "@rva/utils";
import dateCwdReminderTemplate from "../prompts/system/date-cwd-reminder.md" with { type: "text" };
/** Renders the reminder text for the given local calendar date and cwd. */
export function renderDateCwdReminder(date, cwd) {
    return prompt.render(dateCwdReminderTemplate, { date, cwd }).trim();
}
function messageStartsWithReminder(message, reminder) {
    if (typeof message.content === "string")
        return message.content.startsWith(reminder);
    return message.content[0]?.type === "text" && message.content[0].text === reminder;
}
function injectReminder(message, reminder) {
    const content = typeof message.content === "string"
        ? `${reminder}\n\n${message.content}`
        : [{ type: "text", text: reminder }, ...message.content];
    return { ...message, content };
}
/** Developer turns the injector inserted; every other output message maps to an input one. */
const reminderControls = new WeakSet();
/** Whether `message` is a developer turn a {@link DateCwdReminderInjector} inserted. */
export function isDateCwdReminderControl(message) {
    return reminderControls.has(message);
}
/**
 * Keeps volatile date/cwd reminders append-only across provider requests.
 *
 * The first value is attached to the first user turn. A changed value attaches
 * to a newly appended user turn or a persistent developer turn, leaving every
 * previously sent message byte-identical.
 */
export class DateCwdReminderInjector {
    #root;
    #currentReminder;
    #injections = new Map();
    #controls = [];
    #seen = new WeakSet();
    /** Apply the current reminder while preserving all earlier injected bytes. */
    transform(context, date, cwd) {
        if (!context.systemPrompt || context.systemPrompt.length === 0 || context.messages.length === 0)
            return context;
        const reminder = renderDateCwdReminder(date, cwd);
        const messages = this.#inject(context.messages, reminder);
        return messages === context.messages ? context : { ...context, messages };
    }
    #inject(messages, reminder) {
        const firstUser = messages.find((message) => message.role === "user");
        if (!firstUser)
            return messages;
        if (this.#root !== firstUser) {
            // A new first user turn: a compaction summary or a different conversation.
            // Turns kept from the earlier history must keep the reminders they were
            // sent with, or their bytes change under signed thinking; reminders on
            // turns that are gone are dropped. The new root gets the current reminder.
            const present = new Set(messages);
            for (const message of this.#injections.keys()) {
                if (!present.has(message))
                    this.#injections.delete(message);
            }
            this.#controls = this.#controls.filter(control => present.has(control.anchor));
            this.#root = firstUser;
            this.#currentReminder = reminder;
            if (!this.#injections.has(firstUser) && !messageStartsWithReminder(firstUser, reminder)) {
                this.#injections.set(firstUser, injectReminder(firstUser, reminder));
            }
        }
        else if (this.#currentReminder !== reminder) {
            let newUser;
            for (let index = messages.length - 1; index >= 0; index--) {
                const candidate = messages[index];
                if (candidate.role === "user" && !this.#seen.has(candidate)) {
                    newUser = candidate;
                    break;
                }
            }
            if (newUser) {
                this.#injections.set(newUser, injectReminder(newUser, reminder));
            }
            else {
                const anchor = messages.at(-1);
                const control = {
                    role: "developer",
                    content: reminder,
                    synthetic: true,
                    timestamp: Date.now(),
                };
                reminderControls.add(control);
                this.#controls.push({ anchor, message: control });
            }
            this.#currentReminder = reminder;
        }
        const controlsByAnchor = new Map();
        for (const control of this.#controls) {
            const controls = controlsByAnchor.get(control.anchor);
            if (controls)
                controls.push(control.message);
            else
                controlsByAnchor.set(control.anchor, [control.message]);
        }
        let changed = false;
        const out = [];
        for (const message of messages) {
            const injected = this.#injections.get(message);
            out.push(injected ?? message);
            if (injected)
                changed = true;
            const controls = controlsByAnchor.get(message);
            if (controls) {
                out.push(...controls);
                changed = true;
            }
            this.#seen.add(message);
        }
        return changed ? out : messages;
    }
}
