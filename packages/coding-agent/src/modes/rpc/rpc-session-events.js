/** Drops the accumulated snapshot a streaming event carries; `done` and `error` have none. */
function withoutPartial(event) {
    if (!("partial" in event))
        return event;
    const { partial: _partial, ...increment } = event;
    return increment;
}
/**
 * Writes session events to the RPC output. Message ids are assigned whether or
 * not the frame passes the filter, so changing the filter mid-message never
 * splits one message across two ids.
 */
export class RpcSessionEventForwarder {
    #filter;
    #messageUpdates = "full";
    #messageCount = 0;
    /** Ids of started, unfinished messages. External records (advisor cards, IRC) nest inside a streaming reply. */
    #openMessageIds = [];
    #output;
    constructor(output) {
        this.#output = output;
    }
    /** Forward only the listed event types; `null` forwards everything. Returns the active selection. */
    setFilter(events, messageUpdates = "full") {
        this.#filter = events === null ? undefined : new Set(events);
        this.#messageUpdates = messageUpdates;
        return this.#filter ? Array.from(this.#filter) : null;
    }
    forward(event) {
        const frame = this.#stamp(event);
        if (this.#filter && !this.#filter.has(frame.type))
            return;
        if (frame.type === "message_update" && this.#messageUpdates === "delta") {
            this.#output({
                ...frame,
                message: { role: frame.message.role },
                assistantMessageEvent: withoutPartial(frame.assistantMessageEvent),
            });
            return;
        }
        this.#output(frame);
    }
    #stamp(event) {
        switch (event.type) {
            case "message_start": {
                const messageId = this.#mintMessageId();
                this.#openMessageIds.push(messageId);
                return { ...event, messageId };
            }
            case "message_update": {
                let messageId = this.#openMessageIds.at(-1);
                if (messageId === undefined) {
                    messageId = this.#mintMessageId();
                    this.#openMessageIds.push(messageId);
                }
                return { ...event, messageId };
            }
            case "message_end":
                return { ...event, messageId: this.#openMessageIds.pop() ?? this.#mintMessageId() };
            case "agent_end":
                // A run never leaves a message open; drop anything a dropped frame stranded.
                this.#openMessageIds.length = 0;
                return event;
            default:
                return event;
        }
    }
    #mintMessageId() {
        return `msg-${++this.#messageCount}`;
    }
}
