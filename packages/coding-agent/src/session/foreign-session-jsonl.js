import { isRecord, readLines } from "@rva/utils";
/** Stream valid object records while tolerating malformed or truncated lines. */
export async function* readForeignJsonRecords(filePath) {
    const decoder = new TextDecoder();
    let line = 0;
    for await (const bytes of readLines(Bun.file(filePath).stream())) {
        line += 1;
        try {
            const value = JSON.parse(decoder.decode(bytes));
            if (isRecord(value))
                yield { value, line };
        }
        catch {
            // A partially-written line must not hide the readable transcript prefix.
        }
    }
}
/** Read every valid object record from a foreign JSONL transcript. */
export async function collectForeignJsonRecords(filePath) {
    const records = [];
    for await (const record of readForeignJsonRecords(filePath))
        records.push(record);
    return records;
}
