import { isBunTestRuntime } from "@rva/utils/env";

process.stdout.write(JSON.stringify(isBunTestRuntime()));
