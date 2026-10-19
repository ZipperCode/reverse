import { isBunTestRuntime } from "@reverse/utils/env";

process.stdout.write(JSON.stringify(isBunTestRuntime()));
