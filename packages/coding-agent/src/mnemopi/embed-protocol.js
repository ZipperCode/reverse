/** Env var carrying the endpoint the shared server must own. */
export const MNEMOPI_EMBED_SOCKET_ENV = "OMP_MNEMOPI_EMBED_SOCKET";
/** Env var naming the model the shared server serves (process title and logs). */
export const MNEMOPI_EMBED_MODEL_ENV = "OMP_MNEMOPI_EMBED_MODEL";
/** Env var carrying the launch tag the server echoes in `pong`, so a server from another omp version is replaced. */
export const MNEMOPI_EMBED_TAG_ENV = "OMP_MNEMOPI_EMBED_TAG";
/** Env var overriding the idle exit window (milliseconds); for tests. */
export const MNEMOPI_EMBED_IDLE_MS_ENV = "OMP_MNEMOPI_EMBED_IDLE_MS";
/** Idle window (nothing in flight, no request received) after which the server exits and the model's memory is freed. */
export const MNEMOPI_EMBED_IDLE_MS = 15 * 60 * 1000;
