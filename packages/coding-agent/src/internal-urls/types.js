/**
 * Types for the internal URL routing system.
 *
 * Every scheme is a {@link ProtocolHandler} registered with the router. Its
 * {@link SchemeSpec} declares how tools may consume it (backing, selectors,
 * write policy), so tools consult the router instead of branching on scheme
 * names, and the system prompt lists schemes from {@link ProtocolHandler.promptDoc}.
 */
export {};
