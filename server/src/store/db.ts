import { DatabaseSync } from "node:sqlite";

/**
 * Single place that knows which SQLite driver we use. We rely on Node's
 * built-in `node:sqlite` (synchronous, no native build step), which keeps the
 * image small and avoids node-gyp entirely.
 */
export type DB = DatabaseSync;
export { DatabaseSync };
