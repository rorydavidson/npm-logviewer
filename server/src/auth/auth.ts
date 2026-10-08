import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import type { NpmDb } from "../npm/npmDb.js";

export interface AuthResult {
  ok: boolean;
  name?: string;
  email?: string;
}

/**
 * Verify a login against NPM's own user store. Reuses the bcrypt password hash
 * from the NPM `auth` table so users log in with the same credentials.
 *
 * Always runs a bcrypt comparison (even when the user is missing) to keep the
 * response time roughly constant and avoid leaking which emails exist.
 */
// Nginx Proxy Manager hashes passwords with bcrypt cost 13. The dummy hash
// must use the same cost, and be a well-formed hash: bcryptjs rejects a
// malformed one instantly, which would make unknown emails fail measurably
// faster than real ones. Built once, on first use, to keep startup fast.
const NPM_BCRYPT_COST = 13;
let dummyHash: Promise<string> | null = null;

function getDummyHash(): Promise<string> {
  dummyHash ??= bcrypt.hash(crypto.randomBytes(32).toString("hex"), NPM_BCRYPT_COST);
  return dummyHash;
}

export async function verifyCredentials(
  npm: NpmDb,
  email: string,
  password: string,
): Promise<AuthResult> {
  const user = npm.findUserByEmail(email);
  const hash = user?.passwordHash ?? (await getDummyHash());

  let match = false;
  try {
    match = await bcrypt.compare(password, hash);
  } catch {
    match = false;
  }

  if (user && user.passwordHash && match) {
    return { ok: true, name: user.name, email: user.email };
  }
  return { ok: false };
}
