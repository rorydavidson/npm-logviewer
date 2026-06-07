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
export async function verifyCredentials(
  npm: NpmDb,
  email: string,
  password: string,
): Promise<AuthResult> {
  const user = npm.findUserByEmail(email);
  // Dummy hash used when the user/hash is absent, to equalise timing.
  const hash =
    user?.passwordHash ??
    "$2a$13$AbCdEfGhIjKlMnOpQrStUuVwXyZ0123456789abcdefghijklmno";

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
