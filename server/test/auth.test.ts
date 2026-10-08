import { describe, it, expect, vi, afterEach } from "vitest";
import bcrypt from "bcryptjs";
import { verifyCredentials } from "../src/auth/auth.js";
import type { NpmDb } from "../src/npm/npmDb.js";

const noUsers = { findUserByEmail: () => null } as unknown as NpmDb;

describe("verifyCredentials", () => {
  afterEach(() => vi.restoreAllMocks());

  it("compares an unknown email against a well-formed cost-13 hash", async () => {
    // A malformed dummy hash is rejected instantly by bcryptjs, so unknown
    // emails would fail far faster than real ones and leak which exist.
    const compare = vi.spyOn(bcrypt, "compare");
    const result = await verifyCredentials(noUsers, "nobody@example.com", "pw");
    expect(result.ok).toBe(false);
    const hash = compare.mock.calls[0]?.[1] as string;
    expect(hash).toMatch(/^\$2[aby]\$13\$[./A-Za-z0-9]{53}$/);
  }, 20_000);
});
