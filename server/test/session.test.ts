import { describe, it, expect } from "vitest";
import { createToken, verifyToken } from "../src/auth/session.js";

const SECRET = "test-secret-at-least-16-chars";

describe("session tokens", () => {
  it("round-trips a valid token", () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token = createToken({ email: "a@b.com", name: "A", exp }, SECRET);
    const payload = verifyToken(token, SECRET);
    expect(payload?.email).toBe("a@b.com");
    expect(payload?.name).toBe("A");
  });

  it("rejects a token signed with a different secret", () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token = createToken({ email: "a@b.com", name: "A", exp }, SECRET);
    expect(verifyToken(token, "other-secret-value-xx")).toBeNull();
  });

  it("rejects an expired token", () => {
    const exp = Math.floor(Date.now() / 1000) - 10;
    const token = createToken({ email: "a@b.com", name: "A", exp }, SECRET);
    expect(verifyToken(token, SECRET)).toBeNull();
  });

  it("rejects a tampered payload", () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token = createToken({ email: "a@b.com", name: "A", exp }, SECRET);
    const [, sig] = token.split(".");
    const forged = `${Buffer.from(
      JSON.stringify({ email: "evil@b.com", name: "E", exp }),
    ).toString("base64url")}.${sig}`;
    expect(verifyToken(forged, SECRET)).toBeNull();
  });

  it("rejects undefined and malformed tokens", () => {
    expect(verifyToken(undefined, SECRET)).toBeNull();
    expect(verifyToken("no-dot-here", SECRET)).toBeNull();
  });
});
