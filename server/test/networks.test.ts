import { describe, it, expect } from "vitest";
import { classifyIp } from "../src/ingest/networks.js";
import { lookupGeo } from "../src/ingest/geo.js";

describe("classifyIp", () => {
  it("flags Cloudflare ranges", () => {
    expect(classifyIp("172.71.232.53")).toBe("cloudflare"); // 172.64.0.0/13
    expect(classifyIp("104.16.0.1")).toBe("cloudflare"); // 104.16.0.0/13
    expect(classifyIp("162.158.1.1")).toBe("cloudflare"); // 162.158.0.0/15
    expect(classifyIp("131.0.72.5")).toBe("cloudflare"); // 131.0.72.0/22
  });

  it("flags private and Docker ranges", () => {
    expect(classifyIp("10.0.0.5")).toBe("private");
    expect(classifyIp("172.18.0.2")).toBe("private"); // Docker default
    expect(classifyIp("192.168.1.10")).toBe("private");
    expect(classifyIp("127.0.0.1")).toBe("private");
    expect(classifyIp("100.64.0.1")).toBe("private"); // CGNAT
    expect(classifyIp("::1")).toBe("private");
  });

  it("treats real public IPs as public", () => {
    expect(classifyIp("8.8.8.8")).toBe("public");
    expect(classifyIp("203.0.113.7")).toBe("public");
  });

  it("does not confuse a near-miss with a Cloudflare block", () => {
    // 172.63.x is just below Cloudflare's 172.64.0.0/13.
    expect(classifyIp("172.63.255.255")).toBe("public");
  });
});

describe("lookupGeo skips proxies and private IPs", () => {
  it("does not geolocate a Cloudflare edge IP", () => {
    const g = lookupGeo("172.71.232.53");
    expect(g.country).toBeNull();
  });
  it("does not geolocate a private IP", () => {
    expect(lookupGeo("172.18.0.2").country).toBeNull();
  });
});
