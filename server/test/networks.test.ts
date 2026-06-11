import { describe, it, expect } from "vitest";
import { classifyIp, ipMatchesAny, ipv6Subnet } from "../src/ingest/networks.js";
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

  it("classifies IPv6 addresses", () => {
    expect(classifyIp("fd12:3456::1")).toBe("private"); // unique-local
    expect(classifyIp("fe80::abcd")).toBe("private"); // link-local
    expect(classifyIp("2a00:23c5:1234:5678::1")).toBe("public");
    expect(classifyIp("2606:4700::6810:1")).toBe("cloudflare");
    expect(classifyIp("::ffff:192.168.1.10")).toBe("private"); // mapped IPv4
    expect(classifyIp("::ffff:8.8.8.8")).toBe("public");
  });
});

describe("ipMatchesAny", () => {
  it("matches exact IPs", () => {
    expect(ipMatchesAny("8.8.8.8", ["1.1.1.1", "8.8.8.8"])).toBe(true);
    expect(ipMatchesAny("8.8.8.8", ["1.1.1.1"])).toBe(false);
  });
  it("matches CIDR ranges", () => {
    expect(ipMatchesAny("10.20.30.40", ["10.20.30.0/24"])).toBe(true);
    expect(ipMatchesAny("10.20.31.40", ["10.20.30.0/24"])).toBe(false);
  });
  it("ignores blanks", () => {
    expect(ipMatchesAny("8.8.8.8", ["", "  "])).toBe(false);
  });
  it("matches IPv6 CIDR ranges", () => {
    expect(ipMatchesAny("2a00:23c5:1234:5678:abcd::1", ["2a00:23c5:1234::/48"])).toBe(true);
    expect(ipMatchesAny("2a00:23c5:1234:5678::1", ["2a00:23c5:1234:5678::/64"])).toBe(true);
    expect(ipMatchesAny("2a00:23c5:9999:5678::1", ["2a00:23c5:1234::/48"])).toBe(false);
  });
  it("matches IPv6 by value, not text", () => {
    expect(ipMatchesAny("2001:db8:0:0:0:0:0:1", ["2001:db8::1"])).toBe(true);
  });
  it("does not let a v6 entry match a v4 address", () => {
    expect(ipMatchesAny("8.8.8.8", ["::/0"])).toBe(false);
  });
});

describe("ipv6Subnet", () => {
  it("returns the enclosing /64 in canonical form", () => {
    expect(ipv6Subnet("2a00:23c5:1234:5678:abcd:ef01:2345:6789")).toBe(
      "2a00:23c5:1234:5678::/64",
    );
    expect(ipv6Subnet("2001:db8::1")).toBe("2001:db8::/64");
  });
  it("returns null for IPv4, CIDRs, and junk", () => {
    expect(ipv6Subnet("8.8.8.8")).toBeNull();
    expect(ipv6Subnet("2001:db8::/64")).toBeNull();
    expect(ipv6Subnet("not-an-ip")).toBeNull();
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
