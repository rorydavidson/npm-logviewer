import { describe, it, expect } from "vitest";
import {
  parseAccessLine,
  parseErrorLine,
  parseTimeLocal,
  hostIdFromFilename,
  isAccessLog,
  isErrorLog,
} from "../src/ingest/parser.js";

describe("parseTimeLocal", () => {
  it("parses a UTC time_local value", () => {
    const ts = parseTimeLocal("10/Oct/2023:13:55:36 +0000");
    expect(ts).toBe(Date.UTC(2023, 9, 10, 13, 55, 36));
  });

  it("applies a positive timezone offset", () => {
    const ts = parseTimeLocal("10/Oct/2023:13:55:36 +0200");
    expect(ts).toBe(Date.UTC(2023, 9, 10, 11, 55, 36));
  });

  it("applies a negative timezone offset", () => {
    const ts = parseTimeLocal("10/Oct/2023:13:55:36 -0500");
    expect(ts).toBe(Date.UTC(2023, 9, 10, 18, 55, 36));
  });

  it("returns null on junk", () => {
    expect(parseTimeLocal("not a date")).toBeNull();
  });
});

describe("hostIdFromFilename", () => {
  it("extracts the proxy host id", () => {
    expect(hostIdFromFilename("proxy-host-7_access.log")).toBe(7);
    expect(hostIdFromFilename("/data/logs/proxy-host-42_error.log")).toBe(42);
  });
  it("returns null for fallback/dead logs", () => {
    expect(hostIdFromFilename("fallback_access.log")).toBeNull();
    expect(hostIdFromFilename("dead-host-3_access.log")).toBeNull();
  });
});

describe("isAccessLog / isErrorLog", () => {
  it("classifies plain and rotated files", () => {
    expect(isAccessLog("proxy-host-1_access.log")).toBe(true);
    expect(isAccessLog("proxy-host-1_access.log.2")).toBe(true);
    expect(isErrorLog("proxy-host-1_error.log")).toBe(true);
    expect(isErrorLog("proxy-host-1_access.log")).toBe(false);
  });
});

describe("parseAccessLine - proxy format", () => {
  const line =
    '[10/Oct/2023:13:55:36 +0000] - 200 200 - GET https example.com "/api/users?page=2" ' +
    '[Client 203.0.113.5] [Length 1234] [Gzip 2.50] [Sent-to 172.18.0.5] ' +
    '"Mozilla/5.0 (X11; Linux x86_64)" "https://example.com/home"';

  it("parses every field", () => {
    const e = parseAccessLine(line, "proxy-host-3_access.log");
    expect(e).not.toBeNull();
    expect(e!.hostId).toBe(3);
    expect(e!.status).toBe(200);
    expect(e!.upstreamStatus).toBe(200);
    expect(e!.cacheStatus).toBeNull(); // "-"
    expect(e!.method).toBe("GET");
    expect(e!.scheme).toBe("https");
    expect(e!.host).toBe("example.com");
    expect(e!.uri).toBe("/api/users?page=2");
    expect(e!.client).toBe("203.0.113.5");
    expect(e!.bytes).toBe(1234);
    expect(e!.gzip).toBe(2.5);
    expect(e!.sentTo).toBe("172.18.0.5");
    expect(e!.userAgent).toBe("Mozilla/5.0 (X11; Linux x86_64)");
    expect(e!.referer).toBe("https://example.com/home");
    expect(e!.ts).toBe(Date.UTC(2023, 9, 10, 13, 55, 36));
  });

  it("handles a populated cache status and missing gzip", () => {
    const l =
      '[01/Jan/2024:00:00:01 +0000] HIT 200 200 - POST http api.test "/v1" ' +
      '[Client 8.8.8.8] [Length 0] [Gzip -] [Sent-to 10.0.0.2] "curl/8.0" "-"';
    const e = parseAccessLine(l, "proxy-host-1_access.log");
    expect(e!.cacheStatus).toBe("HIT");
    expect(e!.gzip).toBeNull();
    expect(e!.bytes).toBe(0);
    expect(e!.referer).toBe("-");
  });

  it("parses lines without a Sent-to block", () => {
    const l =
      '[01/Jan/2024:00:00:01 +0000] - - 404 - GET http api.test "/missing" ' +
      '[Client 8.8.4.4] [Length 12] [Gzip -] "curl/8.0" "-"';
    const e = parseAccessLine(l, "proxy-host-1_access.log");
    expect(e).not.toBeNull();
    expect(e!.status).toBe(404);
    expect(e!.sentTo).toBeNull();
    expect(e!.upstreamStatus).toBeNull();
  });
});

describe("parseAccessLine - standard format", () => {
  const line =
    '[10/Oct/2023:13:55:36 +0000] 301 - GET http example.com "/" ' +
    '[Client 198.51.100.1] [Length 162] [Gzip -] "Mozilla/5.0" "-"';

  it("parses the standard format", () => {
    const e = parseAccessLine(line, "fallback_access.log");
    expect(e).not.toBeNull();
    expect(e!.hostId).toBeNull();
    expect(e!.status).toBe(301);
    expect(e!.method).toBe("GET");
    expect(e!.upstreamStatus).toBeNull();
    expect(e!.cacheStatus).toBeNull();
    expect(e!.sentTo).toBeNull();
  });
});

describe("parseAccessLine - rejects", () => {
  it("returns null on blank lines", () => {
    expect(parseAccessLine("", "x_access.log")).toBeNull();
    expect(parseAccessLine("   ", "x_access.log")).toBeNull();
  });
  it("returns null on a non-matching line", () => {
    expect(parseAccessLine("totally not a log line", "x_access.log")).toBeNull();
  });
});

describe("parseErrorLine", () => {
  it("parses a typical error entry", () => {
    const l =
      '2023/10/10 13:55:36 [error] 1234#1234: *5 connect() failed (111: Connection refused) ' +
      'while connecting to upstream, client: 203.0.113.9, server: example.com, ' +
      'request: "GET / HTTP/1.1", upstream: "http://172.18.0.5:8080/", host: "example.com"';
    const e = parseErrorLine(l, "proxy-host-2_error.log");
    expect(e).not.toBeNull();
    expect(e!.hostId).toBe(2);
    expect(e!.level).toBe("error");
    expect(e!.client).toBe("203.0.113.9");
    expect(e!.server).toBe("example.com");
    expect(e!.request).toBe("GET / HTTP/1.1");
    expect(e!.upstream).toContain("172.18.0.5");
    expect(e!.message).toContain("connect() failed");
    // The "PID#TID: *CONN" prefix should be stripped.
    expect(e!.message).not.toMatch(/^\d+#\d+/);
    expect(e!.message.startsWith("connect()")).toBe(true);
    expect(e!.ts).toBe(Date.UTC(2023, 9, 10, 13, 55, 36));
  });

  it("returns null on non-error lines", () => {
    expect(parseErrorLine("nope", "x_error.log")).toBeNull();
  });
});
