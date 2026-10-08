import type { IncomingHttpHeaders } from "node:http";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * True if a state-changing request was sent cross-site and must be refused.
 *
 * SameSite cookies alone are not enough here: every host NPM proxies usually
 * shares a parent domain with this dashboard, so they all count as the same
 * *site*, and a page on any of them could submit a form to the API. Browsers
 * tell us where a request came from via Sec-Fetch-Site (all current ones) or
 * Origin (older ones); requests with neither are not from a browser page, so
 * they carry no ambient cookie risk and are let through.
 */
export function isCrossSiteWrite(method: string, headers: IncomingHttpHeaders): boolean {
  if (SAFE_METHODS.has(method.toUpperCase())) return false;

  const fetchSite = headers["sec-fetch-site"];
  if (typeof fetchSite === "string") return fetchSite !== "same-origin";

  const origin = headers.origin;
  if (typeof origin === "string") {
    try {
      return new URL(origin).host !== headers.host;
    } catch {
      return true; // includes the literal "null" origin from sandboxed frames
    }
  }
  return false;
}
