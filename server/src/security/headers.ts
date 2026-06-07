import type { FastifyInstance } from "fastify";

/**
 * Apply a conservative set of security headers to every response.
 *
 * The CSP is locked down to same-origin: the SPA loads its own bundled JS/CSS,
 * talks only to its own API (including the SSE stream), and renders charts as
 * inline SVG. `style-src 'unsafe-inline'` is required because Recharts and the
 * world map set inline `style` attributes; no inline <script> is used.
 */
export function registerSecurityHeaders(app: FastifyInstance, opts: { hsts: boolean }): void {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join("; ");

  app.addHook("onSend", async (_req, reply, payload) => {
    reply.header("Content-Security-Policy", csp);
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Cross-Origin-Opener-Policy", "same-origin");
    reply.header("X-Permitted-Cross-Domain-Policies", "none");
    reply.header(
      "Permissions-Policy",
      "geolocation=(), microphone=(), camera=(), payment=()",
    );
    if (opts.hsts) {
      reply.header(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
      );
    }
    return payload;
  });
}
