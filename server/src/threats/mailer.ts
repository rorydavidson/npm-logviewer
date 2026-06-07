export interface MailerConfig {
  apiKey: string;
  from: string;
}

export interface SendResult {
  ok: boolean;
  error?: string;
}

/**
 * Sends mail through the Resend HTTP API. No SDK dependency — a single fetch.
 * Returns a result object rather than throwing so callers can surface errors
 * in the UI without crashing the engine.
 */
export class Mailer {
  #cfg: MailerConfig;

  constructor(cfg: MailerConfig) {
    this.#cfg = cfg;
  }

  get configured(): boolean {
    return this.#cfg.apiKey.length > 0;
  }

  async send(
    to: string,
    subject: string,
    text: string,
    html?: string,
  ): Promise<SendResult> {
    if (!this.configured) return { ok: false, error: "RESEND_API_KEY not set" };
    if (!to) return { ok: false, error: "no recipient configured" };

    try {
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.#cfg.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: this.#cfg.from,
          to: [to],
          subject,
          text,
          ...(html ? { html } : {}),
        }),
      });
      if (!res.ok) {
        const body = await res.text();
        return { ok: false, error: `Resend ${res.status}: ${body.slice(0, 300)}` };
      }
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "send failed" };
    }
  }
}
