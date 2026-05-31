/**
 * Asqav integration for Attio (https://attio.com), the CRM.
 *
 * Attio exposes no pre-mutation hook. Its App SDK record actions are
 * user-triggered buttons (`onTrigger({ recordId })`), and its webhooks
 * (`record.created` / `record.updated` / `record.deleted`) are post-commit
 * notifications that fire AFTER the record has already changed. There is no
 * surface that runs before a write and can veto it.
 *
 * This module is therefore an honest ATTEST-AFTER receiver, not a
 * pre-execution block. It receives Attio webhook deliveries, optionally
 * verifies the delivery signature, and signs an Asqav receipt for each CRM
 * mutation. The result is a tamper-evident, cryptographically signed record
 * of what changed in the CRM and who changed it - produced after the fact.
 * It cannot stop a mutation. See README.md for the exact control level.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { init, Agent } from "@asqav/sdk";

/** Actor that triggered an Attio event, per the webhooks OpenAPI schema. */
export interface AttioActor {
  /** "api-token" | "workspace-member" | "system" | "app" */
  type: string;
  /** Nullable per the Attio schema (e.g. "system" actors have no id). */
  id: string | null;
}

/** Identity bag inside a single Attio webhook event. */
export interface AttioEventId {
  workspace_id: string;
  object_id: string;
  record_id: string;
  /** Present only on `record.updated`: the attribute that changed. */
  attribute_id?: string;
}

/** A single event inside an Attio webhook delivery. */
export interface AttioEvent {
  /** "record.created" | "record.updated" | "record.deleted" */
  event_type: string;
  id: AttioEventId;
  actor: AttioActor;
}

/** Top-level Attio webhook delivery body. */
export interface AttioWebhookPayload {
  webhook_id: string;
  events: AttioEvent[];
}

/** The three Attio record event types this receiver attests. */
export const ATTIO_RECORD_EVENTS = [
  "record.created",
  "record.updated",
  "record.deleted",
] as const;
export type AttioRecordEvent = (typeof ATTIO_RECORD_EVENTS)[number];

export interface AsqavAttioOptions {
  /** Asqav API key. Falls back to ASQAV_API_KEY. */
  apiKey?: string;
  /** Asqav API base URL. Defaults to the SDK default (asqav.com cloud). */
  baseUrl?: string;
  /**
   * Attio webhook signing secret. When set, every delivery is HMAC-verified
   * before any receipt is signed; an invalid signature throws and nothing is
   * attested. Falls back to ATTIO_WEBHOOK_SECRET. Strongly recommended.
   */
  webhookSecret?: string;
  /** Name registered for the Asqav agent. Defaults to "attio-receiver". */
  agentName?: string;
}

/** Outcome of attesting one Attio event. */
export interface AttestationResult {
  eventType: string;
  recordId: string;
  /** Asqav signature id, or null when signing failed (fail-open). */
  signatureId: string | null;
  /** Populated when signing failed; the delivery is never blocked. */
  error?: string;
}

/**
 * Verify an Attio webhook delivery signature.
 *
 * Attio signs deliveries with an HMAC-SHA-256 of the raw request body keyed by
 * the webhook secret, sent in a header. Pass the EXACT raw body bytes you
 * received - re-serializing the parsed JSON will break the comparison.
 *
 * @param rawBody  The raw, unparsed request body string.
 * @param signature  The signature value from the delivery header.
 * @param secret  The webhook signing secret shown when the webhook is created.
 */
export function verifyAttioSignature(
  rawBody: string,
  signature: string,
  secret: string,
): boolean {
  const expected = createHmac("sha256", secret).update(rawBody).digest("hex");
  const expectedBuf = Buffer.from(expected, "utf8");
  const givenBuf = Buffer.from(signature, "utf8");
  if (expectedBuf.length !== givenBuf.length) return false;
  return timingSafeEqual(expectedBuf, givenBuf);
}

/**
 * Attest-after receiver that signs an Asqav receipt for each Attio CRM
 * mutation. This is NOT a pre-execution gate: by the time a webhook arrives,
 * the Attio record has already changed. It produces an after-the-fact,
 * tamper-evident attestation of what happened.
 */
export class AsqavAttioReceiver {
  private readonly webhookSecret?: string;
  private readonly agentName: string;
  private agent: Agent | null = null;

  constructor(options: AsqavAttioOptions = {}) {
    const apiKey = options.apiKey ?? process.env.ASQAV_API_KEY;
    init({ apiKey, baseUrl: options.baseUrl });
    this.webhookSecret =
      options.webhookSecret ?? process.env.ATTIO_WEBHOOK_SECRET;
    this.agentName = options.agentName ?? "attio-receiver";
  }

  /** Lazily create the Asqav agent the first time a delivery is handled. */
  private async getAgent(): Promise<Agent> {
    if (!this.agent) {
      this.agent = await Agent.create({ name: this.agentName });
    }
    return this.agent;
  }

  /**
   * Handle one raw Attio webhook delivery end to end: verify the signature
   * (when a secret is configured), parse the body, and sign one Asqav receipt
   * per event.
   *
   * @param rawBody  The raw request body string exactly as received.
   * @param signature  The delivery signature header value. Required when a
   *   webhook secret is configured; otherwise ignored.
   * @throws when a webhook secret is configured and the signature is invalid.
   *   In that case nothing is attested - an unverified delivery never
   *   produces a receipt.
   */
  async handleDelivery(
    rawBody: string,
    signature?: string,
  ): Promise<AttestationResult[]> {
    if (this.webhookSecret) {
      if (!signature) {
        throw new Error(
          "attio_signature_missing: webhook secret is configured but no signature was supplied",
        );
      }
      if (!verifyAttioSignature(rawBody, signature, this.webhookSecret)) {
        throw new Error(
          "attio_signature_invalid: delivery signature failed verification; nothing attested",
        );
      }
    }

    const payload = JSON.parse(rawBody) as AttioWebhookPayload;
    return this.attestEvents(payload);
  }

  /**
   * Sign one Asqav receipt per event in an already-parsed and already-verified
   * delivery. Use this when your web framework hands you a parsed body and you
   * verified the signature yourself with `verifyAttioSignature`.
   *
   * Signing is fail-open: if the Asqav API is unreachable, the per-event
   * result carries an `error` and the delivery still returns 200 so Attio does
   * not retry forever. Attestation gaps surface in the Asqav audit trail.
   */
  async attestEvents(
    payload: AttioWebhookPayload,
  ): Promise<AttestationResult[]> {
    const events = payload.events ?? [];
    const results: AttestationResult[] = [];
    if (events.length === 0) return results;

    const agent = await this.getAgent();

    for (const event of events) {
      const recordId = event.id?.record_id ?? "unknown";
      try {
        const receipt = await agent.sign({
          actionType: `attio:${event.event_type}`,
          context: {
            webhook_id: payload.webhook_id,
            event_type: event.event_type,
            workspace_id: event.id?.workspace_id,
            object_id: event.id?.object_id,
            record_id: recordId,
            attribute_id: event.id?.attribute_id,
            actor_type: event.actor?.type,
            actor_id: event.actor?.id,
          },
        });
        results.push({
          eventType: event.event_type,
          recordId,
          signatureId: receipt.signatureId,
        });
      } catch (err) {
        results.push({
          eventType: event.event_type,
          recordId,
          signatureId: null,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    return results;
  }
}
