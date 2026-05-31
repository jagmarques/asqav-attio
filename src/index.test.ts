import { describe, it } from "node:test";
import assert from "node:assert";
import { createHmac } from "node:crypto";
import {
  verifyAttioSignature,
  ATTIO_RECORD_EVENTS,
  AsqavAttioReceiver,
  type AttioWebhookPayload,
} from "./index.ts";

describe("verifyAttioSignature", () => {
  const secret = "whsec_test";
  const body = JSON.stringify({ webhook_id: "wh_1", events: [] });
  const good = createHmac("sha256", secret).update(body).digest("hex");

  it("accepts a valid signature", () => {
    assert.strictEqual(verifyAttioSignature(body, good, secret), true);
  });

  it("rejects a tampered body", () => {
    assert.strictEqual(
      verifyAttioSignature(body + " ", good, secret),
      false,
    );
  });

  it("rejects a wrong signature", () => {
    assert.strictEqual(verifyAttioSignature(body, "deadbeef", secret), false);
  });
});

describe("ATTIO_RECORD_EVENTS", () => {
  it("matches the three cold-verified Attio record event types", () => {
    assert.deepStrictEqual(ATTIO_RECORD_EVENTS, [
      "record.created",
      "record.updated",
      "record.deleted",
    ]);
  });
});

describe("AsqavAttioReceiver", () => {
  it("constructs without throwing", () => {
    const receiver = new AsqavAttioReceiver({ apiKey: "sk_test" });
    assert.ok(receiver instanceof AsqavAttioReceiver);
  });

  it("rejects an unverified delivery when a secret is configured", async () => {
    const receiver = new AsqavAttioReceiver({
      apiKey: "sk_test",
      webhookSecret: "whsec_test",
    });
    const body = JSON.stringify({ webhook_id: "wh_1", events: [] });
    await assert.rejects(
      () => receiver.handleDelivery(body, "wrong-signature"),
      /attio_signature_invalid/,
    );
  });

  it("rejects a delivery missing its signature when a secret is configured", async () => {
    const receiver = new AsqavAttioReceiver({
      apiKey: "sk_test",
      webhookSecret: "whsec_test",
    });
    const body = JSON.stringify({ webhook_id: "wh_1", events: [] });
    await assert.rejects(
      () => receiver.handleDelivery(body),
      /attio_signature_missing/,
    );
  });

  it("attests zero events on an empty delivery without contacting the API", async () => {
    const receiver = new AsqavAttioReceiver({ apiKey: "sk_test" });
    const payload: AttioWebhookPayload = { webhook_id: "wh_1", events: [] };
    const results = await receiver.attestEvents(payload);
    assert.deepStrictEqual(results, []);
  });
});
