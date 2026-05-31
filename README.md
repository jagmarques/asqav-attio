<p align="center">
  <a href="https://asqav.com"><img src="https://asqav.com/logo-text-white.png" alt="Asqav" width="150"></a>
</p>

# asqav-attio

Prove what changed in your Attio CRM, record by record. This integration signs every Attio record mutation with NIST FIPS 204 ML-DSA-65 via the Asqav API, producing a tamper-evident receipt of what was created, updated, or deleted, by whom, and when.

## What control level this gives you (read this first)

This is an attest-after integration, not a pre-execution block. It cannot stop a write before it happens.

The reason is the Attio API itself. Asqav cold-verified Attio's developer surfaces, and Attio exposes no pre-mutation hook:

- Attio webhooks (`record.created`, `record.updated`, `record.deleted`) are post-commit notifications. They fire after the record has already changed, so they can attest but cannot veto. See the [webhooks reference](https://docs.attio.com/rest-api/webhook-reference/record-events/recordupdated).
- Attio App SDK record actions are user-triggered buttons. Their handler is `onTrigger({ recordId })`, which runs when a user clicks the action, not before a save, and has no way to intercept or block a mutation. See the [record action entry point](https://docs.attio.com/sdk/entry-points/record-action) and the [App SDK overview](https://docs.attio.com/sdk/deep-dives/overview).

So the strongest honest control Attio's API supports today is an after-the-fact, cryptographically signed audit trail of CRM mutations. That is what `asqav-attio` delivers. If you need a true pre-execution gate that blocks a rogue agent before it acts, put Asqav on a surface you control before the write, for example the [MCP server](https://github.com/jagmarques/asqav-mcp) or the [SDK](https://github.com/jagmarques/asqav-sdk) inside the agent that drives Attio, rather than relying on Attio's post-commit webhooks.

## Install

`asqav-attio` is not yet published to npm. Install from source until a registry release is cut:

```bash
git clone https://github.com/jagmarques/asqav-attio.git
cd asqav-attio
npm install
npm run build
```

Then add it as a local path dependency in your app's `package.json`:

```json
{
  "dependencies": {
    "asqav-attio": "file:../asqav-attio"
  }
}
```

When the npm release lands, the install becomes:

```bash
npm install asqav-attio
```

## Quick start

Point an Attio webhook (subscribed to the record events you care about) at an HTTP endpoint, then hand each raw delivery to the receiver. The example below uses Express, but any framework works as long as you can read the raw request body.

```ts
import express from "express";
import { AsqavAttioReceiver } from "asqav-attio";

const receiver = new AsqavAttioReceiver({
  apiKey: process.env.ASQAV_API_KEY,
  webhookSecret: process.env.ATTIO_WEBHOOK_SECRET,
  agentName: "attio-prod",
});

const app = express();

// Capture the RAW body. Re-serialized JSON breaks signature verification.
app.post(
  "/attio/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const rawBody = req.body.toString("utf8");
    const signature = req.header("attio-signature") ?? "";

    try {
      const results = await receiver.handleDelivery(rawBody, signature);
      // Each result holds the Asqav signatureId for that record mutation.
      console.log("attested", results);
      res.sendStatus(200);
    } catch (err) {
      // Thrown only when the delivery signature fails to verify.
      console.error("rejected unverified delivery", err);
      res.sendStatus(401);
    }
  },
);

app.listen(3000);
```

## How it works

When Attio commits a record change, it delivers a webhook to your endpoint. For each event in the delivery, `asqav-attio`:

1. Verifies the delivery HMAC against your Attio webhook secret (when one is configured). An unverified delivery throws and nothing is attested.
2. Calls the Asqav API to sign a receipt with `action_type` of `attio:record.created`, `attio:record.updated`, or `attio:record.deleted`, carrying the workspace, object, record, changed-attribute, and actor identifiers from the event.

Signing happens server-side with ML-DSA-65 (NIST FIPS 204), producing a compliance receipt that the CRM, the agent, or any operator can never forge. The signing key never leaves Asqav.

The data that travels depends on the `baseUrl` you point at. Against Asqav cloud (`https://api.asqav.com`) the SDK defaults to hash-only mode, so raw context is hashed client-side before it leaves your infrastructure. Against a self-hosted deployment the full event context lands on the server you control.

## Verifying a delivery yourself

If your framework hands you a parsed body and you would rather verify the signature inline, use `verifyAttioSignature` and `attestEvents` directly:

```ts
import { verifyAttioSignature, AsqavAttioReceiver } from "asqav-attio";

if (!verifyAttioSignature(rawBody, signature, process.env.ATTIO_WEBHOOK_SECRET!)) {
  throw new Error("unverified delivery");
}

const receiver = new AsqavAttioReceiver({ apiKey: process.env.ASQAV_API_KEY });
await receiver.attestEvents(JSON.parse(rawBody));
```

## Fail-open behavior

Per-event signing is fail-open. If the Asqav API is unreachable, the affected event returns an `error` in its result and the delivery still succeeds, so Attio does not retry forever. Any attestation gap is visible in the Asqav audit trail. Signature verification is not fail-open: a delivery whose signature does not verify is rejected and never produces a receipt.

## License

MIT
