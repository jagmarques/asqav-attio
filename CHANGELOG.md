# Changelog

All notable changes to `asqav-attio` are listed here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [SemVer](https://semver.org/) and track the `package.json` version.

## [Unreleased]

## [0.1.0] - Initial release

Initial Attio integration for Asqav.

- `AsqavAttioReceiver`: receives Attio webhook deliveries and signs an Asqav receipt for each `record.created`, `record.updated`, and `record.deleted` event via `@asqav/sdk`.
- `verifyAttioSignature`: HMAC-SHA-256 verification of raw Attio webhook deliveries with a constant-time comparison.
- Honest framing throughout: this is an after-the-fact attestation of CRM mutations, not a pre-execution block, because Attio exposes no pre-mutation hook.
