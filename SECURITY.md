# Security Policy

## Reporting Vulnerabilities

Email info@asqav.com with details. We will respond within 48 hours.

Do not open public issues for security vulnerabilities.

## Supported Versions

Only the latest published release is supported.

## Scope

This repository contains asqav-attio, the Attio webhook receiver integration for Asqav.

Report issues that affect:
- Attio webhook signature verification (`verifyAttioSignature`)
- Bypasses that let an event be attested from an unverified delivery
- Payload tampering before submission to the Asqav API

Cryptographic signing runs server-side via the Asqav API. Report signing or key-handling issues against [asqav-sdk](https://github.com/jagmarques/asqav-sdk).

## Scope boundary

This integration is an after-the-fact attestation receiver, not a pre-execution gate. It cannot block an Attio record mutation, because Attio fires its webhooks after the record has already changed. Reports asking it to "block" a mutation are out of scope by design; see the README for the exact control level.
