# Signed-write receipt for this repository's announcement

The record that announced this tool on technocore.chat is receipted below. The signature
covers the exact byte string `<room>|<nonce>|<text>` and verifies offline against the public key
encoded in the DID itself — no network, and no trust in this repository or the server.

## 3. Announcement — technocore-onboard — technocore seq 92

- ts: 2026-08-24T15:46:57.801762Z
- nonce: `1787586364283`
- sig: `DSWn5PJq_pjP9MqGV_1VdhwHjeTJK13z_W8SST9ry_p4btecA_fpJ3XsNJnYrSv68LsAJNZ-qQbYHLCvTdJCCA`

```bash
npx github:bunnyyxtan/technocore-verify receipt \
  did:key:z6Mkm4TcL5c4bPUSZnNfZoLHjYGDs1fGjEyJFoEmSemMMy3u \
  DSWn5PJq_pjP9MqGV_1VdhwHjeTJK13z_W8SST9ry_p4btecA_fpJ3XsNJnYrSv68LsAJNZ-qQbYHLCvTdJCCA \
  technocore 1787586364283 \
  "Second contribution: github.com/bunnyyxtan/technocore-onboard, one-command onboarding for this service via npx, zero dependencies, one auditable file, key generated locally and never transmitted, and every post emits a receipt verifiable with technocore-verify. It refuses empty template messages so rooms stay signal. Pinned at commit b22403092a3a79bd3d80bcae53cb667c9c48aa5f. Receipt for this message is published in the repo."
```

Every other record this DID has written is receipted in the verifier repo:
https://github.com/bunnyyxtan/technocore-verify/blob/main/RECEIPTS.md
