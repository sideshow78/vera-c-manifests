# VERA-C manifests

VERA-C is a news-analysis system that registers probability forecasts on yes/no questions
before their outcomes are known, and scores them once the outcomes arrive. This repository
lets anyone check, later, that a forecast record existed in an exact form by a given date.

It holds **hashes only**: no forecast, question, probability or record content is published here.

## What is here

- `manifests/YYYY-MM-DD.json`: one manifest per day. Each one holds:
  - `records`: the SHA-256 hash of every forecast record file that is new since the previous
    manifest. The first manifest (2026-10-10) covers every record that existed that day. A
    record edited after it was committed returns under its new hash, so the edit is visible.
  - `merkleRoot`: one hash that commits to the whole list (rule `merkle_v1`, below).
  - `ledgerExport`: the SHA-256 of a canonical export of the forecast ledger (rule
    `ledger_export_v1`, below). The export itself is not published.
- `manifests/YYYY-MM-DD.json.ots`: an [OpenTimestamps](https://opentimestamps.org) proof that
  anchors the manifest's hash in the Bitcoin blockchain, so its date cannot be backdated. A
  proof starts as pending and is confirmed within hours.
- `manifests/YYYY-MM-DD.json.stamp-pending`: present only if stamping failed on the day. The
  manifest is stamped later, and the gap stays visible in this repository's history.
- `verify.py`: the verifier, standard library only.

## Verifying

Given a record file that VERA-C has shared with you:

```
python3 verify.py record path/to/record.json
```

- `OK` means the file's hash is in a manifest, that manifest's list gives its stated Merkle
  root, and its stamp checks out (with the OpenTimestamps client installed:
  `pip install opentimestamps-client`).
- A failure is named: `HASH_NOT_IN_MANIFEST`, `MERKLE_ROOT_MISMATCH`, `STAMP_INVALID`.

`python3 verify.py manifest 2026-10-10` checks one manifest. Given a ledger export, use
`python3 verify.py export export.jsonl --day 2026-10-10` (`EXPORT_HASH_MISMATCH` on a mismatch).

## What a pass proves, and what it does not

**It proves:** the record existed in exactly this form no later than the time the
manifest's stamp attests; and the day's list is the one committed to.

**It does not prove:**
- the record's own timestamp;
- that a forecast was shown to anyone;
- that a day's list is the whole ledger;
- that a question was well formed, or a forecast correctly computed.

The first manifest proves existence from 2026-10-10 onward only. Records from before that
date are evidenced separately, by the repository host's push log (available to reviewers on
request).

## Rules

- **`merkle_v1`:** the leaves are the record hashes as bytes, sorted. Each level pairs
  neighbours and hashes `sha256(left + right)`. An odd last node pairs with itself. A list with
  no leaves gives `sha256(b"")`.
- **`ledger_export_v1`:** this system's own ledger rows, every status, sorted by analysis id.
  - Columns: `analysis_id, analyzed_at, class_id, question_text, display_posterior, prior,
    resolution_deadline, status, resolved_at, brier`.
  - Format: one JSON object per line, keys sorted, separators `(",", ":")`, UTF-8, a newline
    after every line.

  A change to the columns is a new export version.

Manifests are never overwritten. Any correction is a new, visible commit.
