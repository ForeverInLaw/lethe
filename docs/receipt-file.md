# Receipt file

A receipt file shows what one cleanup run did: how many items it deleted, skipped
and failed to delete, for which account and when. The run's install signs it with
its own Ed25519 key. Anyone can check the file without the app.

```json
{
  "format": "lethe-receipt/1",
  "about": "https://github.com/ForeverInLaw/lethe/blob/master/docs/receipt-file.md",
  "algorithm": "ed25519",
  "summary": "{\"run_id\":\"…\",\"platform\":\"telegram\",\"account_label\":\"…\",\"started_epoch_secs\":…,\"finished_epoch_secs\":…,\"deleted\":37,\"skipped\":2,\"failed\":1}",
  "public_key_hex": "…",
  "signature_hex": "…"
}
```

- `summary` is the JSON text that was signed, kept as a string. Decoding it and
  encoding it again can change its bytes, so check the string as it is.
- `signature_hex` is a detached Ed25519 signature over the UTF-8 bytes of
  `summary`, made with the key in `public_key_hex`.
- Fields in `summary` that are zero may be absent. Its fields are described on
  `RunSummary` in `crates/lethe-crypto/src/receipt.rs`.

A valid signature proves that the holder of that key signed this summary and that
the summary has not been edited since. Every receipt from one install carries the
same key, so receipts from the same person's app can be told apart from others.

## Checking a file

With Python and the `cryptography` package:

```python
import json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

receipt = json.load(open(sys.argv[1], encoding="utf-8"))
key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(receipt["public_key_hex"]))
key.verify(bytes.fromhex(receipt["signature_hex"]), receipt["summary"].encode("utf-8"))
print(json.loads(receipt["summary"]))  # reached only when the signature holds
```

`verify` raises `InvalidSignature` for an edited summary or a different key. In
Rust, `ReceiptFile::verify` in `lethe-crypto` does the same check.
