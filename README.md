# Image Encryption & Sharing — Working Prototype

A minimal, tested, end-to-end prototype proving the hybrid encryption pipeline
(AES-256-GCM for the image + RSA-2048 for key exchange) discussed in the project plan.

## What this proves

- ✅ Images are encrypted with a fresh random AES key before storage
- ✅ The AES key is never stored in plain form — only RSA-wrapped per user
- ✅ A user who hasn't been shared an image **cannot** decrypt it (403 Access Denied)
- ✅ Sharing re-wraps the same AES key for a new recipient, without re-encrypting the image
- ✅ Decrypted image is byte-for-byte identical to the original (verified via SHA-256 + AES-GCM's built-in tag)

This has already been tested end-to-end in this environment: register → upload →
access-denied check → share → list → decrypt, all passing correctly.

## Files

```
prototype/
  app.py              Flask backend — all REST API routes
  crypto_utils.py      Core AES-GCM + RSA hybrid encryption functions
  templates/index.html Simple browser UI to demo the full flow
  requirements.txt     Python dependencies
```

## Setup & Run

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Demo Flow (via the browser UI)

1. **Register** two users, e.g. `alice` and `bob`
2. **Upload** an image as `alice`
3. Try **decrypting** the image as `bob` first — you'll get an "Access denied" error (proves access control works)
4. **Share** the image from `alice` to `bob`
5. **List images** as `bob` — you'll now see it
6. **Decrypt** as `bob` — the original image displays correctly

## Important note on the crypto library

This sandbox had no internet access to install `pycryptodome` (the library
originally planned for Member 1's work), so this prototype uses Python's
`cryptography` library instead — it implements the exact same AES-GCM and
RSA-OAEP standards. The function names and structure in `crypto_utils.py`
are written to match what you'd write with `pycryptodome`, so Member 1 can
port it directly, or keep using `cryptography` — both are legitimate,
well-established libraries and either is fine to mention in your report.

## What's intentionally simplified (prototype only — NOT final design)

| Simplification here | What the real project needs |
|---|---|
| In-memory Python dicts for storage | Real database (MySQL/PostgreSQL) — Member 4's schema |
| No login/password, just a username field | Real authentication with JWT (as planned) |
| RSA private keys held in server memory | Encrypted private key storage, or client-side key handling |
| Local single-process demo | Deployed app, cloud/local file storage for encrypted images |

## Next Steps to Turn This Into the Full Project

1. Replace in-memory dicts with real DB models (Member 4)
2. Add `/login` + JWT auth, replace the "type a username" shortcut (Member 2)
3. Add password-based encryption of stored private keys
4. Replace `templates/index.html` with the real React frontend (Member 3)
5. Optional bonus features: steganography, SHA-256 integrity display in UI, chaos-based scrambling
