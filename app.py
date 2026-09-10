"""
app.py
------
Flask backend for the Image Encryption & Sharing prototype.

Implements the REST API endpoints discussed in the project plan:
    POST /register              -> create a user, generate RSA key pair
    GET  /users                 -> list registered usernames (demo convenience)
    POST /upload                -> AES-encrypt an image, store it
    POST /share                 -> RSA-wrap the AES key for another recipient
    GET  /images/<username>     -> list images visible to a user
    GET  /decrypt/<image_id>    -> decrypt & return the image for a given user

NOTE: This is a PROTOTYPE, not the production design:
  - All data is stored in-memory (Python dicts) instead of a real database.
  - There is no login/password/JWT — you just type a username to act as that user.
  - Private keys are held server-side in memory for simplicity. In the real
    project (see Member 4's role), keys and sessions must be handled securely.
The goal here is to prove the full encryption -> sharing -> decryption pipeline
works end-to-end, exactly like Phase 1-3 of the prototype roadmap.
"""

from flask import Flask, request, jsonify, send_file, render_template
import io
import uuid

import crypto_utils

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory "database" (prototype only)
# ---------------------------------------------------------------------------
users = {}     # username -> {"public_key": ..., "private_key": ...}
images = {}    # image_id -> {"ciphertext": ..., "nonce": ..., "owner": ..., "filename": ..., "original_hash": ...}
shares = {}    # (image_id, username) -> encrypted_aes_key


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html')


# ---------------------------------------------------------------------------
# User registration (generates RSA key pair)
# ---------------------------------------------------------------------------
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()

    if not username:
        return jsonify({"error": "Username required"}), 400
    if username in users:
        return jsonify({"error": "User already exists"}), 400

    public_key, private_key = crypto_utils.generate_rsa_keypair()
    users[username] = {"public_key": public_key, "private_key": private_key}

    return jsonify({"message": f"User '{username}' registered with a new RSA key pair."}), 201


@app.route('/users', methods=['GET'])
def list_users():
    return jsonify({"users": list(users.keys())})


# ---------------------------------------------------------------------------
# Upload + AES-encrypt an image
# ---------------------------------------------------------------------------
@app.route('/upload', methods=['POST'])
def upload():
    username = request.form.get('username', '').strip()
    if username not in users:
        return jsonify({"error": "Unknown user. Register first."}), 400
    if 'image' not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    image_file = request.files['image']
    image_bytes = image_file.read()
    original_hash = crypto_utils.get_sha256_hash(image_bytes)

    # --- AES layer: encrypt the actual image ---
    ciphertext, nonce, aes_key = crypto_utils.encrypt_image(image_bytes)

    image_id = str(uuid.uuid4())[:8]
    images[image_id] = {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "owner": username,
        "filename": image_file.filename,
        "original_hash": original_hash,
    }

    # --- RSA layer: wrap the AES key for the owner themselves (self-share) ---
    owner_public_key = users[username]["public_key"]
    encrypted_key_for_owner = crypto_utils.encrypt_aes_key_with_rsa(aes_key, owner_public_key)
    shares[(image_id, username)] = encrypted_key_for_owner

    return jsonify({
        "message": "Image encrypted and stored.",
        "image_id": image_id,
        "sha256": original_hash
    }), 201


# ---------------------------------------------------------------------------
# Share an already-uploaded image with another user
# ---------------------------------------------------------------------------
@app.route('/share', methods=['POST'])
def share():
    data = request.json
    image_id = data.get('image_id')
    from_user = data.get('from_username', '').strip()
    to_user = data.get('to_username', '').strip()

    if image_id not in images:
        return jsonify({"error": "Image not found"}), 404
    if to_user not in users:
        return jsonify({"error": "Recipient not registered"}), 400
    if (image_id, from_user) not in shares:
        return jsonify({"error": "You don't have access to this image"}), 403

    # Step 1: recover the AES key using the sharer's own RSA private key
    from_private_key = users[from_user]["private_key"]
    encrypted_key_for_from_user = shares[(image_id, from_user)]
    aes_key = crypto_utils.decrypt_aes_key_with_rsa(encrypted_key_for_from_user, from_private_key)

    # Step 2: re-wrap that same AES key using the recipient's RSA public key
    to_public_key = users[to_user]["public_key"]
    encrypted_key_for_to_user = crypto_utils.encrypt_aes_key_with_rsa(aes_key, to_public_key)
    shares[(image_id, to_user)] = encrypted_key_for_to_user

    return jsonify({"message": f"Image {image_id} shared with '{to_user}'."})


# ---------------------------------------------------------------------------
# List images visible to a given user
# ---------------------------------------------------------------------------
@app.route('/images/<username>', methods=['GET'])
def list_images(username):
    visible = [
        {"image_id": img_id, "filename": images[img_id]["filename"], "owner": images[img_id]["owner"]}
        for (img_id, user) in shares.keys()
        if user == username
    ]
    return jsonify({"images": visible})


# ---------------------------------------------------------------------------
# Decrypt and return an image for an authorized user
# ---------------------------------------------------------------------------
@app.route('/decrypt/<image_id>', methods=['GET'])
def decrypt(image_id):
    username = request.args.get('username', '').strip()

    if image_id not in images:
        return jsonify({"error": "Image not found"}), 404
    if (image_id, username) not in shares:
        return jsonify({"error": "Access denied — image not shared with this user"}), 403

    # Step 1: unwrap the AES key using this user's private key
    private_key = users[username]["private_key"]
    encrypted_key = shares[(image_id, username)]
    aes_key = crypto_utils.decrypt_aes_key_with_rsa(encrypted_key, private_key)

    # Step 2: decrypt the image itself (GCM also verifies integrity here)
    record = images[image_id]
    try:
        image_bytes = crypto_utils.decrypt_image(record["ciphertext"], record["nonce"], aes_key)
    except Exception:
        return jsonify({"error": "Integrity check failed — image may have been tampered with"}), 400

    # Optional explicit SHA-256 verification (in addition to GCM's built-in check)
    new_hash = crypto_utils.get_sha256_hash(image_bytes)
    verified = (new_hash == record["original_hash"])

    return send_file(
        io.BytesIO(image_bytes),
        mimetype='image/png',
        as_attachment=False,
        download_name=record["filename"]
    )



if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
