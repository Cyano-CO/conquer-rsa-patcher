#!/bin/bash
set -e

OUT_DIR="$(dirname "$0")"

PRIVATE_KEY="$OUT_DIR/private_key.pem"
PUBLIC_KEY="$OUT_DIR/public_key.pem"

echo "Generating 2048-bit RSA keypair..."
openssl genrsa -out "$PRIVATE_KEY" 2048
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

echo "Private key: $PRIVATE_KEY (Use it in encrypt_game_file.py)"
echo "Public key:  $PUBLIC_KEY (Use it in patch_client_binary.py & decrypt_game_file.py)"
