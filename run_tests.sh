#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <patch>"
    echo "Example: $0 5517"
    exit 1
fi

PATCH="$1"
SCRIPT_DIR="$(dirname "$0")"
ORIGINAL_DIR="$SCRIPT_DIR/test/original"
DECRYPTED_DIR="$SCRIPT_DIR/test/decrypted"
ENCRYPTED_DIR="$SCRIPT_DIR/test/encrypted"
KEYPAIR_DIR="$SCRIPT_DIR/test/keypair"
CONQUER_EXE="$SCRIPT_DIR/test/exe/Conquer_${PATCH}.exe"

if [ ! -f "$CONQUER_EXE" ]; then
    echo "Error: $CONQUER_EXE not found"
    exit 1
fi

PRIVATE_KEY="$KEYPAIR_DIR/private_key.pem"
PUBLIC_KEY="$KEYPAIR_DIR/public_key.pem"

DAT_FILES=(
    MyAnimate.dat
    RaceTrackProp.dat
    Server.dat
    showhandlayout.dat
    ShowHandTable.dat
    suittype.dat
)

echo "Cleaning output directories"
rm -f "$DECRYPTED_DIR"/* "$ENCRYPTED_DIR"/* "$KEYPAIR_DIR"/*

EXTRACTED_KEY="$KEYPAIR_DIR/extracted_public_key.pem"

echo "Extracting RSA public key from binary"
python3 "$SCRIPT_DIR/extract_key.py" "$CONQUER_EXE" --out "$EXTRACTED_KEY"

echo "Decrypting DAT files"
for f in "${DAT_FILES[@]}"; do
    python3 "$SCRIPT_DIR/decrypt_game_file.py" \
        "$ORIGINAL_DIR/$f" \
        --pem "$EXTRACTED_KEY" \
        --out "$DECRYPTED_DIR/$f"
done

echo "First 5 lines of each decrypted file..."
for f in "${DAT_FILES[@]}"; do
    echo "***********************************"
    echo "$f"
    head -n 5 "$DECRYPTED_DIR/$f"
    echo "***********************************"
done

echo "Generating RSA keypair"
openssl genrsa -out "$PRIVATE_KEY" 2048
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
echo "Private key: $PRIVATE_KEY"
echo "Public key: $PUBLIC_KEY"

echo "Encrypting DAT files"
for f in "${DAT_FILES[@]}"; do
    python3 "$SCRIPT_DIR/encrypt_game_file.py" \
        "$DECRYPTED_DIR/$f" \
        "$PRIVATE_KEY" \
        --out "$ENCRYPTED_DIR/$f"
done

echo "Patching Conquer.exe"
python3 "$SCRIPT_DIR/patch_client_binary.py" \
    "$CONQUER_EXE" \
    "$PUBLIC_KEY" \
    --out "$ENCRYPTED_DIR/Conquer_${PATCH}_patched.exe"
