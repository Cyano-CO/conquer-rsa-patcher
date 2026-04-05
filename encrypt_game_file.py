import argparse, zlib
from rsa_common import load_pem_private_key_integers, CHUNK_SIZE, GZIP_WBITS


def encrypt_file(data_path, private_exponent, modulus, out_path):
    """
    Encrypt a plaintext game data file for Conquer.
    Gzip-compresses the data, splits into chunks, applies PKCS#1 type 1 padding,
    then RSA private-encrypts each chunk into a 256-byte block.
    """
    with open(data_path, "rb") as f:
        data = f.read()

    compressed = zlib.compress(data, wbits=GZIP_WBITS)

    cipher_text = b""
    for i in range(0, len(compressed), CHUNK_SIZE):
        chunk = compressed[i:i + CHUNK_SIZE]
        padding_len = 256 - 3 - len(chunk)
        padded = bytes([0x00, 0x01]) + bytes([0xFF] * padding_len) + bytes([0x00]) + chunk
        m = int.from_bytes(padded, "big")
        cipher_text += pow(m, private_exponent, modulus).to_bytes(256, "big")

    with open(out_path, "wb") as f:
        f.write(cipher_text)
    print(f"Encrypted file written to: {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt a Conquer game data file with an RSA private key.")
    parser.add_argument("data_file", help="Path to the plaintext game data file to encrypt")
    parser.add_argument("pem", help="Path to the RSA 2048-bit private key PEM file")
    parser.add_argument("--out", help="Output file path (default: <data_file>_encrypted.<ext>)")
    args = parser.parse_args()

    private_exponent, modulus = load_pem_private_key_integers(args.pem)
    print(f"Loaded RSA private key from: {args.pem}")

    if args.out:
        out_path = args.out
    else:
        name, ext = args.data_file.rsplit(".", 1)
        if "decrypted" in name:
            out_path = f"{name.replace('decrypted', 'encrypted')}.{ext}"
        else:
            out_path = f"{name}_encrypted.{ext}"

    encrypt_file(args.data_file, private_exponent, modulus, out_path)
