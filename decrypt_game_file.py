import argparse, zlib
from rsa_common import load_pem_modulus_n, RSA_EXPONENT, GZIP_WBITS

DEFAULT_PEM = "extracted_public_key.pem"


def decrypt_file(data_path, n, out_path):
    """
    Decrypt a Conquer RSA-encrypted game data file.
    Splits into 256-byte blocks, RSA public-decrypts each, strip padding,
    concatenates, then gzip-decompresses.
    """
    with open(data_path, "rb") as f:
        data = f.read()

    payload = b""
    for i in range(0, len(data), 256):
        block = int.from_bytes(data[i:i + 256], "big")
        chunk = pow(block, RSA_EXPONENT, n).to_bytes(256, "big")
        padding_end = chunk.index(b"\x00", 2) # PKCS#1 Padding
        payload += chunk[padding_end + 1:]

    with open(out_path, "wb") as f:
        f.write(zlib.decompress(payload, wbits=GZIP_WBITS))
    print(f"Successfully decrypted file written to: {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt a Conquer RSA-encrypted game data file.")
    parser.add_argument("data_file", help="Path to the encrypted game data file")
    parser.add_argument("--out", help="Output file path (default: <data_file>_decrypted.<ext>)")
    parser.add_argument("--pem", default=DEFAULT_PEM, help=f"RSA public key PEM file (default: {DEFAULT_PEM})")
    args = parser.parse_args()

    try:
        n = load_pem_modulus_n(args.pem)
        print(f"Using RSA modulus from PEM: {args.pem}")
    except FileNotFoundError:
        parser.error(
            f"Key file '{args.pem}' not found. "
            f"Run 'python extract_key.py Conquer.exe' to extract from binary first, or supply your own key with --pem."
        )

    if args.out:
        out_path = args.out
    else:
        name, ext = args.data_file.rsplit(".", 1)
        out_path = f"{name}_decrypted.{ext}"

    decrypt_file(args.data_file, n, out_path)
