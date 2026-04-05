import struct, argparse
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from rsa_common import find_modulus_offsets, XOR_START_IDX

DEFAULT_OUT = "extracted_public_key.pem"


def extract_modulus_from_binary(exe_path):
    """
    Locate and deobfuscate the RSA modulus from a Conquer.exe binary.
    See: https://github.com/conquer-online/wiki/blob/main/src/security/rsa.md#decryption
    """
    with open(exe_path, "rb") as f:
        bin_data = f.read()

    offsets = find_modulus_offsets(bin_data)
    obfuscated = [struct.unpack_from("<I", bin_data, off)[0] for off in offsets]

    # Rolling XOR deobfuscation
    modulus_words = [0] * 64
    idx = XOR_START_IDX
    for j in range(63):
        modulus_words[idx % 64] = obfuscated[j] ^ obfuscated[j + 1]
        idx += 1
    modulus_words[idx % 64] = obfuscated[63]

    n = 0
    for w in modulus_words:
        n = (n << 32) | w
    return n


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract the original RSA public key from a Conquer.exe binary and save as a PEM file."
    )
    parser.add_argument("conquer_exe", help="Path to the original Conquer.exe")
    parser.add_argument("--out", default=DEFAULT_OUT, help=f"Output PEM file path (default: {DEFAULT_OUT})")
    args = parser.parse_args()

    n = extract_modulus_from_binary(args.conquer_exe)
    pub_key = RSAPublicNumbers(e=65537, n=n).public_key()
    pem_bytes = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    with open(args.out, "wb") as f:
        f.write(pem_bytes)
    print(f"Original RSA public key written to: {args.out}")
