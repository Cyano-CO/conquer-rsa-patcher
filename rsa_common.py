import struct
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

START_ORIGINAL_MODULUS = 0xA0AF3D5C # First uint32 of the obfuscated modulus array in the client binary
END_ORIGINAL_MODULUS   = 0x2220F2A7 # Last uint32 of the obfuscated modulus array in the client binary
XOR_START_IDX = 17 # Starting position for XOR loop (hardcoded in client)
RSA_EXPONENT = 65537 # Standard RSA public exponent
GZIP_WBITS = 31 # gzip format for both compress and decompress
CHUNK_SIZE = 245 # Max plaintext bytes per 256-byte RSA block after PKCS#1


def _get_next_offset(bin_data, pos):
    """
    Return the offset of the next modulus word by stepping over the instruction encoding after pos.
    Handles both inline MOV instructions (Windows) and contiguous static arrays (Mac).
    """
    
    b = bin_data[pos + 4:pos + 6]
    
    # Windows Conquer Binary
    if b == b'\xC7\x85':
        return pos + 10  # (Windows) Instruction: MOV [ebp+disp32]
    if b == b'\xC7\x45': 
        return pos + 7   # (Windows) Instruction: MOV [ebp+disp8]
    if 0xB8 <= bin_data[pos + 4] <= 0xBF:
        return pos + 5   # (Windows) Instruction: MOV reg (Used only for the last word)
    
    return pos + 4       # (Windows) Last resort fallback, may probably fail


def _skip_junk_instructions(bin_data, pos):
    """
    On some older windows binaries, there are junk instructions mid-array, we need to skip those
    """
    while True:
        b = bin_data[pos:pos + 2]
        if b == b'\xC7\x85': return pos + 6
        if b == b'\xC7\x45': return pos + 3
        if 0xB8 <= bin_data[pos] <= 0xBF: return pos + 1 
        pos += 1


def find_modulus_offsets(bin_data):
    """
    Search a Conquer.exe binary for all 64 obfuscated modulus imm32 values.
    Returns a list of 64 file offsets, one per value.
    See: https://github.com/conquer-online/wiki/blob/main/src/security/rsa.md
    """
    start_bytes = struct.pack("<I", START_ORIGINAL_MODULUS)
    end_bytes   = struct.pack("<I", END_ORIGINAL_MODULUS)

    pos = 0
    while True:
        offset = bin_data.find(start_bytes, pos)
        if offset == -1:
            raise ValueError(
                "Could not find original obfuscated modulus in the binary. "
                "Unsupported Conquer.exe patch or the binary already patched?"
            )

        # Try contiguous array extraction first (Mac Binaries)
        contiguous = [offset + i * 4 for i in range(64)]
        if bin_data[contiguous[63]:contiguous[63] + 4] == end_bytes:
            return contiguous

        # Fall back to instruction-scanning (Windows Binaries)
        offsets = [offset]
        end_offset = None
        for _ in range(63):
            next_offset = _get_next_offset(bin_data, offsets[-1])
            if bin_data[next_offset:next_offset + 4] == end_bytes and end_offset is None:
                end_offset = next_offset
                next_offset = _skip_junk_instructions(bin_data, next_offset + 4)
            offsets.append(next_offset)

        if end_offset:
            offsets[-1] = end_offset

        if bin_data[offsets[63]:offsets[63] + 4] == end_bytes:
            return offsets

        pos = offset + 1


def load_pem_modulus_n(pem_path):
    """
    Load a 2048-bit RSA public key PEM and return the modulus as an integer.
    """
    with open(pem_path, "rb") as f:
        data = f.read()

    if b"PRIVATE KEY" in data:
        raise ValueError(f"{pem_path} is a private key. Please supply the public key instead.")

    key = load_pem_public_key(data)

    if not isinstance(key, RSAPublicKey) or key.key_size != 2048:
        raise ValueError("PEM must be a 2048-bit RSA public key.")

    return key.public_numbers().n


def load_pem_private_key_integers(pem_path):
    """
    Load a 2048-bit RSA private key PEM and return as integers.
    """
    with open(pem_path, "rb") as f:
        key = load_pem_private_key(f.read(), password=None)

    if not isinstance(key, RSAPrivateKey) or key.key_size != 2048:
        raise ValueError("PEM must be a 2048-bit RSA private key.")

    nums = key.private_numbers()
    return nums.d, nums.public_numbers.n
