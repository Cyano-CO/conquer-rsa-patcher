import re, struct, argparse
from rsa_common import find_modulus_offsets, load_pem_modulus_n, XOR_START_IDX



def load_pem_modulus_words(pem_path):
    """
    Load a RSA Public Key PEM File & Convert its modulus to 64 uint32 values
    """
    n = load_pem_modulus_n(pem_path)
    raw = n.to_bytes(256, "big")
    return [int.from_bytes(raw[i:i+4], "big") for i in range(0, 256, 4)]


def obfuscate(modulus_words):
    """
    Obfuscate the modulus (inverse of the deobfuscate performed in client).
    See: https://github.com/conquer-online/wiki/blob/main/src/security/rsa.md
    """
    obf = [0] * 64
    obf[63] = modulus_words[XOR_START_IDX - 1]

    for j in range(62, -1, -1):
        obf[j] = (modulus_words[(XOR_START_IDX + j) % 64] ^ obf[j + 1]) & 0xFFFFFFFF

    return obf


def patch_skip_play_exe(bin_data):
    """
    Remove the start with play.exe requirement.

    This makes use of the fact that you can run Conquer.exe with arg "blacknull" to bypass the play.exe
    So we do 2 binary patches so that this arg always appears to be set
    """
    try:
        # Patch 1: Patch number args conquer.exe ran with check (so args >=1 will always be true)
        argc_patterns = [
            (rb'\x83\xf8\x05\x0f\x94\xc1\x83\xf8\x01\x88\x0d....\x7d', 1, b'\xeb'), # 6090 (Find JGE, Patch to JMP)
            (rb'\x83\xbd..\xff\xff\x01\x0f\x8d', 2, b'\x90\xe9') # 5517/5187/5615 (Find JGE, Patch to JMP)
        ]
        for pattern, end_offset, patch in argc_patterns:
            m = re.search(pattern, bytes(bin_data))
            if m:
                bin_data[m.end() - end_offset:m.end() - end_offset + len(patch)] = patch
                print("Skip play.exe requirement patch 1 of 2 successful: argc count check (JGE -> JMP)")
                break
        else:
            raise ValueError("argc count check pattern not found")

        # Patch 2: Always true "blacknull" arg check (bn = blacknull)
        bn_patterns = [
            rb'\x61\x68....\x8d\x85....\x50\xff\x15....\x59\x59\x85\xc0', # 5517/5187/5615 (Find test eax,eax)
            rb'\x8d\x45\x1c\x68....\x50\xff\x15....\x59\x59\x85\xc0' # 6090+ (Find test eax,eax)
        ]
        for pattern in bn_patterns:
            match = re.search(pattern, bytes(bin_data), re.DOTALL)
            if match:
                bin_data[match.end() - 2] = 0x31  # test -> xor
                print("Skip play.exe requirement patch 2 of 2 successful: blacknull check (test -> xor)")
                break
        else:
            raise ValueError("blacknull pattern not found")


    except ValueError as e:
        print(f"Optional patch skip play.exe requirement failed: ({e}). "
              "Patched binary will still require play.exe to launch.")


def patch_binary(exe_path, pem_path, out_path, apply_skip_play_exe):
    with open(exe_path, "rb") as f:
        bin_data = bytearray(f.read())

    new_obf = obfuscate(load_pem_modulus_words(pem_path))
    print(f"Loaded obfuscated 2048-bit RSA modulus from: {pem_path}")

    offsets = find_modulus_offsets(bin_data)
    print(f"Found RSA obfuscated modulus offsets")
    for i in range(64): # Overwrite existing obfuscated modulus with new obfuscated one
        struct.pack_into("<I", bin_data, offsets[i], new_obf[i])

    if apply_skip_play_exe:
        patch_skip_play_exe(bin_data)

    with open(out_path, "wb") as f:
        f.write(bin_data)
    print(f"Success! Patched binary written to: {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Patch Conquer.exe with a custom RSA public key.")
    parser.add_argument("conquer_exe", help="Path to the original Conquer.exe")
    parser.add_argument("pem", help="Path to the RSA 2048-bit public key PEM file")
    parser.add_argument("--out", default="Conquer_modified.exe", help="Output binary path (default: Conquer_modified.exe)")
    parser.add_argument("--skip-patch-play-exe", action="store_true", help="Do not patch binary to bypass the play.exe launcher requirement")
    args = parser.parse_args()

    patch_binary(args.conquer_exe, args.pem, args.out, apply_skip_play_exe=not args.skip_patch_play_exe)
