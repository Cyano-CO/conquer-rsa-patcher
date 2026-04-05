# Conquer Online - RSA DAT Decrypt/Encrypt & Binary Patcher

Tools for working with the RSA public key baked into the Conquer Online client binary and encrypting/decrypting RSA-protected game data files. See: [DAT File Format](https://github.com/conquer-online/wiki/blob/main/src/files/formats/dat.md) for a list of applicable files.

See the [RSA wiki page](https://github.com/conquer-online/wiki/blob/main/src/security/rsa.md) for full technical background. 

## Table of Contents

- [Setup](#setup)
- [Scripts](#scripts)
  - [`extract_key.py`](#extract_keypy)
  - [`decrypt_game_file.py`](#decrypt_game_filepy)
  - [`generate_keypair.sh`](#generate_keypairsh)
  - [`encrypt_game_file.py`](#encrypt_game_filepy)
  - [`patch_client_binary.py`](#patch_client_binarypy)
- [Typical Workflow](#typical-workflow)

> [!WARNING]
> **Disclaimer**
> - All information and techniques used here are derived solely from the publicly distributed client binaries. The extracted key is an RSA public key and is therefore public by design, no private keys or confidential information were used or obtained.
> - This project is intended for experimental, research, and educational purposes only.
> - Do **NOT** attempt to patch latest versions as patched client modifications will almost certainly be detected & account will be banned.
> - No warranty given. As with all code, read & understand it before executing it.

> [!NOTE]
> The `Conquer.exe` binary is not included and must be supplied by you.


### Setup

You can run these scripts on Linux, MacOS or Windows via [WSL](https://learn.microsoft.com/en-us/windows/wsl/install).

These scripts require **Python 3.6+**. Download & install from [python.org](https://www.python.org/downloads/).

Clone this repository. These scripts require the `cryptography` package, install it if not already present:

```bash
pip install cryptography
```

## Scripts

### `extract_key.py`

Extracts the RSA public key from a `Conquer.exe` binary and saves it as a PEM file. Run this once before using `decrypt_game_file.py` to decrypt the original dat files

```bash
python3 extract_key.py <Conquer.exe> [--out <output.pem>]
```

| Argument      | Description                                           |
|---------------|-------------------------------------------------------|
| `conquer_exe` | Path to `Conquer.exe`                                 |
| `--out`       | Output PEM path (default: `extracted_public_key.pem`) |

---

### `decrypt_game_file.py`

Decrypts an RSA-encrypted Conquer game data file. Uses `extracted_public_key.pem` by default (run `extract_key.py` first), or specify your own public key with `--pem`.

```bash
python3 decrypt_game_file.py <data_file> [--out <output>] [--pem <public_key.pem>]
```

| Argument    | Description                                                   |
|-------------|---------------------------------------------------------------|
| `data_file` | Path to the encrypted game data file                          |
| `--out`     | Output path (default: `<data_file>_decrypted.<ext>`)          |
| `--pem`     | RSA public key PEM file (default: `extracted_public_key.pem`) |

---

### `generate_keypair.sh`

You will not be able to re-encrypt files without TQ's original private key. Instead you can generate your own 2048-bit RSA keypair via the bash script: 

```bash
./generate_keypair.sh
```

Outputs `private_key.pem` and `public_key.pem` in the same directory as the script. Any existing files will be overwritten!

---

### `encrypt_game_file.py`

Compresses and RSA encrypts a plaintext game data file using your private key.

```bash
python3 encrypt_game_file.py <data_file> <private_key.pem> [--out <output>]
```

| Argument    | Description                                                    |
|-------------|----------------------------------------------------------------|
| `data_file` | Path to the plaintext game data file                           |
| `pem`       | Path to your RSA 2048-bit private key PEM                      |
| `--out`     | Optional, output path (default: `<data_file>_encrypted.<ext>`) |

---

### `patch_client_binary.py`

Replaces the obfuscated RSA modulus in `Conquer.exe` with one derived from your own public key. The patched client will then only be able to decrypt game data files encrypted with your private key.

> [!WARNING]
>  **WARNING**
> After patching the client, all RSA-encrypted DAT files must be re-encrypted with your private key using `encrypt_game_file.py`. The original TQ-encrypted files will no longer be readable by the patched client.

```bash
python3 patch_client_binary.py <Conquer.exe> <public_key.pem> [--out <output.exe>] [--skip-patch-play-exe]
```

| Argument                | Description                                                               |
|-------------------------|---------------------------------------------------------------------------|
| `conquer_exe`           | Path to the original `Conquer.exe`                                        |
| `pem`                   | Path to your RSA 2048-bit public key PEM                                  |
| `--out`                 | Output path (default: `Conquer_modified.exe`)                             |
| `--skip-patch-play-exe` | Skip the play.exe launcher bypass patch (optional but applied by default) |

By default the patcher also bypasses the play.exe launcher requirement, allowing the patched binary to be launched directly. Use `--skip-patch-play-exe` to disable this. This is an optional feature and if it fails, RSA public key patch will continue

The following binary patches have been tested and works (other patches may also work but not tested):

| Patch          | Patch Public Key | Patch bypass play.exe | Game Runs  |
|:---------------|:-----------------|:----------------------|:-----------|
| 5187           | ✅                | ✅                     | ✅          |
| 5517 (Windows) | ✅                | ✅                     | ✅          |
| 5517 (Mac)     | ✅                | ❌                     | Not Tested |
| 5615           | ✅                | ✅                     | ✅          |
| 6090           | ✅                | ✅                     | ✅          |

## Typical Workflow

### Decrypting original game files

```
1. One Time: python3 extract_key.py Conquer.exe
2. python3 decrypt_game_file.py Server.dat
```

### Running with custom encryption

```
1. One Time: ./generate_keypair.sh
2. One Time: python3 patch_client_binary.py Conquer.exe public_key.pem
3. python3 encrypt_game_file.py server.dat private_key.pem
4. Copy the encrypted dat files to Conquer directory
5. Run Conquer_modified.exe
```
