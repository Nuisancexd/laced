# Laced - File Encryption Toolkit
Laced is a command-line cryptography toolkit for encrypting files, generating keys, signing, hashing, and secure file operations.

## Features:
* Hybrid encryption encrypts a random symmetric key (ChaCha20 or AES) using RSA and then encrypts the file with that symmetric key
* RSA encryption the data using RSA
* Symmetric encryption data using a secret key with ChaCha20 or AES
* RSA key generation - RSA public/private key pairs (supports Base64 export)
* Digital signatures files or RSA public keys to verify their authenticity and integrity
 
## Usage Options:
```shell
laced - crypto line program. version 1.0
laced -h/--help -- provides general instructions

laced [command] [options ... ] [ parameters ... ]
DESCRIPTION
LACED is a cryptography toolkit implementing crpyto standarts.
The laced program is a command-line utility providing various crypto funcs:
o  Uses for RSA crypt/gen OpenSSL for Linux, BCrypt for Win
o  Generation of public/private RSA keys
o  Symmetric encryption (ChaCha20, AES256)
o  Hybrid encryption (RSA + ChaCha20 / AES256)
o  RSA encryption and decryption
o  Digital sigantures and verification
o  File hashing with SHA256
o  Base64 encoding/decoding
o  Secure file overwrite
o  Recursive directory encryption
o  Thread pool parallel processing
```

## Key options summary
- **Input/output:** `--path`, `--out`, `--config`, `--name`
- **Encryption mode:** `--mode`, `--cat`
- **Algorithm:** `-al`
- **Key management:** `--key`, `--base64`, `--gen`, `--bit`
- **Performance:** `--en_thread`, `--throttling`
- **Security:** `--sign`, `-ow`/`-rw`, `--delete`
- **Logging:** `--nolog`, `--nout`

 # Installation
This project builds with g++.
Clone the repository and build the project:
```bash
git clone https://github.com/Nuisancexd/laced.git
cd laced/src
make
```

## Contact
ilnur.sadykov.03@gmail.com

