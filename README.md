# Laced - Hybrid, Symmetric, and Asymmetric Encryption Tool.

A versatile encryption tool implementing:
* Hybrid encryption (RSA + ChaCha20 / RSA + AES)
* Pure asymmetric encryption (RSA)
* Pure symmetric encryption (ChaCha20 or AES)
* supports digital signatures and RSA key generation.

## Options:
* Hybrid encryption
Encrypts a random symmetric key (ChaCha20 or AES) using RSA and then encrypts the file with that symmetric key.
* Pure RSA encryption
Encrypts the data directly using RSA.
* Pure symmetric encryption
Encrypts data using a secret key with ChaCha20 or AES.
* RSA key generation
* Generates RSA public/private key pairs (supports Base64 export).
* Digital signatures
Signs files or RSA public keys to verify their authenticity and integrity (supports Root key signing).
 
## Usage Options:
```shell
laced - crypto line program. version 1.0
laced -h/--help -- provides general instructions

laced [command] [options ... ] [ parameters ... ]
DESCRIPTION
LACED is a cryptography toolkit implementing crpyto standarts.
The laced program is a command-line utility providing various crypto funcs:
o  Uses for RSA crypt/gen OpenSSL for Linux, BCrypt for Win
o  Creation of public/private RSA keys
o  Symmetric encryption (ChaCha20, AES256)
o  Hybrid encryption (RSA + ChaCha20 / AES256)
o  Pure RSA encryption and decryption
o  Digital sigantures and verification
o  File hashing with SHA256
o  Base64 encoding/decoding
o  Secure file overwrite
o  Recursive directory encryption
o  Thread pool parallel processing
```


 # Installation
This project builds with MinGW (g++).
Clone the repository and build the project:
git clone https://github.com/Nuisancexd/laced.git
for Windows make -f Makefile.txt
for Linux   make

## Contact
ilnur.sadykov.03@gmail.com

