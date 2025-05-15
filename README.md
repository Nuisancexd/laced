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
   -h / -help       Provides Information about program.
   config           Load parameters from config. Configure from the local path or use
		    '-path' followed by the path to the configuration.
   -s / -sign       Signature and Verification (default: false). When using the signature
		    first specify the public key, followed by the private key, separating them with the '$' symbol.
   -p / -path       Path to the file to encrypt. Optional field. If null, encrypts in local path.
   -n / -name       Encrypt FILENAME with Base64. (default: false)
   -m / -mode       Select the encryption mode. (default: FULL_ENCRYPT)
                    a / auto -- AUTO_ENCRYPT: File size <= 1 MB uses full, <= 5 MB uses partly and > uses header
                    f / full -- FULL_ENCRYPT: Encrypts the entire file. Recommended for small files.
                    p / part -- PARTLY_ENCRYPT: Encrypts only part of the file.
                    h / head -- HEADER_ENCRYPT: Encrypts the first 1 MB of the file.
                    b / block -- BLOCK_ENCRYPT: Encrypts file in 1 MB blocks.
                    r / read -- READ_ENCRYPT: Read without overwriting a file. Only for symmetric encryption.

   -c / -cat        Encryption Category. (default: dir)
                    dir -- Encrypts all files in current directory.
                    indir -- Encrypts all files in subdirectories of the current directory.
                    file -- Encrypts a single file. The -path field must contain the full path to the file.

   -algo            Select the encryption type: asym, sym, or rsa. (default: null)
                    chacha    -- SYMMETRIC: uses ChaCha20 encryption.
                    aes       -- SYMMETRIC: uses AES256 CBE encryption.
                                   Type: crypt or decrypt. This is a required field. (default: null)
                    rsa_chacha -- HYBRID: uses RSA and ChaCha20 encryption.
                                   Type: crypt or decrypt. This is a required field. (default: null)
                    rsa_aes   -- HYBRID: uses RSA and AES256 CBE encryption.
                                   Type: crypt or decrypt. This is a required field. (default: null)
                    rsa       -- RSA_ONLY: uses only RSA encryption.
                                   Type: crypt or decrypt. This is a required field. (default: null)

   -k / -key        Required for HYBRID, ASYMMETRIC & SYMMETRIC encryption. This is a required field.
                    HYBRID & ASYMMETRIC: the full path to private/public RSA key.
                    SYMMETRIC: the secret key. The key size must be between 1 and 32 bytes.

   -iv              For SYMMETRIC: The initialization vector (IV). Size must be between 1 and 8 bytes. Optional field.
   -e / -enable     Enable the Thread Pool. By default, all logical CPU cores are used. (default: false)
   -B64 / -Base64   If RSA key is in Base64 format. (default: false)
   -d / -delete     File flag delete on close. (default: false)
   -ow / -overwrite Overwriting the original file. (default: false; zeros, count: 1)
                    zeros    -- ZEROS: overwrite the file with zeros.          
		    random   -- RANDOM: overwrite the file with random crypt symbols.
		    DOD      -- DOD: overwrite the file with zeros and random crypt symbols.
		    -count       Number of times to overwrite the file.

EXAMPLE USAGE:
Config:     laced config -path C:\Config.laced	laced config
ASYMMETRIC: laced -path C:/FolderFiles -name -mode full -cat dir -what asym -key "C:/FullPathToRSAkeys" crypt
SYMMETRIC:  laced -path C:/FolderFiles -name -mode full -cat dir -what sym -key "secret key"
RSA ONLY:   laced -path C:/File.txt -name -what rsa -key "C:/FullPathToRSAkeys" crypt
Signature:  laced -p C:/FolderFiles -w asym -k C:\key\public_RSA $ C:\key\private_RSA -s crypt
AES256:     laced -p C:/FolderFiles -w sym -k "key" -algo aes -delete de/crypt

RSA Generate Keys OPTIONS:

   Gen / RSAGenKey     Command to generate RSA keys. This is a required field.
   -B64 / -Base64      Save RSA keys in Base64 format. (default: false)
   -b / -bit           RSA key length. Available options: 2048, 3072, or 4096. (default: 4096)
   -p / -path          Path to save the generated keys. This is a required field.
   -print              Print the generated keys in HEX format. (default: false)

EXAMPLE USAGE:
laced.exe RSAGenKey -path C:/GenTofolder -B64 -bit 4096

Signature with Root RSA keys. Before signing the public key, you must first generate a key pair using the -print command
and then insert the byte array into the locker::LoadRootKey function and compile it.
   -s_g / -sign_root    Command options for signing with RootRSAKey.
   -sign                Signature with Root private key. (default: -sign)
   -verify              Verification with Root public key. (default: -sign)
   -p / -path           Path to the public key file. Required field.
EXAMPLE USAGE Signature:   laced.exe -sign_root -p C:/key/RSA_public_key_laced.txt -sign/-verify
```


 # Installation
This project builds with MSVC and MinGW (g++).
Clone the repository and build the project:
git clone https://github.com/Nuisancexd/laced.git
make -f Makefile.txt

## Contact
ilnur.sadykov.03@gmail.com

