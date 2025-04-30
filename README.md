# Laced Hybrid Encryption, Symmetric Encryption and RSA Only by key.

A encryption tool implementing both hybrid encryption (RSA + ChaCha), pure asymmetric encryption (RSA) and symmetric encryption (ChaCha).

## Options:
* Hybrid encryption: encrypts a random symmetric key (ChaCha) with RSA.
* Pure RSA encryption: encrypts data directly using RSA.
* Pure ChaCha encryption: encrypts data with secret key using ChaCha.
* Generate RSA pair (public and private) keys.
* Signature: This module is responsible for digitally signing file hash values as well as signing the public key to ensure its authenticity and integrity.

 
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

   -w / -what       Select the encryption type: asym, sym, or rsa. (default: null)
                    asym -- ASYMMETRIC: uses RSA and ChaCha20 encryption.
                    Type: crypt or decrypt. This is a required field. (default: null)
                    sym -- SYMMETRIC: uses only ChaCha20 encryption.
                    rsa -- RSA_ONLY: uses only RSA encryption.
                    Type: crypt or decrypt. This is a required field. (default: null)

   -k / -key        Required for ASYMMETRIC & SYMMETRIC encryption.
                    - ASYMMETRIC: the full path to the private/public RSA key.
                    - SYMMETRIC: the secret key. The key size must be between 1 and 32 bytes.

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
Config:     laced.exe config -path C:\Config.laced	laced.exe config
ASYMMETRIC: laced.exe -path C:/FolderFiles -name -mode full -cat dir -what asym -key "C:/FullPathToRSAkeys" crypt
SYMMETRIC:  laced.exe -path C:/FolderFiles -name -mode full -cat dir -what sym -key "secret key"
RSA ONLY:   laced.exe -path C:/File.txt -name -what rsa -key "C:/FullPathToRSAkeys" crypt
Signature:  laced.exe -p C:/FolderFiles -w asym -k C:\key\public_RSA $ C:\key\private_RSA -s crypt

RSA Generate Keys OPTIONS:

   Gen / RSAGenKey     Command to generate RSA keys. This is a required field.
   -B64 / -Base64      Save RSA keys in Base64 format. (default: false)
   -b / -bit           RSA key length. Available options: 1024, 2048, or 4096. (default: 2048)
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
This project can be compiled with both MSVC (Microsoft Visual C++) and g++ (GNU Compiler Collection).
Clone the repository and build the project:
git clone https://github.com/Nuisancexd/laced.git
make -f Makefile.txt

# Download 
Download the laced.exe from the [Releases] https://github.com/Nuisancexd/laced/releases/tag/Crypt section.  

* OS: Windows 10
* Architecture: x86
* Compiler Support: MSVC, MinGW (G++)
This program is only compatible with Windows 10 (x86).
It does not support 64-bit versions or other operating systems.

## Contact
ilnur.sadykov.03@gmail.com

