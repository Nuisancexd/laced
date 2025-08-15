#!/bin/bash


echo "laced"

mkdir -p keys
path="$(realpath keys)"
help='--help'

../src/laced -g -p $path -b64 -b 4096
success=$?

pub_key=$path/RSA_public_key_laced.txt
prv_key=$path/RSA_private_key_laced.txt


if [ "$success" -ne 0 ] || [ ! -d "$path" ] || [ ! -f "$pub_key" ] || [ ! -f "$prv_key" ]; then
    echo "failed generate keys"
    exit 1
fi

read -e -p "path to encrypt: " path_enc 

if [ -z "$path_enc" ]; then
echo 'enter ur path to encrypt'
exit 1
fi


#../src/laced -p "$path_enc" -c indir --algo chacha  -k "asd" -d
echo "yes" | ../src/laced -p "$path_enc" -c indir --algo rsa_aes -b64 -k $pub_key $ $prv_key -s --hashsum -d crypt
echo "yes" | ../src/laced -p "$path_enc" -c indir --algo rsa_aes -b64 -k $pub_key $ $prv_key -s --hashsum -d decrypt
