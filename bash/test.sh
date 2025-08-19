#!/bin/bash

echo "laced" $(date '+%d-%m %H:%M:%S')

mkdir -p keys
path="$(realpath keys)"
help='--help'

pub_key=$path/RSA_public_key_laced.txt
prv_key=$path/RSA_private_key_laced.txt

if [ ! -f "$pub_key" ] || [ ! -f "$prv_key" ]; then
    ../src/laced -g -p $path -b64 -b 4096
fi
success=$?


if [ "$success" -ne 0 ] || [ ! -d "$path" ] || [ ! -f "$pub_key" ] || [ ! -f "$prv_key" ]; then
    echo "failed generate keys"
    exit 1
fi

if [ $# -eq 0 ]; then
    read -e -p "path to encrypt: " path_enc
elif [ -d "$1" ]; then
    path_enc="$1"
elif [ -z $path_enc ]; then
    echo "Failed; Provide a valid directory path to encrypt"
    exit 1
fi


#../src/laced -p "$path_enc" -c indir --algo chacha  -k "asd" -d
echo "yes" | ../src/laced -p "$path_enc" -c indir --algo rsa_aes -b64 -k $pub_key $ $prv_key -s --hashsum -d crypt
echo "yes" | ../src/laced -p "$path_enc" -c indir --algo rsa_aes -b64 -k $pub_key $ $prv_key -s --hashsum -d decrypt

echo -e "\033[0;29m"

./log_analyze.sh
