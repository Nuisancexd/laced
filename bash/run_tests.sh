#!/bin/bash

echo "laced" $(date '+%d-%m %H:%M:%S')

function check_diff()
{
    if diff "$file_source" "$file_source_decrypt""/$name" > /dev/null; then
        echo "test: $1 passed"
    else
        echo "test: $1 not passed"
    fi
}

name="source_test_file"
path="$(pwd)"
mkdir -p "$(pwd)""/crypt"
mkdir -p "$(pwd)""/decrypt"

file_source="$path""/$name"
file_source_crypt="$path/crypt"
file_source_decrypt="$path/decrypt"
touch "$file_source"
dd if=/dev/urandom  of="$file_source" bs=512 count=1 status=none

echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" --algo chacha -k "key" -c file > /dev/null
echo "yes" | ../src/laced -p "$file_source_crypt" -o "$file_source_decrypt" --algo chacha -k "key" -d > /dev/null
check_diff CHACHA

echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" --algo aes -k "key" crypt -c file > /dev/null
echo "yes" | ../src/laced -p "$file_source" -o "$file_source_decrypt" --algo aes -k "key" -d decrypt > /dev/null
check_diff AES


path="$(pwd)""/keys"
mkdir -p "$path"

pub_key="$path/RSA_public_key_laced.txt"
prv_key="$path/RSA_private_key_laced.txt"

if [ ! -f "$pub_key" ] || [ ! -f "$prv_key" ]; then
    echo "generatin rsa key w/4096"
    ../src/laced -g -p "$path" -b64 -b 4096 > /dev/null
fi
success=$?


if [ "$success" -ne 0 ] || [ ! -d "$path" ] || [ ! -f "$pub_key" ] || [ ! -f "$prv_key" ]; then
    echo "failed generate keys"
    exit 1
fi

#if [ $# -eq 0 ]; then
#    read -e -p "path to encrypt: " path_enc
#elif [ -d "$1" ]; then
#    path_enc="$1"
#elif [ -z $path_enc ]; then
#    echo "Failed; Provide a valid directory path to encrypt"
#    exit 1
#fi

echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" -al rsa_aes -k $pub_key $ $prv_key -s --hashsum crypt -c file > /dev/null
echo "yes" | ../src/laced -p "$file_source" -o "$file_source_decrypt" -al rsa_aes -k $pub_key $ $prv_key -s --hashsum -d decrypt > /dev/null
check_diff RSA_AES

echo -e "\033[0;29m"

read -e -p "type any key"

rm "$file_source"
rm "$file_source_crypt""/$name"".laced"
rm "$file_source_decrypt""/$name"
rm "$pub_key"
rm "$prv_key"

exit 1

#./log_analyze.sh
