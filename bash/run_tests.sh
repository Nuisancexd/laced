#!/bin/bash

echo "laced" $(date '+%d-%m %H:%M:%S')

args=(-k key -al)

function check_diff()
{
    echo -e "\033[0;29m"
    if diff "$file_source" "$file_source_decrypt""/$name" > /dev/null; then
        echo "test: $1 passed"
    else
        echo "test: $1 not passed"
    fi
    clean
}

function clean()
{
    local dir="$1"

    if [ -d "$dir" ]; then
        rm -f "$dir"/*
    else
        rm -f "$file_source_crypt"/*
        rm -f "$file_source_decrypt"/*
    fi
}


name="source_test_file"
path="$(dirname "$(realpath "$0")")"
mkdir -p "$path/crypt"
mkdir -p "$path/decrypt"

file_source="$path/$name"
file_source_crypt="$path/crypt"
file_source_decrypt="$path/decrypt"
touch "$file_source"
dd if=/dev/urandom  of="$file_source" bs=400 count=1 status=none

echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" "${args[@]}" chacha -c file > /dev/null
echo "yes" | ../src/laced -p "$file_source_crypt" -o "$file_source_decrypt" "${args[@]}" chacha -d > /dev/null
check_diff CHACHA

echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" "${args[@]}" aes crypt -c file > /dev/null
echo "yes" | ../src/laced -p "$file_source_crypt" -o "$file_source_decrypt" "${args[@]}" aes -d decrypt > /dev/null
check_diff AES
echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" "${args[@]}" aes crypt -c file -m part > /dev/null
echo "yes" | ../src/laced -p "$file_source_crypt" -o "$file_source_decrypt" "${args[@]}" aes -d decrypt -m part > /dev/null
check_diff AES_MODE_PART
echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" "${args[@]}" aes crypt -c file -m head 2>&1 | grep "EncryptFileHeader"
clean
echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" "${args[@]}" aes crypt -c file -m block > /dev/null
echo "yes" | ../src/laced -p "$file_source_crypt" -o "$file_source_decrypt" "${args[@]}" aes -d decrypt -m block > /dev/null
check_diff AES_MODE_BLOCK

path_k="$path/keys"
mkdir -p "$path"

pub_key="$path_k/RSA_public_key_laced.txt"
prv_key="$path_k/RSA_private_key_laced.txt"

if [ ! -f "$pub_key" ] || [ ! -f "$prv_key" ]; then
    echo "generatin rsa key w/4096"
    ../src/laced -g -p "$path_k" -b64 -b 4096 > /dev/null
fi
success=$?


if [ "$success" -ne 0 ] || [ ! -d "$path_k" ] || [ ! -f "$pub_key" ] || [ ! -f "$prv_key" ]; then
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

echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" -al rsa -k $pub_key crypt -c file > /dev/null
echo "yes" | ../src/laced -p "$file_source_crypt" -o "$file_source_decrypt" -al rsa -k $prv_key decrypt > /dev/null
check_diff RSA

echo "yes" | ../src/laced -p "$file_source" -o "$file_source_crypt" -al rsa_aes -k $pub_key $ $prv_key -s crypt -c file 2>&1 | grep "VerifySignatureRSA"
echo "yes" | ../src/laced -p "$file_source_crypt" -o "$file_source_decrypt" -al rsa_aes -k $pub_key $ $prv_key -s decrypt 2>&1 | grep "VerifySignatureRSA"
check_diff RSA_AES

echo "yes" | ../src/laced -p "$file_source" --hashfile -c file 2>&1 | grep "HashSum"

cp "$file_source" "$file_source_crypt"
echo "yes" | ../src/laced -p "$file_source_crypt/$name" "${args[@]}" chacha -c file -wi > /dev/null
echo "yes" | ../src/laced -p "$file_source_crypt/$name.laced" "${args[@]}" chacha -c file -wi > /dev/null
cp "$file_source_crypt/$name" "$file_source_decrypt"
check_diff WRITE_IN


read -e -p "type any key"

clean "$path_k"
rm -f "$path/signature.laced.bin"
rm -f "$file_source"

exit 1

#./log_analyze.sh
