#!/bin/bash

echo "laced setup" $(date '+%d-%m %H:%M:%S')

path="$(dirname "$(realpath "$0")")"
path_bin="$(realpath "$(dirname "$0")/../src")"
path_service="$(realpath "$(dirname "$0")/..")"
path_usr="/usr/local/bin"
path_sstd="/etc/systemd/system"
name_service="laced.service"

sudo rm "$path_usr/laced"
sudo cp "$path_bin/laced" "$path_usr"
sudo chmod 700 "$path_usr/laced"
sudo rm -f "$path_sstd/$name_service"
sudo cp "$path_service/$name_service" "$path_sstd"