#!/bin/bash

echo "laced setup" $(date '+%d-%m %H:%M:%S')

path="$(dirname "$(realpath "$0")")"
path_bin="$(realpath "$(dirname "$0")/../src")"
path_service="$(realpath "$(dirname "$0")/..")"
path_usr="/usr/local/bin"
path_sstd="/etc/systemd/system"
name_service="laced.service"
name_conf="/etc/laced"
name_log="/var/log/laced"

make -C "$path_bin" -f "$path_bin/Makefile.linux" 2>&1 | grep -v -E "Nothing to be done|Leaving directory|Entering directory"
exit=${PIPESTATUS[0]}

if [ $exit -ne 0 ]; then
    echo "error build laced"
    exit 1
else
    echo "success build laced"
fi

if [ -f "$path_usr/laced" ]; then
    sudo cp -f "$path_bin/laced" "$path_usr/laced"
    sudo chmod 755 "$path_usr/laced"
fi

sudo mkdir -p "$name_conf" &&  sudo touch "$name_conf/config.laced" && sudo chmod 666 "$name_conf/config.laced"
sudo mkdir -p "$name_log" && sudo touch "$name_log/laced.log" && sudo chmod 666 "$name_log/laced.log"

user=${SUDO_USER:-$(whoami)}
group=$(id -gn "$user")

sudo rm -f "$path_sstd/$name_service"
sed -e "s/{{USER}}/$user/g" \
    -e "s/{{GROUP}}/$group/g" \
    "$path_service/$name_service" > "$path_sstd/$name_service"

echo "successfull install"