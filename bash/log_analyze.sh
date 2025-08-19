#!/bin/bash

path_log=${PWD%/*}/src/LACED_LOG.txt
echo "path log $path_log"

if [ ! -f "$path_log" ]; then
    echo "missing log file - LACED_LOG.txt"
    exit 1
fi

total_lines=$(wc -l < "$path_log")
error_count=$(grep -c -i "ERROR" "$path_log")
mapfile -t events < <(grep -n -i "ERROR" "$path_log")

declare -A map_error_msg
while IFS= read -r line; do
    error_msg=$(awk '{for (i=3; i<=NF; ++i) printf "%s ", $i }' <<< $line | sed 's/ $//')
    if [[ "$error_msg" =~ EXIT ]]; then
        continue
    fi
    ((map_error_msg["$error_msg"]++))
done < <(grep -i "ERROR" "$path_log")


sorted_messages=$(for key in "${!map_error_msg[@]}"; do
    echo "${map_error_msg[$key]} $key"
done | sort -rn | head -n 5)


summary_report="log_summary"
{
    echo "Date: $(date)"
    echo "log_file $path_log"
    echo "Total Lines: $total_lines"
    echo "Total error: $error_count"
    echo -e "\nTop 5 error messages:"
    echo "$sorted_messages"
    echo -e "\nevents"
    for even in "${events[@]}"; do
        if [[ ! "$even" =~ EXIT ]]; then
            echo "$even"
        fi
    done
} > "$summary_report"

echo "summary_report: $summary_report"


if [ $# -ne 0 ] && [ $1 = "cleanup" ]; then
    cat /dev/null > "$path_log"
fi
