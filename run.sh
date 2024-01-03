#!/bin/bash

output_file="results_slice4_vec.txt"
echo -n > "$output_file"


i=1
while [ $i -le 100 ]
do
    result=$(./newattack)
    
    echo -n "$result" >> "$output_file"
    if [ $i -lt 100 ]; then
        echo -n "," >> "$output_file"
    fi

    i=$((i+1))
done