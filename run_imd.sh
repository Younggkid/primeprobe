#!/bin/bash

output_file="results_slice4_vec.txt"
echo -n > "$output_file"

i=1
# 后100次运行并记录数据
while [ $i -le 150 ]
do
    result=$(./newattack)
    
    echo -n "$result" >> "$output_file"
    if [ $i -lt 150 ]; then
        echo -n "," >> "$output_file"
    fi

    i=$((i+1))
done