#!/bin/bash

output_file="results_slice4_vec.txt"
echo -n > "$output_file"

i=1

# 先运行50次但不记录数据
while [ $i -le 50 ]
do
    ./newattack >/dev/null  # 执行可执行文件但将输出重定向到/dev/null
    i=$((i+1))
done

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