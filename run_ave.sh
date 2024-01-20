#!/bin/bash

total_result=0
i=1

while [ $i -le 10 ]
do
    result=$(./newattack)
    
    total_result=$((total_result + result))

    if [ $i -lt 10 ]; then
        echo -n ","
    fi

    i=$((i+1))
done

average_result=$((total_result / 10))
echo "Average Result: $average_result"