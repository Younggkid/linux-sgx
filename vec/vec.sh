#!/bin/bash

output_file="eval_vec_L1.txt"
echo -n > "$output_file"


i=1
while [ $i -le 100 ]
do
    result=$(./app)
    
    echo -n "$result" >> "$output_file"
    if [ $i -lt 100 ]; then
        echo -n "," >> "$output_file"
    fi

    i=$((i+1))
done