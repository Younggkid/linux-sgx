#!/bin/bash

output_file="results_mince_l2_double.txt"
echo -n > "$output_file"

i=1
total_sum=0
while [ $i -le 100 ]
do
    result=$(./app)
    echo "$result" >> "$output_file"
    total_sum=$((total_sum + result))
    i=$((i+1))
done

average=$(echo "scale=2; $total_sum / 100" | bc)
echo "Average: $average"