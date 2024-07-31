#!/bin/bash
i=1
while [ $i -le 100 ]
do
    ./app
    echo -e "\003"
    i=$((i+1))
done