#!/bin/bash

ADDFLOWSFILE=/etc/opennop/opennop-addflows.sh

cat $ADDFLOWSFILE | grep -v -e '^#' -e '^$' | \
while read line
do
    newline="${line/ -A / -D }"
    echo "--"
    echo "-- Deleting rule $newline"
    echo "--"
    $newline
done 

