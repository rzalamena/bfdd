#!/bin/bash

scmd=$1
ccmd=$2

sh -c "$scmd" &
spid=$!

sh -c "$ccmd" &
cpid=$!

wait -np dedpid $spid $cpid

[ "$spid" = "$dedpid" ] || kill "$spid"
[ "$cpid" = "$dedpid" ] || kill "$cpid"
