#!/bin/sh

expected=$1
actual=$2
shift 2

clean() {
    sed -r 's/"downtime":[0-9]+/"downtime":0/; s/line ([0-9]+): [0-9]+ Segm/line \1: 0 Segm/' $1
}

diff -u "$@" <(clean "$expected")  <(clean "$actual")
exit $?
