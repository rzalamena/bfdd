#!/bin/sh

. ./common.sh

# A minimal test to test the test framework itself,
# and an example of how to write tests.

# Check if we can execute bfdctl
echo "======= EXECUTABLE CHECK ======="
run --help

# Check if we can connect to the control socket. Twice.
# To make sure run_tm's timeout works correctly,
# and that the output gets captured in order.

echo "======= CONTROL SOCKET CHECK ======="
run_tm -M
run_tm -M m
