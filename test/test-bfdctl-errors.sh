#!/bin/sh

. ./common.sh

# Extensively test CLI options for backwards compatibility

TEST_IP=127.0.0.2
TEST_LABEL="foo"

echo ""
echo "======= NO  OP / NO MON ======="
run
run -m
run -m -p "$TEST_IP"
run -p "$TEST_IP"

echo ""
echo "======= NO  OP /    MON ======="
run_tm -M
run_tm -M -m
run_tm -M -m -p "$TEST_IP"
run_tm -M -p "$TEST_IP"

echo ""
echo "======= ADD OP /    MON ======="
run_tm -M -a
run_tm -M -a -m
run_tm -M -a -m -p "$TEST_IP"
run_tm -M -a -p "$TEST_IP"

echo ""
echo "======= ADD OP / NO MON ======="
run -a
run -a -m
run -a -m -p "$TEST_IP"
run -a -p "$TEST_IP"

