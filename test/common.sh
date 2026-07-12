BFDCTL_BIN="${CTRLBIN}"
SOCK=${CTRLSOCK}

do_run() {
    timeout=$1
    shift
    echo ""
    echo "----" "$BFDCTL_BIN" -C "$SOCK" "$@"
    echo ""
    if [ -z "$timeout" ]; then
        "$BFDCTL_BIN" -C "$SOCK" "$@"
    else
        "$BFDCTL_BIN" -C "$SOCK" "$@" &
        pid=$!
        sleep "$timeout"
        kill $pid 2>/dev/null
    fi
}

run() {
    do_run "" "$@"
}

run_tm() {
    do_run 0.5 "$@"
}
