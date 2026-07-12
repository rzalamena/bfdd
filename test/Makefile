BIN      = ../bfdd
CTRLBIN  = ../bfdctl
CTRLSOCK = bfdd.sock

TESTS_OUT = $(addsuffix .out.actual,${TESTS})

COMMON    = Makefile with-server.sh diff.sh common.sh
TESTS     = test-bfdctl-minimal

export CTRLSOCK
export CTRLBIN

test: ${TESTS_OUT}

.PHONY: test clean

%.out.actual: %.sh %.out ${CTRLBIN} ${BIN} ${COMMON}
	LC_ALL=C ./with-server.sh '${BIN} -C ${CTRLSOCK}' './$< >$@ 2>&1'
	./diff.sh $*.out $@

clean:
	rm -f -- ${TESTS_OUT}
