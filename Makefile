CC	=	gcc
OBJS	=	bfdd.o bfd.o bfd_config.o bfd_event.o bfd_packet.o control.o log.o \
				util.o
BIN	=	bfdd
CTRLBIN	=	bfdctl

CFLAGS	+=	-Wall -Wextra -Og -ggdb
CFLAGS	+=	-Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
CFLAGS	+=	-Wshadow -Wpointer-arith -Wsign-compare

# Ignore 'uthash.h' warnings
CFLAGS	+=	-Wno-implicit-fallthrough

LDFLAGS	+=	-levent -ljson-c

# Enable verbose event debugs
# CFLAGS += -DBFD_EVENT_DEBUG

.PHONY: all clean

all: ${BIN} ${CTRLBIN}

.c.o:
	${CC} ${CFLAGS} $< -c -o $@

${BIN}: ${OBJS}
	${CC} ${CFLAGS} ${OBJS} ${LDFLAGS} -o ${BIN}

${CTRLBIN}: bfdctl.c
	${CC} ${CFLAGS} bfdctl.c -ljson-c -o $@

clean:
	rm -f -- ${OBJS} ${BIN} ${CTRLBIN}
