CC	=	gcc
OBJS	=	bfdd.o bfd.o bfd_config.o bfd_event.o bfd_packet.o control.o log.o \
				util.o
BIN	=	bfdd

CFLAGS	+=	-Wall -Wextra -Og -ggdb
CFLAGS	+=	-Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
CFLAGS	+=	-Wshadow -Wpointer-arith -Wsign-compare

# Ignore 'uthash.h' warnings
CFLAGS	+=	-Wno-implicit-fallthrough

LDFLAGS	+=	-levent -ljson-c

.PHONY: all clean

all: ${BIN}

.c.o:
	${CC} ${CFLAGS} $< -c -o $@

${BIN}: ${OBJS}
	${CC} ${CFLAGS} ${OBJS} ${LDFLAGS} -o ${BIN}

clean:
	rm -f -- ${OBJS} ${BIN}
