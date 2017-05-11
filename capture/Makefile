#MY_DEF = -DBENCHMARK_1 

WARNCFLAGS = -Wall -Wextra -W -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wno-variadic-macros

EXTRA_LIBS = -L/usr/local/lib -I/usr/local/include

PFRINGDIR  = /usr/local/lib
LIBPFRING  = ${PFRINGDIR}/libpfring.a 

LIBPCAP    = /usr/local/lib/libpcap.a
LIBPCAPDIR = /opt/libpcap/include 

ZMQ_LIBS   = -lzmq

STATSD_CLIENT = -lstatsdclient -I/usr/include/statsd-c-client

PFRING_KERNEL= /usr/local/include

INCLUDE    = -I${PFRING_KERNEL} -I${PFRINGDIR} -I${LIBPCAPDIR} ${STATSD_CLIENT} ${EXTRA_LIBS}

O_FLAG     = -O2 -g -pipe -fpic -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fno-strict-aliasing -fwrapv

CC         = gcc -std=c99 ${MY_DEF}
CFLAGS     = ${O_FLAG} ${WARNCFLAGS} ${INCLUDE} -D ENABLE_BPF -D HAVE_LIBNUMA -DHAVE_PF_RING 

LDFLAGS		= -flto -lrt -Wl,--as-needed

LIBS       = -lpthread -lrt -lnuma -ljemalloc -lm  -losipparser2

OBJS    = ${LIBPFRING} ${LIBPCAP} capture-parser-osip.o lib/base64/lib/libbase64.o 

TARGETS = capture-cap capture-parser capture-result-collector base64

all: ${TARGETS}

%.o: %.c
	@echo ""
	@echo "=== making object $@ ==="
	@echo ""
	${CC} ${CFLAGS} ${INCLUDE} -c $< -o $@

capture-cap: capture.o capture-cap.o ${OBJS}
	${CC} ${LDFLAGS} ${CFLAGS} ${LIBS} -lpfring ${LIBPCAP} ${ZMQ_LIBS} ${LIBPFRING} ${LIBPCAP} -o $@ capture-cap.o capture.o $(OBJS)

capture: capture.o
	@echo ""
	@echo "=== $@ ignored ==="
	@echo ""

capture-parser: capture.o capture-parser.o base64 $(OBJS)
	${CC} ${LDFLAGS} ${CFLAGS} ${LIBS} ${ZMQ_LIBS} -o $@ capture.o capture-parser.o $(OBJS)

capture-result-collector: capture-result-collector.o capture.o
	${CC} ${LDFLAGS} ${CFLAGS} ${LIBS} ${ZMQ_LIBS} -o $@ capture-result-collector.o capture.o

lib/base64/lib/libbase64.o: base64
base64:
	cd lib/base64/ && $(MAKE) all


.PHONY: clean

base64-clean:
	@echo ""
	@echo "=== $@ clean ==="
	@echo ""
	
	cd lib/base64/ && $(MAKE) clean

clean: base64-clean
	@echo ""
	@echo "=== $@ clean ==="
	@echo ""
	@rm -fv ${TARGETS} *.o *~


# valgrind --leak-check=full --show-possibly-lost=yes --show-reachable=yes --leak-resolution=high --track-origins=yes ./capture-cap -i lxcbr0  -z tcp://127.0.0.1:5556  -o /dev/shm/pcap -v
