#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef PTHREAD
#define PTHREAD
#endif

#ifndef HAVE_PF_RING
#define HAVE_PF_RING
#endif

#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>
#include <malloc.h>
#include <jemalloc/jemalloc.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <zmq.h>
#include <inttypes.h>
#include <sys/time.h>
#include <ctype.h>
#include <wchar.h>
#include <sched.h>

#include "capture.h"

#include "statsd-client.h"
