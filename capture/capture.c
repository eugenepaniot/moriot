#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <features.h>
#include <sys/syscall.h>
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

extern int64_t 
clock_usecs (void) {
    // 10^-6
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return (int64_t) ((int64_t) ts.tv_sec * 1000000 + (int64_t) ts.tv_nsec / 1000);
}

extern long 
delta_time (struct timeval * now,
                 struct timeval * before) {
    time_t delta_seconds;
    time_t delta_microseconds;

    /*
     * compute delta in second, 1/10's and 1/1000's second units
     */
    delta_seconds      = now -> tv_sec  - before -> tv_sec;
    delta_microseconds = now -> tv_usec - before -> tv_usec;

    if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
    }
    return((delta_seconds * 1000000) + delta_microseconds);
}


/* Returns 1 (true) if the mutex is unlocked, which is the
 * thread's signal to terminate. 
 */
extern
int needQuit(pthread_mutex_t *mtx)
{
    switch(pthread_mutex_trylock(mtx)) {
        case 0: /* if we got the lock, unlock and return 1 (true) */
            pthread_mutex_unlock(mtx);
            return 1;
        case EBUSY: /* return 0 (false) if the mutex was locked */
            return 0;
    }

    return 1;
}

extern 
void thread_exit_func(void *arg) {
    info_print("thread '%s' exited", (char *) arg);
}

extern
void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result)
{
  char          hex_str[]= "0123456789abcdef";
  unsigned int  i;

  *result = (char *)malloc(binsz * 2 + 1);
  (*result)[binsz * 2] = 0;

  if (!binsz)
    return;

  for (i = 0; i < binsz; i++)
    {
      (*result)[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
      (*result)[i * 2 + 1] = hex_str[(bin[i]     ) & 0x0F];
    }  
}

extern 
void zmq_getsockopt_values(void *zmq_socket) {
    int zmq_getsockopt_value, rc;
    size_t zmq_getsockopt_value_size = sizeof (zmq_getsockopt_value);

    char zmq_getsockopt_value_char[512];
    size_t zmq_getsockopt_value_char_size = sizeof (zmq_getsockopt_value_char);

    debug_print("---------------------------------");

    rc = zmq_getsockopt (zmq_socket, ZMQ_TYPE, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("zmq_getsockopt ZMQ_TYPE failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_getsockopt ZMQ_TYPE: %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_socket, ZMQ_SNDHWM, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("zmq_getsockopt ZMQ_SNDHWM failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_getsockopt ZMQ_SNDHWM (Retrieves high water mark for outbound messages): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_socket, ZMQ_RCVHWM, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("zmq_getsockopt ZMQ_RCVHWM failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_getsockopt ZMQ_RCVHWM (Retrieve high water mark for inbound messages): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_socket, ZMQ_LINGER, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("zmq_getsockopt ZMQ_LINGER failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_getsockopt ZMQ_LINGER (Retrieve linger period for socket shutdown): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_socket, ZMQ_RCVTIMEO, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("zmq_getsockopt ZMQ_RCVTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_getsockopt ZMQ_RCVTIMEO (Maximum time before a socket operation returns with EAGAIN): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_socket, ZMQ_SNDTIMEO, &zmq_getsockopt_value, &zmq_getsockopt_value_size);
    if (rc != 0) {
        warn_print("zmq_getsockopt ZMQ_SNDTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_getsockopt ZMQ_SNDTIMEO (Maximum time before a socket operation returns with EAGAIN): %d", zmq_getsockopt_value);
    }

    rc = zmq_getsockopt (zmq_socket, ZMQ_LAST_ENDPOINT, &zmq_getsockopt_value_char, &zmq_getsockopt_value_char_size);
    if (rc != 0) {
        warn_print("zmq_getsockopt ZMQ_LAST_ENDPOINT failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_getsockopt ZMQ_LAST_ENDPOINT: %s", zmq_getsockopt_value_char);
    }

    debug_print("---------------------------------");
}

extern
void zmq_ctx_destroy_func(void *zmq_ctx) {
    int rc;

    rc = zmq_ctx_destroy(zmq_ctx);
    if (rc != 0) {
        err_print("zmq_ctx_destroy failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_ctx_destroy: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    }
}


int zmq_linger_time;
int zmq_hwm_msg;
int zmq_sndtimeo;

extern
void zmq_setsockopt_func(void *zmq_sock) {
    int rc;
    int opt = 1;

    rc = zmq_setsockopt(zmq_sock, ZMQ_LINGER, &zmq_linger_time, sizeof(zmq_linger_time));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_LINGER failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_SNDHWM, &zmq_hwm_msg, sizeof(zmq_hwm_msg));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_SNDHWM failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_RCVHWM, &zmq_hwm_msg, sizeof(zmq_hwm_msg));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_RCVHWM failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_SNDTIMEO, &zmq_sndtimeo, sizeof(zmq_sndtimeo));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_SNDTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_RCVTIMEO, &zmq_sndtimeo, sizeof(zmq_sndtimeo));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_RCVTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(zmq_sock, ZMQ_DELAY_ATTACH_ON_CONNECT, &opt, sizeof(opt));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_DELAY_ATTACH_ON_CONNECT failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }
}