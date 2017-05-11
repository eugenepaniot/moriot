#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef PTHREAD
#define PTHREAD
#endif

#include <features.h>

#include <sys/syscall.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>
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

#include "statsd-client.h"

#include "capture.h"

#define ALARM_SLEEP 1
#define ZMQ_PROXY_STATS_IPC "inproc://zmq-proxy-stats.inproc"

char *statsd_host = "127.0.0.1";
u_short statsd_port = 8125;

void *_zmq_context;

void *_zmq_frontend;
void *_zmq_backend;

u_int64_t numPkts;
u_int64_t numBytes;

int zmq_linger_time = 1;
int zmq_hwm_msg = 500<<10;
int zmq_sndtimeo = -1;

u_short verbose = 0;

pthread_t res_coll_thread;
pthread_t res_coll_capture_thread;

volatile int stop = 0;

/* --------------------------- */

static
void print_stats(void) {
    statsd_link *link = NULL;

    char buf[512];

    link = statsd_init(statsd_host, statsd_port);

    if(link) {
        snprintf(buf, sizeof(buf), "result-collector.packets");
        statsd_gauge(link, buf, (long unsigned int)numPkts);
        if(verbose >= 3)
            debug_print("%s %lu", buf, (long unsigned int)numPkts);
        
        snprintf(buf, sizeof(buf), "result-collector.bytes");
        statsd_gauge(link, buf, (long unsigned int)numBytes);
        if(verbose >= 3)
            debug_print("%s %lu", buf, (long unsigned int)numBytes);
    }

    statsd_finalize(link);
}

static 
void my_sigalarm(int sig) {
    print_stats();
    alarm(ALARM_SLEEP);
    signal(SIGALRM, my_sigalarm);
}

void res_coll_main_capture_thread_cleanup(void *args) {
    int rc;
    info_print("%s started", __FUNCTION__);

    rc = zmq_close(args);
    if (rc != 0) {
        warn_print("zmq_close zmq_stats_sock failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_close zmq_stats_sock closed");
    }

    info_print("%s completed", __FUNCTION__);
}

static void *res_coll_main_capture_thread(void *args) {
    void *zmq_stats_sock;
    int rc;

    pthread_cleanup_push((void *)thread_exit_func, "res_coll_main_capture_thread");
    
    rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (rc != 0) {
        err_print("pthread_setcancelstate PTHREAD_CANCEL_ENABLE failed (%d): %s", errno, strerror(errno));
    }

    zmq_stats_sock = zmq_socket (_zmq_context, ZMQ_SUB);

    pthread_cleanup_push((void *)res_coll_main_capture_thread_cleanup, zmq_stats_sock);

    zmq_setsockopt_func(zmq_stats_sock);

    rc = zmq_setsockopt(zmq_stats_sock, ZMQ_SUBSCRIBE, "", 0);
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_SUBSCRIBE failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    zmq_getsockopt_values(zmq_stats_sock);

    while(!stop && zmq_connect (zmq_stats_sock, ZMQ_PROXY_STATS_IPC) != 0 ) {
        err_print("zmq_connect failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        sleep(1);
    }

    info_print("entering main loop");
    while(!stop) {
        pthread_testcancel();

        int nbytes = zmq_recv(zmq_stats_sock, NULL, 0, 0);
        if(nbytes > 0) {
            if(verbose >=4)
                debug_print("nbytes: %d", nbytes);
            numPkts++, numBytes+=nbytes;
        }
    }

    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);
    pthread_exit(0);
}

void res_coll_main_thread_cleanup(void *args) {
    int rc;
    info_print("%s started", __FUNCTION__);

    
    rc = zmq_close(_zmq_frontend);
    if (rc != 0) {
        warn_print("zmq_close _zmq_frontend failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_close _zmq_frontend closed");
    }


    rc = zmq_close(_zmq_backend);
    if (rc != 0) {
        warn_print("zmq_close _zmq_backend failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_close _zmq_backend closed");
    }

    info_print("%s completed", __FUNCTION__);
}

static void *res_coll_main_thread(void* args) {
    int rc;

    pthread_cleanup_push((void *)thread_exit_func, "res_coll_main_thread");
    pthread_cleanup_push((void *)res_coll_main_thread_cleanup, NULL);

    rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (rc != 0) {
        err_print("pthread_setcancelstate PTHREAD_CANCEL_ENABLE failed (%d): %s", errno, strerror(errno));
        pthread_exit(0);
    }

    /* ---------------------------------------- */

    _zmq_frontend = zmq_socket (_zmq_context, ZMQ_DEALER);
    rc = zmq_bind (_zmq_frontend, "tcp://*:6666");
    if (rc != 0) {
        err_print("zmq_bind _zmq_frontend failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

    rc = zmq_bind (_zmq_frontend, "ipc://zmq_result_collector.sock");
    if (rc != 0) {
        err_print("zmq_bind _zmq_frontend failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

    zmq_setsockopt_func(_zmq_frontend);
    zmq_getsockopt_values(_zmq_frontend);

    /* ---------------------------------------- */

    _zmq_backend = zmq_socket (_zmq_context, ZMQ_PUB);
    rc = zmq_bind (_zmq_backend, ZMQ_PROXY_STATS_IPC);
    if (rc != 0) {
        err_print("zmq_bind _zmq_frontend failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

    rc = zmq_bind (_zmq_backend, "tcp://*:6667");
    if (rc != 0) {
        err_print("zmq_bind _zmq_frontend failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

    zmq_getsockopt_values(_zmq_backend);

    info_print("entering main loop");

    pthread_testcancel();

    //rc = zmq_proxy(_zmq_frontend, _zmq_backend, _zmq_capture);
    rc = zmq_device(ZMQ_QUEUE, _zmq_frontend, _zmq_backend);
    if (rc != 0) {
        err_print("zmq_proxy failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);
    pthread_exit(0);
}

static
void sigproc(int signum) {
    u_short i;
    int rc;

    info_print("SIGNAL: %s(%d). Leaving.", strsignal(signum), signum);
    signal(SIGALRM, SIG_IGN);

    print_stats();

    stop=1;

    if(res_coll_thread && pthread_kill(res_coll_thread, 0) == 0) {
        debug_print("pthread_cancel to %s", "res_coll_thread");
        pthread_cancel(res_coll_thread);
    } else {
        warn_print("res_coll_thread doesn't exists");
    }

    if(res_coll_capture_thread && pthread_kill(res_coll_capture_thread, 0) == 0) {
        debug_print("pthread_cancel to %s", "res_coll_capture_thread");
        pthread_cancel(res_coll_capture_thread);
    } else {
        warn_print("res_coll_capture_thread doesn't exists");
    }

}

void main_exit(int exitStatus, void *arg) {
    uint rc;

    if (exitStatus > 0)
        warn_print("exitStatus: %d", exitStatus);

    zmq_ctx_destroy_func(_zmq_context);


    info_print("exit");
}

int main(int argc, char* argv[]) {
    int rc;
    char c;
    int numCPU = sysconf( _SC_NPROCESSORS_ONLN );

    signal(SIGINT, sigproc);
    signal(SIGQUIT, sigproc);
    signal(SIGTERM, sigproc);
    signal(SIGINT, sigproc);

    while(( c = getopt(argc,argv,"v:")) != -1) {
        switch(c) {
            case 'v':
                verbose = fmax(atoi(optarg), 1);
                info_print("using verbose mode %d", verbose);
                break;
        }
    }

    if (on_exit(main_exit, NULL) != 0) {
        err_print("on_exit failed");
        exit(EXIT_FAILURE);
    }

    _zmq_context = zmq_ctx_new();
    if (_zmq_context == NULL) {
        err_print("zmq_ctx_new failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        exit(EXIT_FAILURE);
    }
    
    rc = zmq_ctx_set (_zmq_context, ZMQ_IO_THREADS, numCPU);
    if(rc != 0) {
        err_print("zmq_ctx_set ZMQ_IO_THREADS failed");
        raise(SIGTERM);
    }

    info_print("starting thread: res_coll_thread");
    rc = pthread_create(&res_coll_thread, NULL, res_coll_main_thread, NULL);
    if (rc != 0) {
        err_print("pthread_create %s failed: (%d): %s", "res_coll_thread", rc, strerror(rc));
        raise(SIGTERM);
    }

    info_print("starting thread: res_coll_capture_thread");
    rc = pthread_create(&res_coll_capture_thread, NULL, res_coll_main_capture_thread, NULL);
    if (rc != 0) {
        err_print("pthread_create %s failed: (%d): %s", "res_coll_thread", rc, strerror(rc));
        raise(SIGTERM);
    }

    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);

    info_print("entering main loop");

    while(!stop) {
        sleep(1);
    }

    void *t_join_res;

    rc = pthread_join(res_coll_thread, &t_join_res);
    if (rc != 0)
        warn_print("pthread_join on res_coll_thread failed");

    if (t_join_res == PTHREAD_CANCELED)
        warn_print("thread res_coll_thread was canceled");
    else
        info_print("thread res_coll_thread was terminated normally");

    rc = pthread_join(res_coll_capture_thread, &t_join_res);
    if (rc != 0)
        warn_print("pthread_join on res_coll_capture_thread failed");

    if (t_join_res == PTHREAD_CANCELED)
        info_print("thread res_coll_capture_thread was canceled");
    else
        info_print("thread res_coll_capture_thread was terminated normally");

    return 0;
}
