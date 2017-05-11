#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef PTHREAD
#define PTHREAD
#endif

#ifndef HAVE_PF_RING
#define HAVE_PF_RING
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

#include <pfring.h>

#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_message.h>

#include "lib/base64/include/libbase64.h"

#include "statsd-client.h"

#include "capture.h"
#include "capture-parser-osip.h"

#define ALARM_SLEEP 1

#define ZMQ_DEVICE_FE "inproc://zmq-device-fe.inproc"
#define ZMQ_PROXY_STATS_IPC "inproc://zmq-proxy-stats.inproc"

char *statsd_host = "127.0.0.1";
u_short statsd_port = 8125;

char *zmq_capture_addr = NULL;

int thread_multi = 0;

void *_zmq_context;
void *_zmq_frontend;
void *_zmq_backend;

pthread_t zmq_device_main_thread;

struct sip_stats {
    u_int64_t response;
    u_int64_t request;

    u_int64_t invite;
    u_int64_t ack;
    u_int64_t reg;
    u_int64_t bye;
    u_int64_t options;
    u_int64_t info;
    u_int64_t cancel;
    u_int64_t refer;
    u_int64_t notify;
    u_int64_t subscribe;
    u_int64_t message;
    u_int64_t prack;
    u_int64_t update;
    u_int64_t publish;

    u_int64_t status_1xx;
    u_int64_t status_2xx;
    u_int64_t status_3xx;
    u_int64_t status_4xx;
    u_int64_t status_5xx;
    u_int64_t status_6xx;
};

struct thread_stats {
    char name[32];

    u_int64_t numPkts;
    u_int64_t brokenPkts;

    u_int64_t numBytes;
    volatile u_int64_t parseTime;

    u_int64_t zdropPkts;
    u_int64_t zfailedPkts;

    void *zmq_socket;
    void *zmq_socket_res;

    pthread_t pd_thread;

    struct sip_stats sip_stats;
};
struct thread_stats *threads;

u_short num_thread;

pthread_mutex_t do_shutdown;
pthread_mutexattr_t mattr;

int zmq_linger_time = 1;
int zmq_hwm_msg = 100<<10;
int zmq_sndtimeo = -1;

u_short verbose = 0;

/* ------------------------------------------ */

static
void print_stats(void) {
    statsd_link *link = NULL;

    char buf[512];

    link = statsd_init(statsd_host, statsd_port);

    if(link) {
        for(int i=0; i<num_thread; i++) {
            snprintf(buf, sizeof(buf), "parser.%s.packets", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].numPkts);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].numPkts);

            snprintf(buf, sizeof(buf), "parser.%s.brokenPkts", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].brokenPkts);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].brokenPkts);
            
            snprintf(buf, sizeof(buf), "parser.%s.bytes", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].numBytes);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].numBytes);
            
            snprintf(buf, sizeof(buf), "parser.%s.parseTime", threads[i].name);
            statsd_timing(link, buf, (float)(threads[i].parseTime / 1000000.0f) );
            if(verbose >= 3)
                debug_print("%s %.6f", buf, (float) (threads[i].parseTime / 1000000.0f ) );
            threads[i].parseTime = 0;

            snprintf(buf, sizeof(buf), "parser.%s.zfailedPkts", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].zfailedPkts);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].zfailedPkts);

            snprintf(buf, sizeof(buf), "parser.%s.zdropPkts", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].zdropPkts);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].zdropPkts);

            /* ---------------------------------------------------------- */

            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.response", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.response);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.response);

            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.request", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.request);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.request);

            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.invite", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.invite);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.invite);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.ack", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.ack);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.ack);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.reg", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.reg);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.reg);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.bye", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.bye);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.bye);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.options", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.options);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.options);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.info", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.info);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.info);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.cancel", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.cancel);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.cancel);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.refer", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.refer);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.refer);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.notify", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.notify);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.notify);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.subscribe", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.subscribe);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.subscribe);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.message", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.message);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.message);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.prack", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.prack);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.prack);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.update", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.update);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.update);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.publish", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.publish);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.publish);
            

            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.status_1xx", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.status_1xx);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.status_1xx);

            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.status_2xx", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.status_2xx);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.status_2xx);

            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.status_3xx", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.status_3xx);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.status_3xx);
            
            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.status_4xx", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.status_4xx);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.status_4xx);

            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.status_5xx", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.status_5xx);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.status_5xx);

            snprintf(buf, sizeof(buf), "parser.sip_stat.%s.status_6xx", threads[i].name);
            statsd_gauge(link, buf, (long unsigned int)threads[i].sip_stats.status_6xx);
            if(verbose >= 3)
                debug_print("%s %lu", buf, (long unsigned int)threads[i].sip_stats.status_6xx);
        }
    }

    statsd_finalize(link);
}

static 
void my_sigalarm(int sig) {
    print_stats();
    alarm(ALARM_SLEEP);
    signal(SIGALRM, my_sigalarm);
}

/* ------------------------------------------ */

void zmq_device_main_cleanup(void *args) {
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

static void *zmq_device_main(void* args) {
    int rc;

    pthread_cleanup_push((void *)thread_exit_func, "zmq_device_main");
    pthread_cleanup_push((void *)zmq_device_main_cleanup, NULL);

    rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (rc != 0) {
        err_print("pthread_setcancelstate PTHREAD_CANCEL_ENABLE failed (%d): %s", errno, strerror(errno));
        pthread_exit(0);
    }

    /* ------------------------------------------ */

    _zmq_frontend = zmq_socket (_zmq_context, ZMQ_DEALER);
    rc = zmq_bind (_zmq_frontend, ZMQ_DEVICE_FE);
    if (rc != 0) {
        err_print("zmq_bind _zmq_frontend failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

    zmq_setsockopt_func(_zmq_frontend);
    zmq_getsockopt_values(_zmq_frontend);

    /* ------------------------------------------ */

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

    zmq_setsockopt_func(_zmq_backend);

    zmq_getsockopt_values(_zmq_backend);

    info_print("entering main loop");

    pthread_testcancel();

    //rc = zmq_proxy(_zmq_frontend, _zmq_backend, _zmq_capture);
    rc = zmq_device(ZMQ_QUEUE, _zmq_frontend, _zmq_backend);
    if (rc != 0) {
        err_print("zmq_device failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);
    pthread_exit(0);
}

/* ------------------------------------------ */

void parser_main_thread_cleanup(void *args) {
    int i = (intptr_t)args;

    int rc;
    info_print("%s started", __FUNCTION__);

    if(threads[i].zmq_socket) {
        rc = zmq_close(threads[i].zmq_socket);
        if (rc != 0) {
            warn_print("zmq_close zmq_socket failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        } else {
            debug_print("zmq_close zmq_socket closed");
        }
    }

    if(threads[i].zmq_socket_res) {
        rc = zmq_close(threads[i].zmq_socket_res);
        if (rc != 0) {
            warn_print("zmq_close zmq_socket_res failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        } else {
            debug_print("zmq_close zmq_socket_res closed");
        }
    }

    info_print("%s completed", __FUNCTION__);
}

static void *parser_main_thread(void* args) {
    int i = (intptr_t)args;
    int rc;

    int64_t startTime;
    
    pthread_cleanup_push((void *)thread_exit_func, threads[i].name);
    pthread_cleanup_push((void *)parser_main_thread_cleanup, (void *)(intptr_t)i);

    rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (rc != 0) {
        err_print("pthread_setcancelstate PTHREAD_CANCEL_ENABLE failed (%d): %s", errno, strerror(errno));
        pthread_exit(0);
    }

    threads[i].zmq_socket = zmq_socket (_zmq_context, ZMQ_DEALER);

    if(zmq_connect (threads[i].zmq_socket, zmq_capture_addr) != 0) {
        err_print("zmq_connect failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        goto error;
    }

    zmq_setsockopt_func(threads[i].zmq_socket);
    zmq_getsockopt_values(threads[i].zmq_socket);

    /* ---------------------------------------- */

    threads[i].zmq_socket_res = zmq_socket (_zmq_context, ZMQ_DEALER);

    if(zmq_connect (threads[i].zmq_socket_res, ZMQ_DEVICE_FE) != 0) {
        err_print("zmq_connect failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        goto error;
    }
    
    zmq_setsockopt_func(threads[i].zmq_socket_res);
    zmq_getsockopt_values(threads[i].zmq_socket_res);
    
    debug_print("zmq_getsockopt_values zmq_socket_res");
    zmq_getsockopt_values(threads[i].zmq_socket_res);

    info_print("entering main loop");

    parser_init();

    while(!needQuit(&do_shutdown)) {
        pthread_testcancel();

        struct pfring_pkthdr *h;
        u_char *p ;

        char *buf;
        char *encoded_pkt;
        struct rslt_sip_message *ret;

        /* h */
        h = (struct pfring_pkthdr *) malloc(sizeof(struct pfring_pkthdr));
        if(h == NULL) {
            err_print("malloc h failed");
            goto error_zmq;
        }
        rc = zmq_recv(threads[i].zmq_socket, h, sizeof(struct pfring_pkthdr), 0);
        if (rc == -1) {
            err_print("zmq_msg_recv h failed (%d): %s", zmq_errno(), strerror(zmq_errno()));
            goto error_zmq;
        }

        if(sizeof(struct pfring_pkthdr) != rc) {
            err_print("recived data is not struct pfring_pkthdr");
            goto error_zmq;
        }

        threads[i].numPkts++;

        int more;
        size_t more_size = sizeof (more);

        rc = zmq_getsockopt(threads[i].zmq_socket, ZMQ_RCVMORE, &more, &more_size);
        if(rc == -1) {
            err_print("zmq_getsockopt ZMQ_RCVMORE (%d): %s", zmq_errno(), strerror(zmq_errno()));
            goto error_zmq;
        }

        if(more != 1){
            threads[i].brokenPkts++;
            err_print("wrong ZMQ sequence. waiting one message, but got: %d", more);
            goto error_zmq;
        }

        /* p */
        p = (u_char *) malloc( sizeof(u_char) * h->len );
        if(p == NULL) {
            err_print("malloc p failed");
            goto error_zmq;
        }
        rc = zmq_recv(threads[i].zmq_socket, p, h->len, 0);
        if (rc == -1) {
            err_print("zmq_msg_recv p failed (%d): %s", zmq_errno(), strerror(zmq_errno()));
            goto error_zmq;
        }

        if(h->len != rc) {
            err_print("recived wrong packet data. waiting %d bytes but got %d", h->len, rc);
            goto error_zmq;
        }

        /* ----------- */

        startTime = clock_usecs();

        threads[i].numBytes += h->len;

        u_char *payload;
        payload = (u_char*)(p + h->extended_hdr.parsed_pkt.offset.payload_offset);

        ret = (struct rslt_sip_message *) malloc(sizeof(struct rslt_sip_message)) ;
        if(ret == NULL) {
            err_print("malloc ret failed");
            goto error_zmq;
        }

        rc = parseSIP((char *)payload, ret);
        if(rc !=0) {
            //err_print("parseSIP failed %d", rc);
        }

        bin_to_strhex(p, h->len, &encoded_pkt);
        if(encoded_pkt == NULL) {
            err_print("encoded_pkt failed");
        }
        
        int buf_len = asprintf(&buf, JSON_RET_TMPL,
            h->extended_hdr.timestamp_ns,
            h->extended_hdr.parsed_pkt.ipv4_src,
            h->extended_hdr.parsed_pkt.l4_src_port,

            h->extended_hdr.parsed_pkt.ipv4_dst,
            h->extended_hdr.parsed_pkt.l4_dst_port,
            h->extended_hdr.parsed_pkt.offset.payload_offset,

            ret->call_id,
            ret->to,
            ret->from,
            ret->sip_method,
            ret->status_code,
            ret->rc_session_id,
            ret->ua,
            ret->maxfwd,

            ret->cseq.number,
            ret->cseq.method,

            encoded_pkt
        );


        if MSG_IS_REQUEST(ret) {
            threads[i].sip_stats.request++;

            if MSG_IS_INVITE(ret)
                threads[i].sip_stats.invite++;
            else if MSG_IS_ACK(ret)
                threads[i].sip_stats.ack++;
            else if MSG_IS_REGISTER(ret)
                threads[i].sip_stats.reg++;
            else if MSG_IS_BYE(ret)
                threads[i].sip_stats.bye++;
            else if MSG_IS_OPTIONS(ret)
                threads[i].sip_stats.options++;
            else if MSG_IS_INFO(ret)
                threads[i].sip_stats.info++;
            else if MSG_IS_CANCEL(ret)
                threads[i].sip_stats.cancel++;
            else if MSG_IS_REFER(ret)
                threads[i].sip_stats.refer++;
            else if MSG_IS_NOTIFY(ret)
                threads[i].sip_stats.notify++;
            else if MSG_IS_SUBSCRIBE(ret)
                threads[i].sip_stats.subscribe++;
            else if MSG_IS_MESSAGE(ret)
                threads[i].sip_stats.message++;
            else if MSG_IS_PRACK(ret)
                threads[i].sip_stats.prack++;
            else if MSG_IS_UPDATE(ret)
                threads[i].sip_stats.update++;
            else if MSG_IS_PUBLISH(ret)
                threads[i].sip_stats.publish++;

        } else if MSG_IS_RESPONSE(ret) {
            threads[i].sip_stats.response++;

            if MSG_IS_STATUS_1XX(ret)
                threads[i].sip_stats.status_1xx++;
            else if MSG_IS_STATUS_2XX(ret)
                threads[i].sip_stats.status_2xx++;
            else if MSG_IS_STATUS_3XX(ret)
                threads[i].sip_stats.status_3xx++;
            else if MSG_IS_STATUS_4XX(ret)
                threads[i].sip_stats.status_4xx++;
            else if MSG_IS_STATUS_5XX(ret)
                threads[i].sip_stats.status_5xx++;
            else if MSG_IS_STATUS_6XX(ret)
                threads[i].sip_stats.status_6xx++;
        }

        if(buf_len < 0) {
            err_print("asprintf buf failed (%d): %s", errno, strerror(errno));
            goto error_zmq;
        } else {
            if(verbose > 1)
                info_print("%s", buf);
        }

        int loop_count = 0;
        do {
            if (++loop_count > 3) {
                if(verbose)
                    err_print("zmq_send loop count limit exceeded. Break msg");
                threads[i].zdropPkts++;
                break;
            }

            rc = zmq_send(threads[i].zmq_socket_res, (void *)buf, buf_len, ZMQ_DONTWAIT);
            if (rc == -1) {
                if(verbose)
                    err_print("zmq_send failed: (%d): %s,\n'%s'", zmq_errno(), zmq_strerror(zmq_errno()), (char *)buf);

                threads[i].zfailedPkts++;
                sched_yield();
            } else {
                if(verbose > 0) 
                    debug_print("zmq_msg_send successful (%zu): %s", strlen(buf), buf);
            }
        } while (
            rc == -1 && zmq_errno() == EINTR
        );

        threads[i].parseTime = fmax(clock_usecs()-startTime, threads[i].parseTime);
error_zmq:
        insane_free(p);
        insane_free(h);

        insane_free(buf);
        insane_free(ret);

        insane_free(encoded_pkt);
    }

error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);
    pthread_exit(0);
}

/* ------------------------------------------ */

static
void sigproc(int signum) {
    u_short i;

    info_print("SIGNAL: %s(%d). Leaving.", strsignal(signum), signum);
    signal(SIGALRM, SIG_IGN);

    print_stats();

    pthread_mutex_unlock(&do_shutdown);

    sleep(1);

    for(int i=0; i<num_thread; i++) {
        if(threads[i].pd_thread && pthread_kill(threads[i].pd_thread, 0) == 0) {
            debug_print("pthread_cancel to %s", threads[i].name);
            pthread_cancel(threads[i].pd_thread);
        } else {
            warn_print("%s doesn't exists", threads[i].name);
        }
    }

    if(zmq_device_main_thread && pthread_kill(zmq_device_main_thread, 0) == 0) {
        debug_print("pthread_cancel to zmq_device_main_thread");
        pthread_cancel(zmq_device_main_thread);
    } else {
        warn_print("zmq_device_main_thread doesn't exists");
    }

}

void main_exit(int exitStatus, void *arg) {
    uint rc;

    if (exitStatus > 0)
        warn_print("exitStatus: %d", exitStatus);

    for(int i=0; i<num_thread; i++) {
        void *t_join_res;

        if(threads == NULL)
            continue;

        info_print("waiting while exit '%s'", threads[i].name);

        rc = pthread_join(threads[i].pd_thread, &t_join_res);
        if (rc != 0)
            warn_print("pthread_join on '%s' failed", threads[i].name);

        if (t_join_res == PTHREAD_CANCELED)
            warn_print("thread '%s' was canceled", threads[i].name);
        else
            info_print("thread '%s' was terminated normally", threads[i].name);
    }

    zmq_ctx_destroy_func(_zmq_context);
    
    insane_free(zmq_capture_addr);

    rc = pthread_mutex_destroy(&do_shutdown);
    if (rc != 0)
        err_print("pthread_mutex_destroy failed: (%d): %s", rc, strerror(rc));
    else
        debug_print("pthread_mutex_destroy do_shutdown (%d): %s", rc, strerror(rc));

    rc = pthread_mutexattr_destroy(&mattr);
    if (rc != 0)
        err_print("pthread_mutexattr_destroy failed: (%d): %s", rc, strerror(rc));
    else
        debug_print("pthread_mutexattr_destroy mattr (%d): %s", rc, strerror(rc));

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

    while(( c = getopt(argc,argv,"z:r:t:v:")) != -1) {
        switch(c) {
            case 'z':
                zmq_capture_addr = strdup(optarg);
                break;
            case 't':
                thread_multi = atoi(optarg);
                break;
            case 'v':
                verbose = fmax(atoi(optarg), 1);
                info_print("using verbose mode %d", verbose);
                break;
        }
    }

    num_thread = fmax(numCPU * thread_multi, 1);
    
    if (on_exit(main_exit, NULL) != 0) {
        err_print("on_exit failed");
        exit(EXIT_FAILURE);
    }

    if(zmq_capture_addr == NULL) {
        err_print("-z zmq_capture_addr required");
        exit(EXIT_FAILURE);  
    }

    debug_print("num_thread: %d", num_thread);

    if ((threads = calloc(num_thread, sizeof(struct thread_stats))) == NULL) {
        err_print("threads calloc failed (%d): %s", errno, strerror(errno));
        raise(SIGTERM);
    }

    rc = pthread_mutexattr_init(&mattr);
    if (rc != 0) {
        err_print("pthread_mutexattr_init failed: (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    rc = pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK_NP);
    if (rc != 0) {
        err_print("pthread_mutexattr_settype failed: (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    rc = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
    if (rc != 0) {
        err_print("pthread_mutexattr_setpshared failed: (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    rc = pthread_mutex_init(&do_shutdown, &mattr);
    if (rc != 0) {
        err_print("pthread_mutex_init failed: (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    _zmq_context = zmq_ctx_new();
    if (_zmq_context == NULL) {
        err_print("zmq_init failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_ctx_set (_zmq_context, ZMQ_IO_THREADS, numCPU);
    if(rc != 0) {
        err_print("zmq_ctx_set ZMQ_IO_THREADS failed");
        raise(SIGTERM);
    }

    pthread_mutex_lock(&do_shutdown);

    info_print("starting thread: zmq_device_main_thread");
    rc = pthread_create(&zmq_device_main_thread, NULL, zmq_device_main, NULL);
    if (rc != 0) {
        err_print("pthread_create zmq_device_main_thread failed: (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    for(int i=0; i<num_thread; i++) {
        snprintf(threads[i].name, sizeof(threads[i].name), "parser-thread-%d", i);

        info_print("starting thread: %s", threads[i].name);

        rc = pthread_create(&threads[i].pd_thread, NULL, parser_main_thread, (void *)(intptr_t)i);
        if (rc != 0) {
            err_print("pthread_create %s failed: (%d): %s", threads[i].name, rc, strerror(rc));
            raise(SIGTERM);
        }
    }

    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);

    info_print("entering main loop");

    while(!needQuit(&do_shutdown)) {
        sleep(1);
    }

    return 0;
}

// http://www.antisip.com/doc/exosip2/
// http://www.gnu.org/software/osip/doc/html/
// http://sofia-sip.sourceforge.net/refdocs/sip/annotated.html