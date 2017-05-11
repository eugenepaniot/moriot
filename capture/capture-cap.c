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
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <math.h>
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

#include <pfring.h>

#define ALARM_SLEEP             1
#define DEFAULT_SNAPLEN       16436
#define DEFAULT_DEVICE     "eth1"

#define ZMQ_PROXY_BACK_2_FRONT_IPC "inproc://zmq-proxy-back-2-front.inproc"
#define ZMQ_PROXY_STATS_IPC "inproc://zmq-proxy-stats.inproc"

#define ARRAY_SIZE(x)  (sizeof(x) / sizeof((x)[0]))

u_short numCPU;
u_short num_channels = 1;
u_short verbose = 0;

void *_zmq_context;

void *_zmq_frontend;
void *_zmq_backend;

char *bpfFilter = NULL;
char *zmq_parser_addr = "tcp://0.0.0.0:5555";
char *out_pcap_file = NULL;

char *statsd_host = "127.0.0.1";
u_short statsd_port = 8125;

struct thread_stats {
  u_int64_t __padding_0[8];

  char name[32];

  u_int64_t numPkts;
  u_int64_t numBytes;
  
  u_int64_t zdropPkts;
  u_int64_t zfailedPkts;

  void *zmq_socket;
  pfring *ring;
  pthread_t pd_thread;
  int core_affinity;

  pcap_dumper_t *dumper;

  u_int64_t __padding_1[3];
};

struct thread_stats *threads;
pthread_t t_zmq_proxy_thread;

pthread_mutex_t do_shutdown;

int zmq_linger_time = 1;
int zmq_hwm_msg = 500<<10;
int zmq_sndtimeo = -1;

/* ******************************** */

static
void print_stats(void) {
    pfring_stat pfringStat;
    statsd_link *link = NULL;

    char buf[512];

    if(statsd_host != NULL) {
        link = statsd_init(statsd_host, statsd_port);
    }

    for(u_short i=0; i < num_channels; i++) {
        if (!threads[i].ring)
            continue;

        if(pfring_stats(threads[i].ring, &pfringStat) >= 0) {
            
            snprintf(buf, sizeof(buf),
               "Name:     %s\n"
               "Packets:  %lu\n"
               "ZMQ Dropped:  %lu\n"
               "ZMQ Failed:  %lu\n"

               "PFRing Dropped:  %lu\n"
               "Bytes:    %lu",

               threads[i].name,
               (long unsigned int)threads[i].numPkts,
               (long unsigned int)threads[i].zdropPkts,
               (long unsigned int)threads[i].zfailedPkts,

               (long unsigned int)pfringStat.drop,
               (long unsigned int)threads[i].numBytes);

            pfring_set_application_stats(threads[i].ring, buf);

            if(link) {
                snprintf(buf, sizeof(buf), "capture.%s.packets", threads[i].name);
                statsd_gauge(link, buf, (long unsigned int)threads[i].numPkts);

                snprintf(buf, sizeof(buf), "capture.%s.packetsZdropped", threads[i].name);
                statsd_gauge(link, buf, (long unsigned int)threads[i].zdropPkts);

                snprintf(buf, sizeof(buf), "capture.%s.packetsZfailed", threads[i].name);
                statsd_gauge(link, buf, (long unsigned int)threads[i].zfailedPkts);

                snprintf(buf, sizeof(buf), "capture.%s.packetsDropped", threads[i].name);
                statsd_gauge(link, buf, (long unsigned int)pfringStat.drop);

                snprintf(buf, sizeof(buf), "capture.%s.bytes", threads[i].name);
                statsd_gauge(link, buf, (long unsigned int)threads[i].numBytes);
            }
        }
    }

    statsd_finalize(link);
}

static
void sigproc(int signum) {
    u_short i;

    info_print("SIGNAL: %s(%d). Leaving.", strsignal(signum), signum);
    signal(SIGALRM, SIG_IGN);

    print_stats();

    pthread_mutex_unlock(&do_shutdown);

    sleep(1);

    if(t_zmq_proxy_thread && pthread_kill(t_zmq_proxy_thread, 0) == 0) {
        debug_print("pthread_cancel to %s", "t_zmq_proxy_thread");
        pthread_cancel(t_zmq_proxy_thread);
    } else {
        warn_print("t_zmq_proxy_thread doesn't exists");
    }

    for(i=0; i<num_channels; i++) {
        if(threads[i].pd_thread && pthread_kill(threads[i].pd_thread, 0) == 0) {

            if (threads[i].ring) {
                debug_print("pfring_breakloop ring_id: %d", pfring_get_ring_id(threads[i].ring));
                pfring_breakloop(threads[i].ring);
            }

            debug_print("pthread_cancel to %s", threads[i].name);
            pthread_cancel(threads[i].pd_thread);
        } else {
            warn_print("%s doesn't exists", threads[i].name);
        }
    }
}

/* ******************************** */

static void zmq_proxy_thread_clean_up(void) {
    int rc;

    info_print("zmq_proxy cleanup started");

    if(_zmq_frontend) {
        rc = zmq_close(_zmq_frontend);
        if (rc != 0) {
            warn_print("zmq_close _zmq_frontend failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        } else {
            debug_print("zmq_close _zmq_frontend closed");
        }
    }

    if(_zmq_backend) {
        rc = zmq_close(_zmq_backend);
        if (rc != 0) {
            warn_print("zmq_close _zmq_backend failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        } else {
            debug_print("zmq_close _zmq_backend closed");
        }
    }

    info_print("zmq_proxy cleanup complete");
}

static void* zmq_proxy_thread(void) {
    int rc;

    int zmq_sndtimeo=-1;

    pthread_cleanup_push(thread_exit_func, "zmq_proxy_thread");
    pthread_cleanup_push((void *)zmq_proxy_thread_clean_up, NULL);

    rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (rc != 0) {
        err_print("pthread_setcancelstate PTHREAD_CANCEL_ENABLE failed (%d): %s", errno, strerror(errno));
        pthread_exit(0);
    }

    info_print("zmq_proxy_thread started");
    
    _zmq_frontend = zmq_socket (_zmq_context, ZMQ_DEALER);
    rc = zmq_bind (_zmq_frontend, ZMQ_PROXY_BACK_2_FRONT_IPC);
    if (rc != 0) {
        err_print("zmq_bind _zmq_frontend failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

    zmq_setsockopt_func(_zmq_frontend);

    rc = zmq_setsockopt(_zmq_frontend, ZMQ_SNDTIMEO, &zmq_sndtimeo, sizeof(zmq_sndtimeo));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_SNDTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(_zmq_frontend, ZMQ_RCVTIMEO, &zmq_sndtimeo, sizeof(zmq_sndtimeo));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_RCVTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    zmq_getsockopt_values(_zmq_frontend);

    _zmq_backend = zmq_socket (_zmq_context, ZMQ_DEALER);
    rc = zmq_bind (_zmq_backend, zmq_parser_addr);
    if (rc != 0) {
        err_print("zmq_bind _zmq_backend failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

    rc = zmq_bind (_zmq_backend, "ipc://zmq_parser_addr.sock");
    if (rc != 0) {
        err_print("zmq_bind _zmq_backend failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }

    zmq_setsockopt_func(_zmq_backend);

    rc = zmq_setsockopt(_zmq_backend, ZMQ_SNDTIMEO, &zmq_sndtimeo, sizeof(zmq_sndtimeo));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_SNDTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    rc = zmq_setsockopt(_zmq_backend, ZMQ_RCVTIMEO, &zmq_sndtimeo, sizeof(zmq_sndtimeo));
    if (rc != 0) {
        err_print("zmq_setsockopt ZMQ_RCVTIMEO failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

    zmq_getsockopt_values(_zmq_backend);

    pthread_testcancel();

    rc = zmq_device(ZMQ_QUEUE, _zmq_frontend, _zmq_backend);
    if (rc != 0) {
        err_print("zmq_device failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
    }

error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);
    pthread_exit(0);
}

static void processRingPacket (struct pfring_pkthdr *h, u_char *p, u_char *user_bytes) {
    int thread_id = (intptr_t) user_bytes;

    char *encoded_pkt = NULL;
    char *buf = NULL;
    int rc;

    int loop_count = 0;

    threads[thread_id].numPkts++, threads[thread_id].numBytes += h->len+24; /* 8 Preamble + 4 CRC + 12 IFG */;

    //memset((void*)&h->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
    //pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 4, 1 /* timestamp */ , 0 /* add_hash */);
   
    if(threads[thread_id].dumper) {
        pcap_dump((u_char*)threads[thread_id].dumper, (struct pcap_pkthdr*)h, p);
        pcap_dump_flush(threads[thread_id].dumper);
    }

    if((unsigned)h->extended_hdr.parsed_pkt.offset.payload_offset >= (unsigned)h->len ) {
        //warn_print("extended_hdr.parsed_pkt.offset.payload_offset >= h->len. Zero payload?");
        goto error;
    }

    if(h->extended_hdr.parsed_pkt.ip_version != 4) {
        //warn_print("only ipv4 supported");
        goto error;
    }

    /* --------------------- */
    if(verbose) {
        char print_buffer[512];

        bin_to_strhex(p, h->len, &encoded_pkt);

        int buf_len = asprintf(&buf, "%lu|%u:%u|%u:%u|%u:%s",
                h->extended_hdr.timestamp_ns,
                h->extended_hdr.parsed_pkt.ipv4_src,
                h->extended_hdr.parsed_pkt.l4_src_port,

                h->extended_hdr.parsed_pkt.ipv4_dst,
                h->extended_hdr.parsed_pkt.l4_dst_port,
                h->extended_hdr.parsed_pkt.offset.payload_offset,
                encoded_pkt 
                );

        if(buf_len < 0) {
            err_print("asprintf buf failed (%d): %s", errno, strerror(errno));
            goto error;
        }

        pfring_print_parsed_pkt(print_buffer, 512, p, h);

        debug_print("ring_id: %u | \n%s | \n%s", pfring_get_ring_id(threads[thread_id].ring),
                print_buffer,
                buf);
    }
    /* --------------------- */
    
    do {
        if (++loop_count > 3) {
            if(verbose)
                err_print("zmq_send h loop count limit exceeded. Break msg");
            threads[thread_id].zdropPkts++;
            goto error;
        }

        rc = zmq_send(threads[thread_id].zmq_socket, (void *)h, sizeof(struct pfring_pkthdr), ZMQ_SNDMORE);
        if (rc == -1) {
            if(verbose)
                err_print("zmq_send failed: (%d): %s,\n'%s'", zmq_errno(), zmq_strerror(zmq_errno()), (char *)buf);

            threads[thread_id].zfailedPkts++;
            sched_yield();
        }
        else {
            if(verbose)
                debug_print("send successful h (%d)", rc);
        }
    } while (
        rc == -1 && zmq_errno() == EINTR
    );

    loop_count = 0;
    do {
        if (++loop_count > 3) {
            err_print("zmq_send p loop count limit exceeded. Break msg");
            threads[thread_id].zdropPkts++;
            goto error;
        }

        rc = zmq_send(threads[thread_id].zmq_socket, (void *)p, h->len, 0);
        if (rc == -1) {
            if(verbose)
                err_print("zmq_send failed: (%d): %s,\n'%s'", zmq_errno(), zmq_strerror(zmq_errno()), (char *)buf);

            threads[thread_id].zfailedPkts++;
            sched_yield();
        }
        else {
            if(verbose)
                debug_print("send successful p (%d) %s", rc, buf);
        }
    } while (
        rc == -1 && zmq_errno() == EINTR
    );

error:
    insane_free(encoded_pkt);
    insane_free(buf);
}

void packet_consumer_thread_cleanup(void *arg) {
    int id = (intptr_t) arg;
    int rc;

    info_print("thread '%s' cleanup started", threads[id].name);

    if(threads[id].dumper) {
        debug_print("close pcap_dump");
        pcap_dump_close(threads[id].dumper);
    }

    rc = zmq_close(threads[id].zmq_socket);
    if (rc != 0) {
        err_print("zmq_close _zmq_socket failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
    } else {
        debug_print("zmq_close '%s' _zmq_socket closed", threads[id].name);
    }

    if(threads[id].ring && pfring_get_ring_id(threads[id].ring)) {
        debug_print("pfring_close ring_id: %d", pfring_get_ring_id(threads[id].ring));
        pfring_close(threads[id].ring);
    }

    if(threads[id].ring && pfring_get_ring_id(threads[id].ring)) {
        debug_print("pfring_shutdown ring_id: %d", pfring_get_ring_id(threads[id].ring));
        pfring_shutdown(threads[id].ring);
    }

    info_print("thread '%s' cleanup complete", threads[id].name);
}


void *packet_consumer_thread(void* _id) {
    int id = (intptr_t)_id;
    int rc;

    pthread_cleanup_push(thread_exit_func, threads[id].name);
    pthread_cleanup_push(packet_consumer_thread_cleanup, _id);

    if(numCPU > 1) {
        /* Bind this thread to a specific core */
        cpu_set_t cpuset;
        u_long core_id;

        if (threads[id].core_affinity != -1)
            core_id = threads[id].core_affinity % numCPU;
        else
            core_id = (id + 1) % numCPU;

        CPU_ZERO(&cpuset);
        CPU_SET(core_id, &cpuset);
        if((rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
            err_print("Error while binding thread %u to core %lu: errno=%i", id, core_id, rc);
        else {
            info_print("set thread %u on core %lu/%u", id, core_id, numCPU);
        }
    }
    
    rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (rc != 0) {
        err_print("pthread_setcancelstate PTHREAD_CANCEL_ENABLE failed (%d): %s", errno, strerror(errno));
        goto error;
    }

    threads[id].zmq_socket = zmq_socket (_zmq_context, ZMQ_PUSH); //ZMQ_PUSH
    if(threads[id].zmq_socket == NULL ) {
        err_print("zmq_socket _zmq_socket failed: (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        raise(SIGTERM);
        goto error;
    }
    
    zmq_setsockopt_func(threads[id].zmq_socket);
    zmq_getsockopt_values(threads[id].zmq_socket);

    while(!needQuit(&do_shutdown) && zmq_connect (threads[id].zmq_socket, ZMQ_PROXY_BACK_2_FRONT_IPC) != 0 ) {
        err_print("zmq_connect failed (%d): %s", zmq_errno(), zmq_strerror(zmq_errno()));
        sleep(1);
        //goto error;
    }

    u_char *buffer = NULL;
    struct pfring_pkthdr hdr;

    info_print("entering main loop");
    while(!needQuit(&do_shutdown)) {
        pthread_testcancel();

        if(pfring_recv(threads[id].ring, &buffer, 0, &hdr, 1) > 0) {
            processRingPacket(&hdr, buffer, (void *)(intptr_t)id);
        }
        else {
            sched_yield();
        }
    }

error:
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(2);

    pthread_exit(0);
}


static void my_sigalarm(int sig) {
    if (needQuit(&do_shutdown))
        return;

    print_stats();
    alarm(ALARM_SLEEP);
    signal(SIGALRM, my_sigalarm);
}

static void printHelp(void) {
    printf("capture-cap\nEugene Paniot <e.paniot@gmail.com>\n\n");
    printf("-h              Print this help.\n");
    printf("-v              Verbose.\n");
    printf("-i <device>     Device name. Default: %s\n", DEFAULT_DEVICE);
    printf("-z <zmq addr>   0MQ bind address. Default: %s.\n", zmq_parser_addr);
    printf("-m <zmq hwm>    Set custom high water mark for outbound and inbound messages.\n");
    printf("-q <bool>       Queue messages only to completed connections. Default 1.\n");
    printf("-f <filter>     BPF (Berkeley Packet Filter) rule.\n");
    printf("-o <path>       Dump packets onto the specified pcap file.\n");
    printf("-s              Opening a single ring for the whole device. Insted of several individual rings (one per RX-queue).\n");
    printf("-w              Use custom poll watermark. A low watermark value such as 1, reduces the latency of poll().\n");
    printf("                but likely increases the number of poll() calls.\n");
    printf("                A high watermark (it cannot exceed 50%% of the ring size, otherwise the PF_RING kernel module will top its value).\n");
    printf("                instead reduces the number of poll() calls but slightly increases the packet latency.\n");
    printf("                The default value for the watermark is 128.\n");
    printf("-S              Statsd server address. Default: 127.0.0.1.\n");
    printf("-P              Statsd port. Default: 8125.\n");
    printf("-b <prio>       CPU pergentage priority (0-99)\n");
    printf("-R              Packet direction\n");
    printf("\n");
    printf("* - required.\n");
}

int main(int argc, char* argv[]) {
    void *t_join_res;

    char *device = NULL;
    packet_direction direction = rx_only_direction;

    char c;
    int snaplen = DEFAULT_SNAPLEN;
    int rc;
    pfring *ring[MAX_NUM_RX_CHANNELS];
    u_int32_t version;

    u_short poll_wtm = 128, cpu_percentage = 64;
    u_short use_multichannel = 1;
    pthread_mutexattr_t mattr;

    int threads_core_affinity[MAX_NUM_RX_CHANNELS];

    signal(SIGINT, sigproc);
    signal(SIGQUIT, sigproc);
    signal(SIGTERM, sigproc);
    signal(SIGINT, sigproc);

    numCPU = sysconf( _SC_NPROCESSORS_ONLN );

    u_int32_t flags = 0;
    flags |= PF_RING_PROMISC;    
    flags |= PF_RING_LONG_HEADER; 
                                    /* If uset, PF_RING does not fill the field extended_hdr of struct pfring_pkthdr. 
                                    If set, the extended_hdr field is also properly filled. 
                                    In case you do not need extended information, set this value to 0 in order to speedup the operation. */
    flags |= PF_RING_DNA_SYMMETRIC_RSS; /* symmetric RSS is ignored by non-DNA drivers. 
                                        Set the hw RSS function to symmetric mode (both directions of the same flow go to the same hw queue). */
    //flags |= PF_RING_STRIP_HW_TIMESTAMP;
    flags |= PF_RING_TIMESTAMP; /* Force PF_RING to set the timestamp on received packets (usually it is not set when using zero-copy, for optimizing performance). */
    //flags |= PF_RING_DO_NOT_PARSE;

    memset(threads_core_affinity, -1, sizeof(threads_core_affinity));

    while((c = getopt(argc,argv,"hsli:vz:m:t:f:o:w:b:S:P:R:")) != -1) {
        switch(c) {
            case 'h':
                printHelp();
                return(0);
                break;
            case 'i':
                device = strdup(optarg);
                break;
            case 'v':
                verbose = 1;
                info_print("using verbose mode");
                break;
            case 'z':
                zmq_parser_addr = strdup(optarg);
                break;
            case 'm':
                zmq_hwm_msg = fmax(atoi(optarg), 1);
                break;
            case 'f':
                bpfFilter = strdup(optarg);
                break;
            case 'o':
                out_pcap_file = strdup(optarg);
                break;
            case 's':
                use_multichannel = 0;
                break;
            case 'S':
                statsd_host = strdup(optarg);
                break;
            case 'P':
                statsd_port = atoi(optarg);
                break;
            case 'w':
                poll_wtm = atoi(optarg);
                break;    
            case 'b':
                cpu_percentage = atoi(optarg);
                break;
            case 'R':
                direction = atoi(optarg);
                break;
        }
    }

    int zmq_major, zmq_minor, zmq_patch;
    zmq_version (&zmq_major, &zmq_minor, &zmq_patch);
    info_print ("using 0MQ version: %d.%d.%d", zmq_major, zmq_minor, zmq_patch);

    if(zmq_major < 3) {
        err_print("0MQ >= 3.x.x version reqired");
        exit(EXIT_FAILURE);
    }

    debug_print("numCPU: %d", numCPU);
    debug_print("MAX_NUM_RX_CHANNELS: %d", MAX_NUM_RX_CHANNELS);

    if(device == NULL) device = DEFAULT_DEVICE;
    info_print("using device %s", device);

    if(use_multichannel == 1) {
        num_channels = pfring_open_multichannel(device, snaplen, flags, ring);
        if(num_channels <= 0) {
            err_print("pfring_open_multichannel failed. Return channels: %d (%d): %s", num_channels, errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        if(num_channels > MAX_NUM_RX_CHANNELS) {
            warn_print("too many channels (%d), using %d channels", num_channels, MAX_NUM_RX_CHANNELS);
            num_channels = MAX_NUM_RX_CHANNELS;
        } else if (num_channels > numCPU) {
            warn_print("more channels (%d) than available cores (%d), using %d channels", num_channels, numCPU, numCPU);
            num_channels = numCPU;
        } else {
            debug_print("found %d channels", num_channels);
        }

        info_print("using multichannel PF_RING mode");

    } else {
        num_channels = 1;
        ring[0] = pfring_open(device, snaplen, flags);
        if(ring[0] == NULL) {
            err_print("pfring_open failed (%d): %s", errno, strerror(errno));
            exit(EXIT_FAILURE);
        }

        info_print("using single PF_RING mode");
    }
    
    pfring_version(ring[0], &version);
    info_print("using PF_RING v.%d.%d.%d",
        (version & 0xFFFF0000) >> 16,
        (version & 0x0000FF00) >> 8,
        version & 0x000000FF
    );

    if ((threads = calloc(num_channels, sizeof(struct thread_stats))) == NULL) {
        err_print("threads calloc failed (%d): %s", errno, strerror(errno));
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

    rc = pthread_mutexattr_init(&mattr);
    if (rc != 0) {
        err_print("pthread_mutexattr_init failed: (%d): %s", rc, strerror(rc));
        exit(EXIT_FAILURE);
    }

    rc = pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK_NP);
    if (rc != 0) {
        err_print("pthread_mutexattr_settype failed: (%d): %s", rc, strerror(rc));
        exit(EXIT_FAILURE);
    }

    rc = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
    if (rc != 0) {
        err_print("pthread_mutexattr_setpshared failed: (%d): %s", rc, strerror(rc));
        exit(EXIT_FAILURE);
    }

    rc = pthread_mutex_init(&do_shutdown, &mattr);
    if (rc != 0) {
        err_print("pthread_mutex_init failed: (%d): %s", rc, strerror(rc));
        exit(EXIT_FAILURE);
    }

    pthread_mutex_lock(&do_shutdown);

    if(cpu_percentage > 0) {
        int  high_priority;
        high_priority = sched_get_priority_max(SCHED_RR);

        if(cpu_percentage > high_priority) {
            warn_print("cpu_percentage(%hu) more than high priority(%d)", cpu_percentage, high_priority);
            cpu_percentage = high_priority;
        }
        info_print("set cpu_percentage to %hu", cpu_percentage);

        struct sched_param schedparam;
        schedparam.sched_priority = cpu_percentage;
        if(sched_setscheduler(0, SCHED_RR, &schedparam) == -1) {
            err_print("error while setting the scheduler (%d): %s", errno, strerror(errno));
        }
    }

    rc = mallopt(M_CHECK_ACTION, 1);
    if (rc != 1) {
        err_print("mallopt() failed (%d): %s", rc, strerror(rc));
        raise(SIGTERM);
    }

    u_int i;
    char path[256] = { 0 };

    for(i=0; i<num_channels; i++) {

        threads[i].ring = ring[i];
        threads[i].core_affinity = threads_core_affinity[i];

        snprintf(threads[i].name, sizeof(threads[i].name), "capture-cap-thread-%d", i);
        pfring_set_application_name(threads[i].ring, threads[i].name);

        pfring_set_application_stats(threads[i].ring, "Statistics not yet computed.");
        if(pfring_get_appl_stats_file_name(threads[i].ring, path, sizeof(path)) != NULL)
            info_print("Dumping statistics on %s", path);

        // rx_only_direction | rx_and_tx_direction
        if((rc = pfring_set_direction(threads[i].ring, direction)) != 0) {
            err_print("pfring_set_direction failed, returned %d", rc);
            raise(SIGTERM);
        }

        if((rc = pfring_set_socket_mode(threads[i].ring, recv_only_mode)) != 0) {
            err_print("pfring_set_socket_mode failed, returned %d", rc);
            raise(SIGTERM);
        }
        
        if(bpfFilter != NULL) {
            rc = pfring_set_bpf_filter(threads[i].ring, bpfFilter);
            if(rc != 0) {
                err_print("pfring_set_bpf_filter '%s' returned %d", bpfFilter, rc);
                raise(SIGTERM);
            }
            else {
                debug_print("successfully set BPF filter '%s' on %s", bpfFilter, threads[i].name);
            }
        }
        
        if((rc = pfring_enable_rss_rehash(threads[i].ring)) != 0)
            warn_print("pfring_enable_rss_rehash failed, returned %d", rc);

        if(poll_wtm) {
            if((rc = pfring_set_poll_watermark(threads[i].ring, poll_wtm)) != 0) {
                warn_print("pfring_set_poll_watermark returned %d", rc);
            } else {
                info_print("using poll_watermark %hu", poll_wtm);
            }
        }

        if((rc = pfring_set_poll_duration(threads[i].ring, 10000)) != 0)
            warn_print("pfring_set_poll_duration returned %d", rc);

        if((rc = pfring_enable_ring(threads[i].ring)) != 0) {
            err_print("pfring_enable_ring failed, returned %d", rc);
            raise(SIGTERM);
        } else {
            debug_print("enable id: %d ring device", i);
        }

        if(out_pcap_file) {
            char pcap_path[256];

            snprintf(pcap_path, sizeof(pcap_path), "%s", out_pcap_file);
            threads[i].dumper = pcap_dump_open(pcap_open_dead_with_tstamp_precision(DLT_EN10MB, 16384, PCAP_TSTAMP_PRECISION_NANO), pcap_path);
            if(threads[i].dumper == NULL) {
                warn_print("unable to create dump file '%s'", pcap_path);
            } else {
                info_print("write pcap dump to '%s'", pcap_path);
            }
        }

        info_print("starting thread: %s", threads[i].name);
        rc = pthread_create(&threads[i].pd_thread, NULL, packet_consumer_thread, (void *)(intptr_t)i);
        if (rc != 0) {
            err_print("pthread_create %s failed: (%d): %s", threads[i].name, rc, strerror(rc));
            raise(SIGTERM);
        }
    }

    info_print("starting thread: zmq_proxy_thread");
    rc = pthread_create(&t_zmq_proxy_thread, NULL, (void *)zmq_proxy_thread, NULL);
    if (rc != 0) {
        err_print("pthread_create zmq_proxy_thread failed: (%d): %s", rc, strerror(rc));
        exit(EXIT_FAILURE);
    }

    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);

    info_print("entering main loop");

    rc = pthread_join(t_zmq_proxy_thread, &t_join_res);
    if (rc != 0) {
        warn_print("pthread_join on '%s' failed", "t_zmq_proxy_thread");
    }

    if (t_join_res == PTHREAD_CANCELED)
        info_print("thread '%s' was canceled", "t_zmq_proxy_thread");
    else
        info_print("thread '%s' was terminated normally", "t_zmq_proxy_thread");

    for(i=0; i<num_channels; i++) {
        info_print("waiting while exit '%s'", threads[i].name);

        rc = pthread_join(threads[i].pd_thread, &t_join_res);
        if (rc != 0) {
            warn_print("pthread_join on '%s' failed", threads[i].name);
            continue;
        }

        if (t_join_res == PTHREAD_CANCELED)
            info_print("thread '%s' was canceled", threads[i].name);
        else
            info_print("thread '%s' was terminated normally", threads[i].name);
    }

    if(device)
        insane_free(device);

    if(zmq_parser_addr)
        insane_free(zmq_parser_addr);

    if(bpfFilter)
        insane_free(bpfFilter);

    if(out_pcap_file)
        insane_free(out_pcap_file);

    if(statsd_host)
        insane_free(statsd_host);

    insane_free(threads);

    zmq_ctx_destroy_func(_zmq_context);

    rc = pthread_mutex_destroy(&do_shutdown);
    if (rc != 0)
        err_print("pthread_mutex_destroy failed: (%d): %s", rc, strerror(rc));

    rc = pthread_mutexattr_destroy(&mattr);
    if (rc != 0)
        err_print("pthread_mutexattr_destroy failed: (%d): %s", rc, strerror(rc));

    //malloc_stats_print(NULL, NULL, NULL);

    info_print("exit");
    return 0;
}

// Packet Hexdump Decoder - http://sadjad.me/phd/
// https://github.com/netsniff-ng/netsniff-ng
// http://www.tcpdump.org/sniffex.c
// http://www.strchr.com/strcmp_and_strlen_using_sse_4.2 
// http://www.alfredklomp.com/programming/sse-strings/