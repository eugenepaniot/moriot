#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef DEBUG
#define DEBUG 1
#endif

#ifndef EXTRADEBUG
#define EXTRADEBUG 0
#endif

#define _MULTI_THREADED

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define RESET "\033[0m"

#define insane_free(p) { free(p); p = 0; }

#define info_print(FMT, ARGS...) do { \
        pid_t ptid = syscall(__NR_gettid); \
        unsigned int pid = getpid(); \
        fprintf(stdout, KGRN "[INFO (%u:%04x) %s:%d]:\t " KNRM FMT "\n", pid, ptid, __FUNCTION__, __LINE__, ## ARGS); \
        fflush(stdout); \
    } while (0)

#define warn_print(FMT, ARGS...) do { \
        pid_t ptid = syscall(__NR_gettid); \
        unsigned int pid = getpid(); \
        fprintf(stderr, KYEL "[WARN (%u:%04x) %s:%d]:\t " KNRM FMT "\n", pid, ptid, __FUNCTION__, __LINE__, ## ARGS); \
        fflush(stderr); \
    } while (0)

#define err_print(FMT, ARGS...) do { \
        pid_t ptid = syscall(__NR_gettid); \
        unsigned int pid = getpid(); \
        fprintf(stderr, KRED "[ERROR (%u:%04x) %s:%d]:\t " KNRM FMT "\n", pid, ptid, __FUNCTION__, __LINE__, ## ARGS); \
        fflush(stderr); \
    } while (0)

#define debug_print(FMT, ARGS...) do { \
        if (DEBUG) { \
            pid_t ptid = syscall(__NR_gettid); \
            unsigned int pid = getpid(); \
            fprintf(stdout, KBLU "[DEBUG (%u:%04x) %s:%d]:\t " KNRM FMT "\n", pid, ptid, __FUNCTION__, __LINE__, ## ARGS); \
            fflush(stdout); \
        } \
    } while (0)

extern u_short verbose;

extern int64_t clock_usecs (void);
extern long delta_time (struct timeval * now, struct timeval * before);
extern int needQuit(pthread_mutex_t *mtx);
extern void thread_exit_func(void *arg);

extern void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result);

extern void zmq_ctx_destroy_func(void *zmq_ctx);
extern void zmq_getsockopt_values(void *zmq_socket);
extern void zmq_setsockopt_func(void *zmq_sock);