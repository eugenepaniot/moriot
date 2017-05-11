#define JSON_RET_TMPL \
"{\
    \"timestamp_ns\": %lu, \
    \"ip\": { \
        \"src\": { \
            \"ip\": %u, \
            \"port\": %u \
        }, \
        \"dst\": { \
            \"ip\": %u, \
            \"port\": %u \
        }, \
        \"payload_offset\": %u \
    },\
    \"sip\": { \
        \"call_id\": %s, \
        \"to\": %s, \
        \"from\": %s, \
        \"sip_method\": %s, \
        \"status_code\": %d, \
        \"rc_session_id\": %s, \
        \"ua\": %s, \
        \"maxfwd\": %s, \
        \"cseq\": { \
            \"number\": %s, \
            \"method\": %s \
        } \
    },\
    \"raw\": { \
        \"pkt\": \"%s\" \
    } \
}"

struct cseq_t {
    char *number;
    char *method;
};

extern struct rslt_sip_message {
    char *call_id;
    char *to;
    char *from;
    char *sip_method;
    int status_code;
    char *rc_session_id;
    char *ua;
    char *maxfwd;
    char *via;
    struct cseq_t cseq;
};

extern inline int parseSIP(const char *payload, struct rslt_sip_message *ret);