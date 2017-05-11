#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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
#include <jemalloc/jemalloc.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <inttypes.h>
#include <sys/time.h>
#include <ctype.h>
#include <wchar.h>
#include <sched.h>

#include "capture.h"
#include "capture-parser-osip.h"

#include <osipparser2/osip_message.h>
#include <osipparser2/sdp_message.h>
#include <osipparser2/osip_parser.h>

u_short verbose;

// https://www.gnu.org/software/osip/doc/html/structosip__message.html
// https://www.gnu.org/software/osip/doc/html/group__oSIP__SDP.html

extern inline int parseSIP(const char *payload, struct rslt_sip_message *ret) {
    int rc;

    osip_message_t *sip;

    osip_header_t *rc_session_id_header;
    osip_header_t *ua_header;
    osip_header_t *maxfwd_header;

    osip_via_t *via;

    ret->call_id = "null";
    ret->to = "null";
    ret->from = "null";
    ret->sip_method = "null";
    ret->status_code = 0;
    ret->rc_session_id = "null";
    ret->ua = "null";
    ret->maxfwd = "null";
    ret->cseq.number = "null";
    ret->cseq.method = "null";
    ret->via = "null";

    if (verbose > 1)
        debug_print("%s", payload);

    rc = osip_message_init(&sip);
    if (rc != 0) {
        err_print("osip_message_init failed"); 
        goto error;
    }

    rc = osip_message_parse(sip, payload, strlen(payload));
    if (rc == -1) {
        err_print("osip_message_parse failed %d", rc);
        goto error;
    }
    
    for (int posattr = 0; !osip_list_eol(&sip->vias, posattr); posattr++) {
        rc = osip_message_get_via (sip, posattr, &via);
        if (rc < 0)
            break;

        if(via != NULL ) {
            asprintf(&ret->via, "%s { \
                \"version\": %s, \
                \"protocol\": %s, \
                \"host\": %s, \
                \"port\": %s \
             }", 
             ret->via,
             via->version,
             via->protocol,
             via->host,
             via->port
             );
            
            if (verbose > 3) {
                debug_print("%s", ret->via);
                //debug_print("via: %s %s %s %s %s", via->version, via->protocol, via->host, via->port);
            }
        }
    }

    if(sip->call_id != NULL && sip->call_id->number != NULL) {
        asprintf(&ret->call_id, "\"%s\"", sip->call_id->number);
        
        if (verbose > 3)
            debug_print("call_id: %s %s", ret->call_id,  sip->call_id->host);
    }

    if(sip->to != NULL && sip->to->url->username != NULL) {
        asprintf(&ret->to, "\"%s\"", sip->to->url->username);

        if (verbose > 3)
            debug_print("to: %s %s ", sip->to->displayname,  ret->to);
    }

    if(sip->from != NULL && sip->from->url->username != NULL) {
        asprintf(&ret->from, "\"%s\"", sip->from->url->username);

        if (verbose > 3)
            debug_print("from: %s %s ", sip->from->displayname,  sip->from->url->username);
    }

    if(sip->sip_method != NULL) {
        asprintf(&ret->sip_method, "\"%s\"", sip->sip_method);

        if (verbose > 3)
            debug_print("sip_method: %s", sip->sip_method);
    }

    if(sip->status_code != 0) {
        ret->status_code = sip->status_code;

        if (verbose > 3)
            debug_print("status_code: %d", sip->status_code);
    }

    osip_message_header_get_byname (sip, "p-rc-session-id", 0, &rc_session_id_header);
    if (rc_session_id_header != NULL && rc_session_id_header->hvalue != NULL) {
        asprintf(&ret->rc_session_id, "\"%s\"", rc_session_id_header->hvalue);

        if (verbose > 3)
            debug_print("p-rc-session-id: %s ", rc_session_id_header->hvalue);
    }

    osip_message_header_get_byname (sip, "User-Agent", 0, &ua_header);
    if (ua_header != NULL && ua_header->hvalue != NULL) {
        asprintf(&ret->ua, "\"%s\"", ua_header->hvalue);

        if (verbose > 3)
            debug_print("ua: %s ", ua_header->hvalue);
    }

    osip_message_header_get_byname (sip, "Max-Forwards", 0, &maxfwd_header);
    if (maxfwd_header != NULL && maxfwd_header->hvalue != NULL) {
        asprintf(&ret->maxfwd, "\"%s\"", maxfwd_header->hvalue);

        if (verbose > 3)
            debug_print("maxfwd: %s ", maxfwd_header->hvalue);
    }

    if(sip->cseq !=NULL) {
        if(sip->cseq->number != NULL)
            asprintf(&ret->cseq.number, "\"%s\"", sip->cseq->number);

        if(sip->cseq->method != NULL)
            asprintf(&ret->cseq.method, "\"%s\"", sip->cseq->method);

        if (verbose > 3)
            debug_print("cseq: %s %s", sip->cseq->number, sip->cseq->method);
    }

    /* ----------------------------------- */
    // SDP PARSE
/*
    sdp_message_t *sdp;
    osip_content_type_t *ctt;

    rc = sdp_message_init(&sdp);
    if (rc != 0) {
        err_print("sdp_message_init failed"); 
        goto error;
    }

    ctt = osip_message_get_content_type(sip);

    if(strcmp(ctt->type, "application") == 0 && strcmp(ctt->subtype, "sdp") == 0) {

        osip_body_t * sdp_body = (osip_body_t *)osip_list_get(&sip->bodies, 0);
        if(sdp_body) {
            char *sdp_str = sdp_body->body;

            if(verbose >= 3) 
                debug_print("SDP: %s", sdp_str);

            sdp_message_parse(sdp, sdp_str);

            sdp_media_t *med = (sdp_media_t *)osip_list_get(&sdp->m_medias, 0);

            if ((char *) osip_list_get (&med->m_payloads, 0) != NULL) {
                for (int posattr=0; !osip_list_eol(&med->a_attributes, posattr); posattr++) {

                    sdp_attribute_t *attr = (sdp_attribute_t *) osip_list_get (&med->a_attributes, posattr);

                    if (0 == osip_strncasecmp (attr->a_att_field, "rtpmap", 6) && attr->a_att_value) {
                        if(verbose >= 3) 
                            debug_print("%s", attr->a_att_value);
                    }
                }

            }
        }
    }
*/
    /* ----------------------------------- */
error:
    osip_message_free(sip);
    //sdp_message_free(sdp);

    return rc;
}
