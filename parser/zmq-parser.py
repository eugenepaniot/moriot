#!/usr/bin/env python

from __future__ import print_function

import multiprocessing
import threading
import time
import datetime
import re
import string
import statsd
import json
import sys
import argparse
import resource
import os
import psutil
import time

import zmq.green as zmq

_threads = []

IGNORE_USER_AGENTS = ['friendly-scanner']

import ctypes, os

CLOCK_MONOTONIC_RAW = 4 # see <linux/time.h>

class timespec(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_long),
        ('tv_nsec', ctypes.c_long)
    ]

librt = ctypes.CDLL('librt.so.1', use_errno=True)
clock_gettime = librt.clock_gettime
clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(timespec)]

def monotonic_time():
    t = timespec()
    if clock_gettime(CLOCK_MONOTONIC_RAW , ctypes.pointer(t)) != 0:
        errno_ = ctypes.get_errno()
        raise OSError(errno_, os.strerror(errno_))
    return t.tv_sec + t.tv_nsec * 1e-9


if 0:
    """
   The "where" column describes the request and response types in which
   the header field can be used.  Values in this column are:

      R: header field may only appear in requests;

      r: header field may only appear in responses;

      2xx, 4xx, etc.: A numerical value or range indicates response
           codes with which the header field can be used;

      c: header field is copied from the request to the response.

      An empty entry in the "where" column indicates that the header
           field may be present in all requests and responses.

   The "proxy" column describes the operations a proxy may perform on a
   header field:

      a: A proxy can add or concatenate the header field if not present.

      m: A proxy can modify an existing header field value.

      d: A proxy can delete a header field value.

      r: A proxy must be able to read the header field, and thus this
           header field cannot be encrypted.

   The next six columns relate to the presence of a header field in a
   method:

      c: Conditional; requirements on the header field depend on the
           context of the message.

      m: The header field is mandatory.

      m*: The header field SHOULD be sent, but clients/servers need to
           be prepared to receive messages without that header field.

      o: The header field is optional.

      t: The header field SHOULD be sent, but clients/servers need to be
           prepared to receive messages without that header field.

           If a stream-based protocol (such as TCP) is used as a
           transport, then the header field MUST be sent.

      *: The header field is required if the message body is not empty.
           See Sections 20.14, 20.15 and 7.4 for details.

      -: The header field is not applicable.

   "Optional" means that an element MAY include the header field in a
   request or response, and a UA MAY ignore the header field if present
   in the request or response (The exception to this rule is the Require
   header field discussed in 20.32).  A "mandatory" header field MUST be
   present in a request, and MUST be understood by the UAS receiving the
   request.  A mandatory response header field MUST be present in the
   response, and the header field MUST be understood by the UAC
   processing the response.  "Not applicable" means that the header
   field MUST NOT be present in a request.  If one is placed in a
   request by mistake, it MUST be ignored by the UAS receiving the
   request.  Similarly, a header field labeled "not applicable" for a
   response means that the UAS MUST NOT place the header field in the
   response, and the UAC MUST ignore the header field in the response.

    Header field          where   proxy ACK BYE CAN INV OPT REG
    ___________________________________________________________
    Accept                  R            -   o   -   o   m*  o
    Accept                 2xx           -   -   -   o   m*  o
    Accept                 415           -   c   -   c   c   c
    Accept-Encoding         R            -   o   -   o   o   o
    Accept-Encoding        2xx           -   -   -   o   m*  o
    Accept-Encoding        415           -   c   -   c   c   c
    Accept-Language         R            -   o   -   o   o   o
    Accept-Language        2xx           -   -   -   o   m*  o
    Accept-Language        415           -   c   -   c   c   c
    Alert-Info              R      ar    -   -   -   o   -   -
    Alert-Info             180     ar    -   -   -   o   -   -
    Allow                   R            -   o   -   o   o   o
    Allow                  2xx           -   o   -   m*  m*  o
    Allow                   r            -   o   -   o   o   o
    Allow                  405           -   m   -   m   m   m
    Authentication-Info    2xx           -   o   -   o   o   o
    Authorization           R            o   o   o   o   o   o
    Call-ID                 c       r    m   m   m   m   m   m   DONE
    Call-Info                      ar    -   -   -   o   o   o
    Contact                 R            o   -   -   m   o   o
    Contact                1xx           -   -   -   o   -   -
    Contact                2xx           -   -   -   m   o   o
    Contact                3xx      d    -   o   -   o   o   o
    Contact                485           -   o   -   o   o   o
    Content-Disposition                  o   o   -   o   o   o
    Content-Encoding                     o   o   -   o   o   o
    Content-Language                     o   o   -   o   o   o
    Content-Length                 ar    t   t   t   t   t   t
    Content-Type                         *   *   -   *   *   *
    CSeq                    c       r    m   m   m   m   m   m   DONE
    Date                            a    o   o   o   o   o   o
    Error-Info           300-699    a    -   o   o   o   o   o
    Expires                              -   -   -   o   -   o
    From                    c       r    m   m   m   m   m   m   DONE
    In-Reply-To             R            -   -   -   o   -   -
    Max-Forwards            R      amr   m   m   m   m   m   m   DONE
    Min-Expires            423           -   -   -   -   -   m
    MIME-Version                         o   o   -   o   o   o
    Organization                   ar    -   -   -   o   o   o
    Priority                    R          ar    -   -   -   o   -   -
    Proxy-Authenticate         407         ar    -   m   -   m   m   m
    Proxy-Authenticate         401         ar    -   o   o   o   o   o
    Proxy-Authorization         R          dr    o   o   -   o   o   o
    Proxy-Require               R          ar    -   o   -   o   o   o
    Record-Route                R          ar    o   o   o   o   o   -
    Record-Route             2xx,18x       mr    -   o   o   o   o   -
    Reply-To                                     -   -   -   o   -   -
    Require                                ar    -   c   -   c   c   c
    Retry-After          404,413,480,486         -   o   o   o   o   o
    500,503             -   o   o   o   o   o
    600,603             -   o   o   o   o   o
    Route                       R          adr   c   c   c   c   c   c
    Server                      r                -   o   o   o   o   o
    Subject                     R                -   -   -   o   -   -
    Supported                   R                -   o   o   m*  o   o
    Supported                  2xx               -   o   o   m*  m*  o
    Timestamp                                    o   o   o   o   o   o
    To                        c(1)          r    m   m   m   m   m   m   DONE
    Unsupported                420               -   m   -   m   m   m
    User-Agent                                   o   o   o   o   o   o
    Via                         R          amr   m   m   m   m   m   m   DONE
    Via                        rc          dr    m   m   m   m   m   m   DONE
    Warning                     r                -   o   o   o   o   o
    WWW-Authenticate           401         ar    -   m   -   m   m   m
    WWW-Authenticate           407         ar    -   o   -   o   o   o

"""

def _print(msg="empty message", level="DEBUG"):
    if level == "ERROR":
        print("%s: %s" % (str(level).upper(), msg), file=sys.stderr)
    else:
        print("%s: %s" % (str(level).upper(), msg), file=sys.stdout)

class Server(object):
    global _threads

    def __init__(self):
        self.zmq_context = zmq.Context()
        
    def start(self):
        try:
            socket_front = self.zmq_context.socket(zmq.SUB)
            socket_front.setsockopt(zmq.SUBSCRIBE, '')
            socket_front.connect(args.ca)
            
            socket_back = self.zmq_context.socket(zmq.DEALER)
            socket_back.set_hwm(args.zhwm)
            socket_back.bind('inproc://backend')

            _threads = [Worker(self.zmq_context, i) for i in range(0, WORKERS) ]
            
            for thread in _threads:
                thread.setDaemon(True)
                thread.start()

            zmq.device(zmq.FORWARDER, socket_front, socket_back)

        except Exception, e:
            _print(repr(e))
            raise Exception(repr(e))

        finally:
            _print("bringing down zmq device")

            self.stop()

            socket_front.close()
            socket_back.close()

            self.zmq_context.term()

    def stop(self):
        for thread in _threads:
            try:
                _print("Stopping thread: %s" % thread.getName())
                thread.stop()
            except Exception, e:
                _print(repr(e), "ERROR")
                pass

        for thread in _threads:
            try:
                _print("Waiting for thread: %s" % thread.getName())
                thread.join(2)
            except Exception, e:
                _print(repr(e))
                pass


class Worker(threading.Thread):
    req_methods = "INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|PRACK|SUBSCRIBE|NOTIFY|PUBLISH|INFO|REFER|MESSAGE|UPDATE"

    re_sip_from = r"(?:(?:From:|f:).*(?:sip:)(?P<from>([\w\.\*\%\+\-\#]+)))"
    re_sip_to = r"(?:(?:To:|t:).*(?:sip:)(?P<to>([\w\.\*\%\+\-\#]+)))"
    re_sip_callid = r"(?:(?:Call-ID:|i:)[\s+]?(?P<callid>.*))"
    re_sip_callid_rc = r"(?:p-rc-session-id:[\s+]?(?P<callid_rc>.*))"
    re_sip_method_request = r'(?:(?P<request_method>' + req_methods + ')\s.*SIP/2.0)'
    re_sip_method_response = r"(?:SIP/2.0\s+(?P<response_code>\d+)\s+(?:\w+))"
    re_sip_via = r"(?:Via:[\s+]?(?P<via>.*))"
    re_sip_cseq = r'(?:CSeq:[\s+]?(?P<cseq>\d+[\s+]?(?:' + req_methods + ')))'
    re_sip_maxfwd = r"(?:Max-Forwards:[\s+]?(?P<maxfwd>\d+))"
    re_sip_user_agent = r"(?:User-Agent:\s+(?P<user_agent>.*))"

    re_sip_sdp_codecs = r"(?:a=rtpmap:\d+ (?P<sdp_codec>([\w-]+))/\d+)"

    def __init__(self, zmq_context, _id):
        try:
            super(Worker, self).__init__()
            self.zmq_context = zmq_context
            self.worker_id = _id
            self.name = "worker-%u" % _id

            self.stats = {}
            self.stats['numPkts'] = 0
            self.stats['malformedNumPkts'] = 0

            self.reg = re.compile(
                self.re_sip_from            + '|' + self.re_sip_to               + '|' + 
                self.re_sip_callid          + '|' + self.re_sip_callid_rc        + '|' +
                self.re_sip_method_request  + '|' + self.re_sip_method_response  + '|' +
                self.re_sip_cseq            + '|' + self.re_sip_user_agent       + '|' +
                self.re_sip_maxfwd          + '|' + self.re_sip_sdp_codecs       + '|' +
                self.re_sip_via
                ,re.IGNORECASE | re.MULTILINE | re.UNICODE )

            self.statsd = statsd.StatsClient(args.sa, args.sp)

            self.socket_result = self.zmq_context.socket(zmq.PUSH)
            self.socket_result.set_hwm(args.zhwm)
            self.socket_result.connect(args.rca)

            self._stop = threading.Event()

            self._print('started', 'INFO')

            self.start_time = monotonic_time()
        except Exception, e:
            self._print(repr(e), "ERROR")
            raise Exception(repr(e))

    def __del__(self):
        try:
            if hasattr(self, 'socket_result'):
                self._print ("closing zmq result collector socket", 'INFO')
                self.socket_result.close()

            self._print ("term zmq context", 'INFO')
            self.zmq_context.term()
        except Exception, e:
            self._print(repr(e), "ERROR")
            pass

    def stop(self):
        self._print("set stop flag")
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

    def _print(self, msg="empty message", level="DEBUG"):
        _print("thread[%u][%s]: %s" % ( self.worker_id, self.name, msg), level)
        return

    def run(self):
        try:
            socket = self.zmq_context.socket(zmq.DEALER)
            socket.connect('inproc://backend')

            while not self.stopped() and self.zmq_context:
                try:
                    request = socket.recv(flags=zmq.NOBLOCK)
                    result = self.compute(request)
                    
                except zmq.ZMQError as e:
                    if e.errno == zmq.EAGAIN:
                        time.sleep(1)
                        pass
                    else:
                        self._print("socket.recv failed with: %s" % e, "ERROR")
                        break

                except Exception, e:
                    self._print("%s" % e, "ERROR")
                    pass

        except Exception, e:
            self._print(repr(e), "ERROR")
            pass

        finally:
            self._print("Closing ZMQ socket")
            socket.close()

    def compute(self, request):
        if self.stopped() or request is None:
            return

        #timer = self.statsd.timer("parser.compute.%s" % self.name, rate=0.5).start()

        self.stats['numPkts'] += 1

        cur_time = monotonic_time()
        if ( cur_time - self.start_time) > 1:
            self.start_time = cur_time

            self.statsd.gauge("parser.compute.%s.numPkts" % self.name, self.stats['numPkts'] )

        try:
            nts = None
            src = None
            dst = None
            payload = None
            malformed = 0
            malformed_reason = ""

            #self._print("%s" % request )
            return

            try:
                nts, src, dst, payload = request.split('|', 3)
                src_ip, src_port = src.split(':', 2)
                dst_ip, dst_port = dst.split(':', 2)
                payload_offset, payload_data = payload.split(':', 2)
            except Exception, e:
                print ( "%s : %s" % (repr(request), repr(e)) )
                return
        
            payload_text = filter(lambda x: x in string.printable, payload_data[int(payload_offset)*2:].decode("hex"))

            try:
                # include non UTF8 symbols
                payload_data[int(payload_offset)*2:].decode("hex").decode('utf8')
            except UnicodeDecodeError:
                malformed_reason += " include non UTF8 symbols in payload_data |"
                malformed = 1

            #print "NTS: %s SRC: %s DST %s PAYL: %s" % (float(nts), src, dst, payload_text)
            #return

            #if nts is None or src is None or dst is None or payload_data is None or payload_text is None:
            #    raise Exception("bad data in request: %s", repr(request))

            data = {}
            data['data'] = None
            data['malformed_data'] = None

            sip_r = {}

            sip_r['source_ip'] = src_ip
            sip_r['source_port'] = src_port
            
            sip_r['destination_ip'] = dst_ip
            sip_r['destination_port'] = dst_port
            
            sip_r['from'] = None
            sip_r['to'] = None
            sip_r['callid'] = None
            sip_r['callid_rc'] = None
            sip_r['request_method'] = None
            sip_r['response_code'] = None
            sip_r['user_agent'] = None
            
            sip_r['cseq'] = None
            sip_r['maxfwd'] = None
            sip_r['via'] = None

            sip_r['enc_name'] = []

            sip_r['micro_ts'] = "%.6f" % (float(nts)/1000/1000/1000)

            try:
                sip_r['msg'] = payload_text.decode('utf8')

                if args.debug >= 1:
                    self._print( sip_r['msg'] )

            except UnicodeDecodeError:
                malformed_reason += " include non UTF8 symbols in payload_text |"
                malformed = 1

            sdp_r = {}

            s = self.reg.finditer(sip_r['msg'])
            for m in s:
                r = m.groupdict()

                if r['from'] is not None:
                    sip_r['from'] = r['from'].strip()

                if r['to'] is not None:
                    sip_r['to'] = r['to'].strip()

                if r['callid'] is not None:
                    sip_r['callid'] = r['callid'].strip()

                if r['callid_rc'] is not None:
                    sip_r['callid_rc'] = r['callid_rc'].strip()

                if r['request_method'] is not None:
                    sip_r['request_method'] = r['request_method'].strip()

                if r['response_code'] is not None:
                    sip_r['response_code'] = r['response_code'].strip()

                if r['user_agent'] is not None:
                    sip_r['user_agent'] = r['user_agent'].strip()

                if r['cseq'] is not None:
                    sip_r['cseq'] = r['cseq'].strip()

                if r['via'] is not None:
                    sip_r['via'] = r['via'].strip()
                    
                if r['maxfwd'] is not None:
                    sip_r['maxfwd'] = r['maxfwd'].strip()

                if r['sdp_codec'] is not None:
                    sip_r['enc_name'].append(r['sdp_codec'].strip())

            if sip_r['callid'] is None or sip_r['callid'] == "" or \
                sip_r['from'] is None or sip_r['from'] == "" or \
                sip_r['to'] is None or sip_r['to'] == "" or \
                sip_r['cseq'] is None or sip_r['cseq'] == "" or \
                sip_r['via'] is None or sip_r['via'] == "":

                malformed_reason += " required headers is None or empty |"
                malformed = 1

            if sip_r['user_agent'] is not None and sip_r['user_agent'] == "":
                malformed_reason += " user agent defined but empty |"
                malformed = 1

            if sip_r['request_method'] is not None and (sip_r['maxfwd'] is None or sip_r['maxfwd'] == ""):
                malformed_reason += " Max-Forwards header required for SIP requests |"
                malformed = 1

            if malformed == 1:
                self.stats['malformedNumPkts'] += 1
                self.statsd.gauge("parser.compute.%s.malformedNumPkts" % self.name, self.stats['malformedNumPkts'], rate=0.1)

                malformed_data = "Malformed reason: %s \nData: \n%s" % (malformed_reason, payload_data)
                data['malformed_data'] = malformed_data

            data['data'] = sip_r

            jr = json.dumps(data)

            if args.debug >= 1:
                self._print( jr )

            self.socket_result.send( jr, flags=zmq.NOBLOCK )

        except Exception, e:
            self._print("%s : REQ: %s" % (repr(e), request), "ERROR")
            pass

        finally:
            if args.debug > 0:
                self._print("STATS: %s | %s" % (self.stats['numPkts'], self.stats['malformedNumPkts']))

            #timer.stop(send=True)

if __name__ == '__main__':
    global args
    global WORKERS

    parser = argparse.ArgumentParser(description='MORIOT Parser', argument_default=argparse.SUPPRESS)

    parser.add_argument('--rca', default='tcp://127.0.0.1:6666', help='Result collector ZMQ address')
    parser.add_argument('--ca', default='tcp://127.0.0.1:5555', help='Capture node ZMQ address')

    parser.add_argument('--sa', default='127.0.0.1', help='Stats address')
    parser.add_argument('--sp', type=int, default=8125, help='Stats port')

    parser.add_argument('--zhwm', type=int, default=100000, help='The ZMQ_HWM option shall set the high water mark for the specified socket.')

    parser.add_argument('--tm', type=int, default=4, help='Thread multiplicator. Worker count = CPU count*tm')

    parser.add_argument('--debug', type=int, default=0, help='Debug')

    args = parser.parse_args()

    if args.tm <=0:
        WORKERS=1
    else:
        WORKERS = multiprocessing.cpu_count()*args.tm

    #resource.setrlimit(resource.RLIMIT_NOFILE, (WORKERS<<10, WORKERS<<10))
    #_print("RLIMIT_NOFILE:", resource.getrlimit(resource.RLIMIT_NOFILE))

    #resource.setrlimit(resource.RLIMIT_NPROC, (WORKERS*128, WORKERS*128))
    #_print("RLIMIT_NPROC:", resource.getrlimit(resource.RLIMIT_NPROC))

    try:
        p = psutil.Process()
        #p.nice(-20)

        _print("NICE: PID: %d VALUE: %d" % (os.getpid(), p.nice()))
    except Exception, e:
        _print(repr(e), "NICE FAILED")
        pass
    
    server = Server()
    try:
        server.start()
    except KeyboardInterrupt:
        _print("Main KeyboardInterrupt")
        pass
    except Exception, e:
        _print(repr(e), "ERROR")
        pass