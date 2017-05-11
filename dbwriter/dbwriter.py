#!/usr/bin/env python

from __future__ import print_function

import multiprocessing
import threading
import time
import datetime
import re
import string
import pprint
import statsd
import json
import sys
import argparse
import resource

import zmq.green as zmq

import MySQLdb

table = """
CREATE TABLE `sip_capture` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `datetime` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `from` varchar(255) DEFAULT NULL,
  `to` varchar(255) DEFAULT NULL,
  `callid` varchar(255) DEFAULT NULL,
  `callid_rc` varchar(255) DEFAULT NULL,
  `user_agent` varchar(128) DEFAULT NULL,
  `request_method` varchar(128) DEFAULT NULL,
  `response_code` smallint(5) unsigned DEFAULT NULL,
  `source_ip` int(16) unsigned DEFAULT NULL,
  `source_port` smallint(6) unsigned DEFAULT NULL,
  `destination_ip` int(16) unsigned DEFAULT NULL,
  `destination_port` smallint(6) unsigned DEFAULT NULL,
  `malformed` tinyint(1) DEFAULT '0',
  `msg` mediumblob,
  PRIMARY KEY (`id`),
  clustering KEY `datetime` (`datetime`),
  KEY `from` (`from`),
  KEY `to` (`to`),
  KEY `callid` (`callid`),
  KEY `callid_rc` (`callid_rc`),
  KEY `user_agent` (`user_agent`),
  KEY `request_method` (`request_method`),
  KEY `response_code` (`response_code`),
  KEY `source_ip` (`source_ip`),
  KEY `source_port` (`source_port`),
  KEY `destination_ip` (`destination_ip`),
  KEY `destination_port` (`destination_port`),
  KEY `request_method_datetime` (`request_method`,`datetime`),
  KEY `response_code_datetime` (`response_code`,`datetime`),
  KEY `callid_callid_rc` (`callid`,`callid_rc`),
  KEY `callid_callid_rc_datetime` (`callid`,`callid_rc`,`datetime`),
  KEY `id_datetime` (`id`,`datetime`),
  KEY `malformed` (`malformed`)
) ENGINE=TOKUDB DEFAULT CHARSET=utf8
;


CREATE TABLE `sip_capture_sdp` (
  `id` bigint(20) unsigned NOT NULL,
  `codec` varchar(255) DEFAULT NULL,
  KEY `id` (`id`),
  KEY `codec` (`codec`),
  KEY `codec_2` (`codec`,`id`)
) ENGINE=TokuDB DEFAULT CHARSET=utf8


SELECT * FROM INFORMATION_SCHEMA.EVENTS \G

delimiter |
CREATE EVENT analyze_sip_capture_tables 
ON SCHEDULE 
    EVERY 1 HOUR
ON COMPLETION 
    NOT PRESERVE
COMMENT 'perrform analyze table'
DO
BEGIN
    ANALYZE TABLE sip_capture;
END |
delimiter ;


delimiter |
CREATE EVENT delete_old_data_sip_capture_tables
ON SCHEDULE 
    EVERY 1 MINUTE
ON COMPLETION 
    NOT PRESERVE
COMMENT 'Delete old data'
DO
BEGIN

    DELETE QUICK LOW_PRIORITY 
    FROM 
        sip_capture
    WHERE
        datetime <= DATE_ADD(NOW(), INTERVAL -1 DAY);

END |
delimiter ;

"""

def _print(msg="empty message", level="DEBUG"):
    if level == "ERROR":
        print("%s: %s" % (str(level).upper(), msg), file=sys.stderr)
    else:
        print("%s: %s" % (str(level).upper(), msg), file=sys.stdout)
        

class Server(object):
    def __init__(self):
        self.zmq_context = zmq.Context(io_threads=max(multiprocessing.cpu_count()-1, 1))
        self._threads = []

    def start(self):
        try:
            socket_front = self.zmq_context.socket(zmq.SUB)
            socket_front.setsockopt(zmq.SUBSCRIBE, '')
            socket_front.set_hwm(args.zhwm)
            socket_front.connect(args.rca)

            socket_back = self.zmq_context.socket(zmq.PUSH)
            socket_back.set_hwm(args.zhwm)

            socket_back.bind('inproc://backend')

            self._threads = [Worker(self.zmq_context, i) for i in range(0, WORKERS) ]
            
            for thread in self._threads:
                thread.setDaemon(True)
                thread.start()
        
            zmq.device(zmq.FORWARDER, socket_front, socket_back)

        except Exception, e:
            _print(repr(e), "ERROR")
            _print("bringing down zmq device")
        finally:
            self.stop()
            socket_front.close()
            socket_back.close()
            self.zmq_context.term()

    def stop(self):
        for thread in self._threads:
            try:
                _print("Stopping thread: %s" % thread.getName())
                thread.stop()
            except Exception, e:
                pass

        for thread in self._threads:
            try:
                _print("Waiting for thread: %s" % thread.getName())
                thread.join(2)
            except Exception, e:
                pass

class Worker(threading.Thread):
    def __init__(self, zmq_context, _id):
        super(Worker, self).__init__()
        self._stop = threading.Event()

        self.zmq_context = zmq_context
        self.worker_id = _id
        self.name = "worker-%u" % _id

        self.statsd = statsd.StatsClient(args.sa, args.sp)

        self.stats = {}
        self.stats['numPkts'] = 0
        self.stats['malformedNumPkts'] = 0


    def __del__(self):
        try:
            self._print ("closing zmq context", 'INFO')
            self.zmq_context.term()
        except Exception, e:
            pass

        try:
            if hasattr(self, 'db'):
                self._print ("closing connection to DB", 'INFO')
                self.db.close()
        except Exception, e:
            pass

    def stop(self):
        self._print("set stop flag")
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()

    def _print(self, msg="empty message", level="DEBUG"):
        _print("thread[%u][%s]: %s \n" % ( self.worker_id, self.name, msg), level)
        return

    def db_connect(self):
        if hasattr(self, 'db'):
            if self.db.open:
                return

        while not self.stopped():
            try:
                self.db = MySQLdb.connect(host=args.da, port=args.dp, user=args.du, passwd=args.dpw, db=args.ddb, 
                    charset='utf8', compress=True, init_command="SET time_zone='UTC'")
                if self.db.open:
                    self._print("successful connect to DB %s@%s/%s" % (args.du, args.da, args.ddb))
                    break
            except Exception, e:
                self._print("MySQL Error: %s" % repr(e), "ERROR")
                self._print("Reconnecting...")
                time.sleep(2)


    def run(self):
        socket = self.zmq_context.socket(zmq.PULL)
        socket.connect('inproc://backend')
        i=0

        while not self.stopped() and self.zmq_context:
            try:
                self.db_connect()
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

        self._print("Closing ZMQ socket")
        socket.close()

    def parse_for_malformed(self, data):
        if 0:
            """
            SEE: 
            https://tools.ietf.org/html/rfc3261
            https://tools.ietf.org/html/rfc4475



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
    Via                         R          amr   m   m   m   m   m   m
    Via                        rc          dr    m   m   m   m   m   m
    Warning                     r                -   o   o   o   o   o
    WWW-Authenticate           401         ar    -   m   -   m   m   m
    WWW-Authenticate           407         ar    -   o   -   o   o   o
            """

        malformed_reason = []
        malformed = 0

        payload_offset = data['ip']['payload_offset']

        # include non UTF8 symbols
        try:
            data['raw']['pkt'][payload_offset*2:].decode("hex").decode('utf8')
        except UnicodeDecodeError:
            malformed_reason.append("include non UTF8 symbols in payload_data")
            malformed += 1

        try:
            # required headers is None or empty
            if not malformed:
                if not data['sip']['call_id']:
                    malformed_reason.append("required headers 'Call-ID' is None or empty")
                    malformed += 1

                if not data['sip']['from']:
                    malformed_reason.append("required headers 'From' is None or empty")
                    malformed += 1

                if not data['sip']['to']:
                    malformed_reason.append("required headers 'To' is None or empty")
                    malformed += 1

                if data['sip']['cseq']:
                    if not data['sip']['cseq']['number']:
                        malformed_reason.append("required headers 'CSeq number' is None or empty")
                        malformed += 1
                        
                    elif data['sip']['cseq']['number'].isdigit() and int(data['sip']['cseq']['number']) > 4294967295:
                        malformed_reason.append("the CSeq sequence number is >2**32-1")
                        malformed += 1
                                                
                    if not data['sip']['cseq']['method']:
                        malformed_reason.append("required headers 'CSeq method' is None or empty")
                        malformed += 1
                else:
                    malformed_reason.append("required headers 'CSeq' is None or empty")
                    malformed += 1

                if data['sip']['sip_method']:
                    if data['sip']['maxfwd'] == "":
                        malformed_reason.append("required headers 'Max-Forwards' is empty")
                        malformed += 1

                    if data['sip']['maxfwd'].isdigit() and int(data['sip']['maxfwd']) > 255:
                        malformed_reason.append("Max-Forwards header value is >255")
                        malformed += 1
        except Exception, e:
            self._print("%s : err: %s" % repr(e), "ERROR")
            pass

        if malformed > 0:
            return "\n\n\nMALFORMED REASON:\n%s \n\nRAW PACKET:\n%s" % (" |\n".join(malformed_reason), data['raw']['pkt'] )
        else:
            return None

    def compute(self, request):
        if self.stopped() or request is None:
            return

        timer = self.statsd.timer("dbwriter.compute.%s" % self.name).start()

        self.stats['numPkts'] += 1
        self.statsd.gauge("dbwriter.compute.%s.numPkts" % self.name, self.stats['numPkts'], rate=0.1)

        try:
            data = json.loads(request)
            
            if args.debug >= 3:
                self._print(repr(request))

            sql_tmpl = """
                INSERT INTO sip_capture SET
                `datetime` = FROM_UNIXTIME(%(timestamp_ns)f),

                `from` = %(sip.from)s,
                `to` = %(sip.to)s,
                `callid` = %(sip.call_id)s,
                `callid_rc` = %(sip.rc_session_id)s,
                `request_method` = %(sip.sip_method)s,
                `response_code` = %(sip.status_code)s,
                `user_agent` = %(sip.ua)s,

                `source_ip` = %(ip.src.ip)u,
                `source_port` = %(ip.src.port)u,

                `destination_ip` = %(ip.dst.ip)u,
                `destination_port` = %(ip.dst.port)u,

                `malformed` = %(malformed)u,
                
                `msg` = "%(msg)s"
                """
            
            malformed_msg = self.parse_for_malformed(data)
            malformed = 0

            payload_offset = data['ip']['payload_offset']

            msg = ""
            try:
                msg = data['raw']['pkt'][payload_offset*2:].decode("hex")
            except UnicodeDecodeError:
                msg = repr(data)

            if malformed_msg is not None:
                msg += malformed_msg
                malformed = 1

                self.stats['malformedNumPkts'] += 1
                self.statsd.gauge("dbwriter.compute.%s.malformedNumPkts" % self.name, self.stats['malformedNumPkts'] )
            
            t = {}
            t['from'] = "NULL" if MySQLdb.escape_string( data['sip']['from'] ) == "" else "\"%s\"" % MySQLdb.escape_string( data['sip']['from'] )
            t['to'] = "NULL" if MySQLdb.escape_string( data['sip']['to'] ) == "" else "\"%s\"" % MySQLdb.escape_string( data['sip']['to'] )
            t['call_id'] = "NULL" if MySQLdb.escape_string( data['sip']['call_id'] ) == "" else "\"%s\"" % MySQLdb.escape_string( data['sip']['call_id'] )
            t['rc_session_id'] = "NULL" if MySQLdb.escape_string( data['sip']['rc_session_id'] ) == "" else "\"%s\"" % MySQLdb.escape_string( data['sip']['rc_session_id'] )
            t['sip_method'] = "NULL" if MySQLdb.escape_string( data['sip']['sip_method'] ) == "" else "\"%s\"" % MySQLdb.escape_string( data['sip']['sip_method'] )
            t['ua'] = "NULL" if MySQLdb.escape_string( data['sip']['ua'] ) == "" else "\"%s\"" % MySQLdb.escape_string( data['sip']['ua'] )

            sql = sql_tmpl % {
                            'timestamp_ns': data['timestamp_ns'] / float(1000000000),

                            'sip.from': t['from'],
                            'sip.to': t['to'],
                            'sip.call_id': t['call_id'],
                            'sip.rc_session_id': t['rc_session_id'],
                            'sip.sip_method': t['sip_method'],
                            'sip.status_code': data['sip']['status_code'] or "NULL",
                            'sip.ua': t['ua'],

                            'ip.src.ip': data['ip']['src']['ip'],
                            'ip.src.port': data['ip']['src']['port'],

                            'ip.dst.ip': data['ip']['dst']['ip'],
                            'ip.dst.port': data['ip']['dst']['port'],

                            'malformed': int(malformed),

                            'msg': MySQLdb.escape_string( msg )
                        }

            if args.debug >= 3:
                self._print("sip_capture prepare: %s" % sql )

            cursor = self.db.cursor()

            try:
                cursor.execute( sql )

                if args.debug >= 1:
                    self._print("sip_capture executed: %s" % cursor._last_executed)

                self.db.commit()
            except Exception, e:
                self.db.ping(True)
                self._print("%s" % cursor._last_executed, "ERROR")
                self._print("%s" % repr(e), "ERROR")
                self.db.rollback()
                pass

            finally:
                cursor.close()

        except Exception, e:
            self._print("%s : REQ: %s" % (repr(e), request), "ERROR")
            pass

        finally:
            timer.stop(send=True)

if __name__ == '__main__':
    global args
    global WORKERS

    parser = argparse.ArgumentParser(description='MORIOT Results DBwriter', argument_default=argparse.SUPPRESS)

    parser.add_argument('--rca', default='tcp://127.0.0.1:6667', help='Result collector ZMQ address')

    parser.add_argument('--da', help='Data node address', required=True)
    parser.add_argument('--dp', type=int, default=3306, help='Data node port')

    parser.add_argument('--du', default='root', help='Data node username')
    parser.add_argument('--dpw', default='', help='Data node username password')

    parser.add_argument('--ddb', default='moriot_data', help='Data node DB name')

    parser.add_argument('--sa', default='127.0.0.1', help='Stats address')
    parser.add_argument('--sp', type=int, default=8125, help='Stats port')

    parser.add_argument('--zhwm', type=int, default=10000, help='The ZMQ_HWM option shall set the high water mark for the specified socket.')

    parser.add_argument('--tm', type=int, default=8, help='Thread multiplicator. Worker count = CPU count*tm')

    parser.add_argument('--debug', type=int, default=0, help='Debug')

    args = parser.parse_args()

    if (args.tm <= 0):
        _print("Running in single proceess")
        WORKERS = 1
    else:
        WORKERS = multiprocessing.cpu_count()*args.tm

    resource.setrlimit(resource.RLIMIT_NOFILE, (WORKERS<<10, WORKERS<<10))
    _print("RLIMIT_NOFILE:", resource.getrlimit(resource.RLIMIT_NOFILE))

    resource.setrlimit(resource.RLIMIT_NPROC, (WORKERS*128, WORKERS*128))
    _print("RLIMIT_NPROC:", resource.getrlimit(resource.RLIMIT_NPROC))

    server = Server()
    try:
        server.start()
    except KeyboardInterrupt:
        _print("Main KeyboardInterrupt")
        pass
    except Exception, e:
        _print(repr(e), "ERROR")
        pass