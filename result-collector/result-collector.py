#!/usr/bin/env python

import sys
import statsd
import argparse
import os
import psutil
import resource
import os

from multiprocessing import Process, cpu_count

import zmq.green as zmq
from zmq.devices.monitoredqueuedevice import MonitoredQueue
from zmq.utils.strtypes import asbytes

frontend_port = 6666
backend_port = 6667
monitor_port = 6668

context = zmq.Context(io_threads=max(cpu_count()-1, 1))
args = None

def monitordevice():
    in_prefix=asbytes('in')
    out_prefix=asbytes('out')

    monitoringdevice = MonitoredQueue(zmq.PULL, zmq.PUB, zmq.PUB, in_prefix, out_prefix)
    
    monitoringdevice.bind_in("tcp://*:%d" % frontend_port)
    monitoringdevice.bind_out("tcp://*:%d" % backend_port)
    monitoringdevice.bind_mon("tcp://127.0.0.1:%d" % monitor_port)
    
    #monitoringdevice.setsockopt_in(zmq.HWM, 100000)
    #monitoringdevice.setsockopt_out(zmq.HWM, 100000)

    print "Monitoring device has started"
    monitoringdevice.start()
    
def monitor():
    print "Starting monitoring process"
    sd = statsd.StatsClient(args.sa, args.sp)

    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.connect ("tcp://127.0.0.1:%s" % monitor_port)
    socket.setsockopt(zmq.SUBSCRIBE, "")

    stats = {}
    stats['numPkts'] = 0

    while True:
        string = socket.recv_multipart()
        if args.debug >= 1:
            print "Monitoring Client: %s" % string

        stats['numPkts'] += 1
        sd.gauge("result-collector.numPkts", stats['numPkts'], rate=0.1)
        
try:
    parser = argparse.ArgumentParser(description='MORIOT Results DBwriter', argument_default=argparse.SUPPRESS)
    parser.add_argument('--sa', default='127.0.0.1', help='Stats address')
    parser.add_argument('--sp', type=int, default=8125, help='Stats port')

    parser.add_argument('--debug', type=int, default=0, help='Debug')

    args = parser.parse_args()

    resource.setrlimit(resource.RLIMIT_NOFILE, (512<<10, 512<<10))
    print "RLIMIT_NOFILE:", resource.getrlimit(resource.RLIMIT_NOFILE)

    resource.setrlimit(resource.RLIMIT_NPROC, (1024, 1024))
    print "RLIMIT_NPROC:", resource.getrlimit(resource.RLIMIT_NPROC)

    p = psutil.Process()
    p.nice(-20)

    print "NICE: PID: %d VALUE: %d" % (os.getpid(), p.nice())

    monitoring_p = Process(target=monitordevice)
    monitoring_p.start()

    monitorclient_p = Process(target=monitor)
    monitorclient_p.start()

    monitoring_p.join()
    monitorclient_p.join()

except KeyboardInterrupt:
    print "Main KeyboardInterrupt"
    monitorclient_p.terminate()
    monitoring_p.terminate()

except Exception, e:
    print repr(e)
    pass

context.term()

#TODO:
# Rewrite to C