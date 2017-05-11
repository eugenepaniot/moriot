#!/usr/bin/python

from scapy.all import *
import random
import multiprocessing
import threading
import statsd
import argparse

import time

def millis():
    return int(round(time.time() * 1000))

class Worker(threading.Thread):
    def __init__(self, pkts, interval, thread_id=0):
        super(Worker, self).__init__()
        self.pkts = pkts
        self.interval = interval
        self.thread_id = thread_id

    def run(self):
        stats = {}
        stats['numPkts'] = 0

        thread_name = "worker-%u" % self.thread_id

        sleepBetweenPkts = (float(self.interval)/float(self.pkts))

        sd = statsd.StatsClient(args.sa, args.sp)

        server = args.dst

        data = (
"""
INVITE sip:EPtest@%s SIP/2.0
To: EPtest<sip:EPtest@%s>
From: EPtest<sip:EPtest@%s>
Call-ID: 11111111111111111111111111111111
Via: localhost
CSeq: 1 INVITE
Contact: <sip:EPtest@%s:5076>
Max-Forwards: 2
Allow: INVITE, ACK, CANCEL, BYE
User-Agent: eptest/v1.0
Content-Type: application/sdp
Content-Length: 0
"""
        % (server, server, server, server)
        )

        print "%s pkts" % self.pkts
        print "%s interval" % self.interval
        print "%s interval" % self.interval
        print "%s sleepBetweenPkts" % sleepBetweenPkts

        lastTime = millis()

        pkt = IP(dst=server, proto=17) / UDP(dport=5060) / Raw(load=data)

        while 1:
            #if millis() - lastTime <= sleepBetweenPkts:
            #    time.sleep( sleepBetweenPkts )
            #    print sleepBetweenPkts
            #    continue

            #pkt[Ether].dst = "00:50:56:b7:53:af"
            #pkt[IP].src = RandIP("10.14.37.*")
            pkt[UDP].sport = random.randint(1024, 65534)

            if args.debug:
                pkt.show()

            send(pkt, verbose=0, count=self.pkts, inter=0)
            #time.sleep(sleepBetweenPkts)
            #sendpfast(pkt, pps=self.pkts)

            stats['numPkts'] += self.pkts
            sd.gauge("loadGen.%s.numPkts" % thread_name, stats['numPkts'], rate=1)


if __name__ == "__main__":
    global args

    parser = argparse.ArgumentParser(description='MORIOT load generator', argument_default=argparse.SUPPRESS)
    parser.add_argument('--pkts',type=int, default=100, help='How many packets send per interval')
    parser.add_argument('--int', type=int, default=1, help='Interval')

    parser.add_argument('--dst', default='127.0.0.1', help='Dest address')

    parser.add_argument('--sa', default='127.0.0.1', help='Stats address')
    parser.add_argument('--sp', type=int, default=8125, help='Stats port')
    parser.add_argument('--debug', type=int, default=0, help='Debug')

    args = parser.parse_args()

    cpuCount = multiprocessing.cpu_count()
    #cpuCount=1
    ppc = round(args.pkts/cpuCount)

    threads = [Worker(ppc, args.int, i) for i in range(0, cpuCount) ]

    for thread in threads:
        thread.setDaemon(True)
        thread.start()

    while True:
        time.sleep(1)
