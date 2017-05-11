#!/usr/bin/env python

import sys
import time
import zmq

context = zmq.Context()
sock = context.socket(zmq.PUSH)

for arg in sys.argv[1:]:
    sock.connect(arg)

while True:
    time.sleep(1)
    d = sys.argv[1] + ':SEND:' + time.ctime()
    sock.send(d)
    print d
