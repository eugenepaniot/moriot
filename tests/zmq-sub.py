#!/usr/bin/env python

import sys
import zmq
import time

context = zmq.Context()
sock = context.socket(zmq.SUB)
sock.setsockopt(zmq.SUBSCRIBE, '')

for arg in sys.argv[1:]:
    sock.connect(arg)

while True:
    message = sock.recv()
    print message
    #time.sleep(1)