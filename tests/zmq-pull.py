#!/usr/bin/env python

import sys
import zmq

context = zmq.Context(io_threads=4)

front = context.socket(zmq.PULL)
front.bind("tcp://*:6666")

back = context.socket(zmq.PUB)
back.bind("tcp://*:6667")

zmq.device(zmq.QUEUE, front, back)

context.term()