#!/usr/bin/python

import time
import random

def doTimeConsumingStep(N):
    """
    This represents the computational part of your simulation.

    For the sake of illustration, I've set it up so that it takes a random
    amount of time which is occasionally longer than the interval you want.
    """
    r = random.random()
    computationTime = N * (r + 0.2)
    print("...computing for %f seconds..."%(computationTime,))
    time.sleep(computationTime)


def timerTest(N=1):
    repsCompleted = 0
    beginningOfTime = time.clock()

    start = time.clock()
    goAgainAt = start + N
    while 1:
        print("Loop #%d at time %f" % (repsCompleted, time.clock() - beginningOfTime))
        repsCompleted += 1
        doTimeConsumingStep(N)
        #If we missed our interval, iterate immediately and increment the target time
        if time.clock() > goAgainAt:
            print("Oops, missed an iteration")
            goAgainAt += N
            continue
        #Otherwise, wait for next interval
        timeToSleep = goAgainAt - time.clock()
        goAgainAt += N
        time.sleep(timeToSleep)


if __name__ == "__main__":
    timerTest(0.2)