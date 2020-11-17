import time

class Timer(object):

    def __init__(self, tme = .5):
        self.START_TIME = self.TIMER_STOP = -1
        self.TIMEOUT_INTERVAL = self.ESTIMATED_RTT = tme
        self.DEV_RTT = 0
        self.MAX_RTT = 5
        self.LAST_START = -1

    def mark(self):
        self.LAST_START = time.time()
    # Starts the timer
    def start(self):
        if self.START_TIME == self.TIMER_STOP:
            self.START_TIME = time.time()

    # Stops the timer
    def stop(self, recalc = True):
        if self.running() and recalc:
            SAMPLE_RTT = time.time() - self.START_TIME
            self.ESTIMATED_RTT *= 0.875
            self.ESTIMATED_RTT += SAMPLE_RTT / 8

            self.DEV_RTT *= 3 / 4
            self.DEV_RTT += abs(SAMPLE_RTT - self.ESTIMATED_RTT) / 4

            self.TIMEOUT_INTERVAL = self.ESTIMATED_RTT + 4 * self.DEV_RTT #max(.005, self.TIMEOUT_INTERVAL / 1.5)
        self.START_TIME = self.TIMER_STOP

    def duplicate(self):
        self.TIMEOUT_INTERVAL = min(3 / 2 * self.TIMEOUT_INTERVAL, self.MAX_RTT)

    # Determines whether the timer is runnning
    def running(self):
        return self.START_TIME != self.TIMER_STOP

    # Determines whether the timer timed out
    def timeout(self):
        if not self.running():
            return False
        else:
            if time.time() - self.START_TIME >= self.TIMEOUT_INTERVAL:
                self.duplicate()
                self.START_TIME = self.TIMER_STOP
                return True
            else:
                return False

    def wait(self, tme):
        return self.running() and time.time() -  self.LAST_START >= tme