#!/usr/bin/env python
# -*- coding:utf-8 -*-

import threading
import time

class monitor_thread(threading.Thread):
    def __init__(self,logging,logical,physical,interval):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.i = 0
        self.logging = logging
        self.logical = logical
        self.physical = physical
        self.interval = interval
        
    def run(self):
        self.logging.debug("Start monitor-thread.")
        while True:
            time.sleep(self.interval)
            self.logging.info("logical----Active node: %4d Active edge: %4d"
                              % ( len(self.logical),self.logical.size()))
            self.logging.info("physical----Active node: %4d Active edge: %4d"
                              % (len(self.physical),self.physical.size()))
            self.i += 1
    
    def notify_logical_instance(self, logical):
        self.logical = logical
    
