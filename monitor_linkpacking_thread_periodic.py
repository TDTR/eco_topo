#!/usr/bin/env python
# -*- coding:utf-8 -*-

import threading
import time
import networkx as nx

class monitor_linkpacking_thread(threading.Thread):
    def __init__(self,logging,bin_content,flow_map,topology,period=5):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.logging = logging
        self.bin_content = bin_content
        self.flow_map = flow_map
        self.topology = topology
        self.period = period
        self.i = 0
        
    def run(self):
        self.logging.debug("Start monitor-thread.")
        while True:
            time.sleep(self.period)
            link_usage = {}
            link_usage.clear()
            self.logging.debug("LinkUsage calc IN")
            for src,dst in nx.edges_iter(self.topology):
                self.logging.debug("LinkUsage calc %s -> %s",src,dst)
                f_list_ = self.bin_content[src][dst]
                contention_ = 0
                for f in f_list_:
                    contention_ += self.flow_map[f]
                    link_usage[(src,dst)]=contention_
            self.logging.info("LinkUsage %s", link_usage)
            self.i += 1
            
    def notify_logical_instance(self, logical):
        self.topology = logical
    
