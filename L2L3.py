#!/usr/bin/env python
# -*- coding:utf-8 -*-

class L2L3:
    def __init__(self):
        self.list = []
        
    def show_ip(self):
        for iterator in self.list:
            print iterator[0]
            
    def show_mac(self):
        for iterator in self.list:
            print iterator[1]

    def set_entry(self,ip,mac):
        self.list.append((ip,mac))
        return True
    def remove_entry(self,ip,mac):
        try:
            self.list.index((ip,mac))
            self.list.remove((ip,mac))
            return True
        except ValueError:
            return False        

    def get_mac_address(self,ip):
        for i in self.list:
            if (i[0]==ip):
                return i[1]
            else: continue
        return None
        
