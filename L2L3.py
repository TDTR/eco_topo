#!/usr/bin/env python
# -*- coding:utf-8 -*-

class L2L3:
    def __init__(self):
        self.list = []
        self.index = 0

    def __iter__(self):
        return self

    def __str__(self):
        return self.show_ip()

    def next(self):
        if self.index >= len(self.list):
            self.index = 0
            raise StopIteration
        result = self.list[self.index]
        self.index += 1
        return result
    
    def show_ip(self):
        for iterator in self.list:
            print iterator[0]
            
    def show_mac(self):
        for iterator in self.list:
            print iterator[1]

    def set_entry(self,ip,mac):
        print ip,"-",mac
        self.list.append((ip,mac))
        print self.list
    
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
        
