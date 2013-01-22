#!/usr/bin/env python
# -*- coding:utf-8 -*-

# Copyright 2012 James McCauley
#
# This file is part of POX.
#
#l POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.
"""
This Program is prototype of master thesis toru-tu@naist

Dependes on openflow.discovery
Works with openflow.spanning_tree

master
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
#from pox.openflow.discovery import Discovery
#from eco_flow_table import FlowTable
from eco_discovery import Discovery
from pox.lib.util import dpidToStr
from pox.lib.util import strToDPID
from PathInstalled import *
import networkx as nx
import threading
import time
#import logging
#import logging.config
from monitor_thread import *
# experimental parameter is here.
from variable_parameter import *

log = core.getLogger()

# physical topology graph
phy_topology = nx.DiGraph()

# low power subnet generated by phy_topology
eco_subnet = nx.DiGraph()

# ethaddr -> (switch,port)
mac_map = {}

# bin packing map [sw1][sw2]->[flow id]
content_map = defaultdict(lambda:defaultdict(lambda:list()))

# Thread class
# output number of edges and nodes to stdout 
monitor  = None

# give each flow using flow identification
flow_id = -1
# [flow_id]-> size
flow_map = {}

def _calc_packing(p):
    contention_ = []
    for s1,s2 in zip(p[:-1],p[1:]):
        f_list_ = map(int,content_map[s1][s2])
        # TODO(2012/11/30): add all items in content_map[s1][s2].
        # for f in f_list:
        #     contention += int(flow_map[f])
        contention_.append(len(f_list_) * ITEM_SIZE)
        
    return (BANDWIDTH -max(contention_))

def _get_raw_path(src,dst):
    def get_path_list(phy_topology,src,dst):
        shortest_path_len_ = nx.dijkstra_path_length(phy_topology,dpidToStr(src.dpid),dpidToStr(dst.dpid))
        simple_paths_ = list(nx.all_simple_paths(phy_topology,source=dpidToStr(src.dpid),
                                             target=dpidToStr(dst.dpid), cutoff = shortest_path_len_ + CUTOFF))
        return simple_paths_

    global eco_subnet
    global phy_topology

    # 省電力サブネット上でパスを取得
    path_list_ = get_path_list(eco_subnet,src,dst)
    if len(path_list_) == 0:
        # 省電力サブネット上にパスがないので，物理トポロジ上で取得
        path_list_ = get_path_list(phy_topology,src,dst)
        # pathのdiffをとって、diff結果のノードを追加する必要がある
    
    # get max contention value
    bin_content_ =[]
    for i in range(len(path_list_)):
        bin_content_.append(_calc_packing(path_list_[i]))

    if max(bin_content_) < 0:
        log.info("I need more capacity")
        path_list_ = get_path_list(phy_topology,src,dst)
        bin_content_ =[]
        for i in range(len(path_list_)):
            bin_content_.append(_calc_packing(path_list_[i]))
            
    log.debug("number_of_bin_content_ = %s" % len(bin_content_))
    log.debug("bin_content_ = %s" % bin_content_)
            
    # get max content index list
    index =[]
    for i,v in enumerate(bin_content_):
        if(v == max(bin_content_)):index.append(i)
    
    if len(index) == 1:
        # if max contention path is only 1!
        return path_list_[index[0]]
    else :
        # not only 1 path are the same value of binの空き
        # calc hop count
        hop_list = []
        for i in index:
            hop_list.append(len(path_list_[i]))
        
        # return min number of hops path_list_
        ## TODO
        # if hop_count が同じ場合
        # カウンタの値を参照してさらに分岐する場合
        #return path_list_[hop_list[hop_list.index(min(hop_list))]]
        return path_list_[index[hop_list.index(min(hop_list))]]

def _check_path(src,dst):
    global eco_subnet
    global phy_topology

    if eco_subnet.has_edge(src,dst) == False:
        if phy_topology.has_edge(src,dst) == False :
            return False
        else:
            forward_port_ = phy_topology[src][dst]['port']
            back_port_ = phy_topology[dst][src]['port']
            eco_subnet.add_edge(src, dst, port = forward_port_)
            eco_subnet.add_edge(dst, src, port = back_port_)
            log.info("add_edge to eco_subnet %s -> %s" % (src,dst))
    return True
    

def _check_switch(p):
    global eco_subnet
    global phy_topology
    for i in range(len(p) -1):
        if eco_subnet.has_node(p[i]) is False:
            if phy_topology.has_node(p[i]) is False : return False
            else:
                log.info("add_node to eco_subnet %s" % phy_topology.node[p[i]])
                sw_instance_ = phy_topology.node[p[i]]['switch']
                eco_subnet.add_node(p[i], switch = sw_instance_)
    return True

def _check_switch2(p):
    global eco_subnet
    global phy_topology
    for i in range(len(p)):
        if eco_subnet.has_node(p[i]) is False:
            if phy_topology.has_node(p[i]) is False : return False
            else:
                log.debug("INIT:add_node to eco_subnet %s" % phy_topology.node[p[i]])
                sw_instance_ = phy_topology.node[p[i]]['switch']
                eco_subnet.add_node(p[i], switch = sw_instance_)
    return True

def handle_timeout(**kw):
    global content_map
    log.debug("delete f_map %s->%s:%d" % (kw['sw1'],kw['sw2'],kw['f']))
    log.debug("f's type is %s"% type(kw['f']))
    # content_map[s1][s2]==flow_id を消す
    content_map[kw['sw1']][kw['sw2']].remove(kw['f'])
    
def _get_path(src,dst,final_port):
    global flow_id
    global eco_subnet
    global phy_topology

    #print '_get_path', src,dst,final_port

    if src == dst:
        path_ = [str(src)]
    else:
        # path <- return path list src to dst express str(dpid)
        path_ = _get_raw_path(src, dst)
        if path_ is None: return None
        #path = [src] + path + [dst]
        ###log.info("raw:        ",path)
        
    if _check_switch(path_)==False:
        exit 
    r_ = []
    
    for s1,s2 in zip(path[:-1],path[1:]):
        if _check_path(s1,s2) == False: exit 
        ## 怪しい only one switch の場合エラー
        #port = eco_subnet[s1][s2].values
        port_ = eco_subnet[s1][s2]['port']
        r_.append((s1,port_))
        content_map[s1][s2].append(flow_id)
        content_map[s2][s1].append(flow_id)
       # Timer(HARD_TIMEOUT, handle_timeout, kw={})
        Timer(HARD_TIMEOUT, handle_timeout, kw={'f':flow_id,'sw1':s1,'sw2':s2})
        Timer(HARD_TIMEOUT, handle_timeout, kw={'f':flow_id,'sw1':s2,'sw2':s1})
       
    r_.append((path[-1], final_port))

    #    assert _check_path(r)

    return r_

    
class Switch(EventMixin):
    def __init__(self):
        self.connection = None
        self.ports = None
        self.dpid = None
        self._listeners = None

    def __repr__(self):
        return dpidToStr(self.dpid)

    def _install(self,switch,port,match,buf=-1):
        # install switch flow_table
        # configure flow_entry timeout here!!
        msg_ = of.ofp_flow_mod()
        msg_.match = match
        msg_.idle_timeout = IDLE_TIMEOUT
        msg_.hard_timeout = HARD_TIMEOUT
        msg_.actions.append(of.ofp_action_output(port = port))
        msg_.buffer_id = buf
        switch.connection.send(msg_)

    def _install_path(self, p, match, buffer_id=-1):
        for s,port in p[1:]:
            sw = eco_subnet.node[s]['switch'] 
            self._install(sw, port, match)

        src_sw= eco_subnet.node[p[0][0]]['switch']
        self._install(src_sw,p[0][1], match, buffer_id)

        event = PathInstalled(p)
        core.eco_subnetlogy.raiseEvent(event)

    def install_path(self, dst_sw, last_port, match, event):
        # dst_sw is switch instance
        # print 'install_path', self,dst_sw
        p = _get_path(self,dst_sw,last_port)
        if p is None:
            log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)
            
            import pox.lib.packet as pkt
            
            if (match.dl_type == pkt.ethernet.IP_TYPE and
                event.parsed.find('ipv4')):
                # It's IP -- let's send a destination unreachable
                log.debug("Dest unreachable (%s -> %s)",
                          match.dl_src, match.dl_dst)
                
                from pox.lib.addresses import EthAddr
                e = pkt.ethernet()
                e.src = EthAddr(dpidToStr(self.dpid)) #FIXME: Hmm...
                e.dst = match.dl_src
                e.type = e.IP_TYPE
                ipp = pkt.ipv4()
                ipp.protocol = ipp.ICMP_PROTOCOL
                ipp.srcip = match.nw_dst #FIXME: Ridiculous
                ipp.dstip = match.nw_src
                icmp = pkt.icmp()
                icmp.type = pkt.ICMP.TYPE_DEST_UNREACH
                icmp.code = pkt.ICMP.CODE_UNREACH_HOST
                orig_ip = event.parsed.find('ipv4')
                
                d = orig_ip.pack()
                d = d[:orig_ip.hl * 4 + 8]
                import struct
                d = struct.pack("!HH", 0,0) + d #FIXME: MTU
                icmp.payload = d
                ipp.payload = icmp
                e.payload = ipp
                msg_ = of.ofp_packet_out()
                msg_.actions.append(of.ofp_action_output(port = event.port))
                msg_.data = e.pack()
                self.connection.send(msg_)

            return

        log.debug('will install this path:%s' %p)
        self._install_path(p,match,event.ofp.buffer_id)
        log.debug("Installing path for %s -> %s %04x (%i hops)",
                  match.dl_src,match.dl_dst,match.dl_type,len(p))
    
    def _handle_PacketIn(self, event):
        global flow_id
        global eco_subnet

        def flood():
            """ Flooding the packet"""
            msg_ = of.ofp_packet_out()
            msg_.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg_.buffer_id = event.ofp.buffer_id
            msg_.in_port = event.port
            self.connection.send(msg_)
        
        def drop():
            """Kill the buffer"""
            if event.ofp.buffer_id != -1:
                msg_ = of.ofp_packet_out()
                msg_.buffer_id = event.ofp.buffer_id
                event.ofp.buffer_id = -1
                msg_.in_port = event.port
                self.connection.send(msg_)            
            
        packet = event.parsed

        # loc = (switch, port)
        loc = (self,event.port)
        oldloc = mac_map.get(packet.src)

        if packet.type == packet.LLDP_TYPE:
            drop()
            return
        
        log.debug("packet:src= %s packet:dst= %s / (loc,oldloc)= (%s,%s) ",packet.src,packet.dst,loc,oldloc)
        
        if oldloc is None:
            if packet.src.isMulticast() == False:
                mac_map[packet.src] = loc #learn position for ethaddr
                log.debug("Learned %s at %s.%i",packet.src, loc[0],loc[1])
        elif oldloc != loc:
            # ethaddr seen at different place
            # eco_subnet[] is MultiGraph().neighbors(n)
            # input: node Returns: list node
            if eco_subnet.has_node(dpidToStr(loc[0].dpid)) == True:
                if eco_subnet[dpidToStr(loc[0].dpid)].has_key(loc[1])==False:
                    # New place is another plain port (probably)
                    log.debug("%s moved from %s.%i to %s.%i?", packet.src,
                            dpidToStr(oldloc[0].connection.dpid), oldloc[1],
                            dpidToStr(   loc[0].connection.dpid),    loc[1])
                    if packet.src.isMulticast() == True:
                    #if packet.src.isMulticast() == False:
                        mac_map[packet.src] = loc
                        log.debug("Learned %s at %s.%i",packet.src, loc[0],loc[1])
                elif packet.dst.isMulticast() == False:
                    log.warning("Packet from %s arrived at %s.%i without flow",
                                    packet.src, dpidToStr(self.dpid), event.port)

        if packet.dst.isMulticast():
            log.debug("flood multicast from %s", packet.src)
            flood()
        else:
            if packet.dst not in mac_map:
                log.debug("%s unknown --drop", packet.dst,)
                drop()
            else:
                flow_id += 1
                dest = mac_map[packet.dst]
                match = of.ofp_match.from_packet(packet)
                flow_map[flow_id]=ITEM_SIZE
                log.debug('flow_id %d ITEM_SIZE=%d' % (flow_id,flow_map[flow_id]))
                self.install_path(dest[0],dest[1],match,event)
                
        
    def disconnect(self):
        if self.connection is not None:
            log.debug("Disconnect %s " % (self.connection,))
            self.connection.removeListeners(self._listeners)
            self.connection = None
            self._listeners = None

    def connect(self,connection):
        if self.dpid is None:
            self.dpid = connection.dpid
        assert self.dpid == connection.dpid

        if self.ports is None:
            self.ports = connection.features.ports
        self.disconnect()
        log.debug("Connect %s" % (connection,))
        self.connection = connection
        self._listeners = self.listenTo(connection)

    def _handle_ConnectionDown(self, event):
        self.disconnect()

    def _handle_FlowRemoved(self,event):
        print "_FlowRemoved! %s" % event.ofp.reason

class eco_topology(EventMixin):
    global phy_topology
    global eco_subnet
    _eventMixin_events = set([
        PathInstalled,
        ])

    def __init__(self):
        self.listenTo(core.openflow, priority=0)
        self.listenTo(core.openflow_discovery)

    def _handle_LinkEvent(self,event):
        global eco_subnet
        global phy_topology
        def flip(link):
            return Discovery.Link(link[2],link[3], link[0],link[1])

        l = event.link
        string_dpid1 = dpidToStr(l.dpid1)
        string_dpid2 = dpidToStr(l.dpid2)

        # clear all entry of switch
        clear = of.ofp_flow_mod(match=of.ofp_match(),command=of.OFPFC_DELETE)
        # index = str(dpid) , sw=Switch 
        for index,sw in phy_topology.nodes_iter(data=True):
            sw.values()[0].connection.send(clear)
        flow_map.clear()
        
        if event.removed:
            if l.dpid2 in phy_topology[string_dpid1]:
                phy_topology.remove_edge(string_dpid1, string_dpid2)
            if l.dpid1 in phy_topology[string_dpid2]:
                phy_topology.remove_edge(string_dpid2, string_dpid1)

            for ll in core.openflow_discovery.adjacency:
                if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
                    if flip(ll) in core.openflow_discovery.adjacency:
                        phy_topology.add_edge(string_dpid1, string_dpid2,port=ll.port1)
                        phy_topology.add_edge(string_dpid2, string_dpid1,port=ll.port2)
                        break
        else:
            # もし、既に接続済みなら無視できる
            # 未接続ならば、
            if phy_topology.has_edge(string_dpid1, string_dpid2) == False:
                if flip(l) in core.openflow_discovery.adjacency:
                    phy_topology.add_edge(string_dpid1, string_dpid2, port=l.port1)
                    phy_topology.add_edge(string_dpid2, string_dpid1, port=l.port2)

        # create eco phy_topologylogy
        # TODO debug
        #temp1 = nx.Graph(phy_topology)
        #temp2 = nx.minimum_spanning_tree(temp1)
        #eco_subnet = nx.DiGraph(temp2)
        
        #monitor.notify_logical_instance(eco_subnet)
        
        #for e in phy_topology.edges_iter():
        #    if (phy_topology.has_edge(e[0],e[1]) == True and eco_subnet.has_edge(e[0],e[1]) == True):
        #        if(phy_topology[e[0]][e[1]]['port'] == eco_subnet[e[0]][e[1]]['port']) == False:
        #            eco_subnet.add_edge(e[0],e[1],port=phy_topology[e[0]][e[1]]['port'])
        #        else : continue
        #    else : continue
        
        # remove_node = []
        # for n in eco_subnet.nodes_iter():
        #     physical_edge = phy_topology.edges(n)
        #     logical_edge = eco_subnet.edges(n)
        #     # fat treeからトポロジを吸収していく
        #     if(len(physical_edge) == 4 and len(logical_edge)==1):
	# 	eco_subnet.remove_edge(*logical_edge[0])
        #         remove_node.append(n)
        # for n in remove_node:
        #     eco_subnet.remove_node(n)
        #log.debug("nodes= %s -> eco_nodes= %s" % (phy_topology.nodes(),eco_subnet.nodes()))
        #log.debug("edges= %s-> eco_edges= %s" % (phy_topology.edges(),eco_subnet.edges()))
                 
    def _handle_ConnectionUp(self, event):
        str_event_dpid = dpidToStr(event.dpid)
        if phy_topology.has_node(str_event_dpid) == False:
            # New Switch
            sw = Switch()
            phy_topology.add_node(str_event_dpid,switch=sw)
            sw.connect(event.connection)
            log.debug("node %s" % phy_topology.node)
        else:
            log.debug("event dpid is %s", str_event_dpid)
            sw = phy_topology.node[str_event_dpid]['switch']
            sw.connect(event.connection)

def create_eco_subnet():
    global phy_topology
    
    switchNum = POD_NUM**3/4 + 1
    p_edge_top = POD_NUM**3/4 + 1 + POD_NUM + POD_NUM**2/2
    p_edge_bottom = p_edge_top + POD_NUM**2/2
    
    all_path = nx.shortest_path(phy_topology,dpidToStr(switchNum))
    for edge_num in range(p_edge_top,p_edge_bottom):
        path = all_path[dpidToStr(edge_num)]
        _check_switch2(path)
        for s1,s2 in zip(path[:-1],path[1:]):
            if _check_path(s1,s2)==False:
                exit
            
def launch():
    global eco_subnet
    global phy_topology
    global monitor
    if 'openflow_discovery' not in core.components:
        import pox.openflow.Discovery as discovery
        core.registerNew(discovery.Discovery)

    core.registerNew(eco_subnetlogy)
    monitor = monitor_thread(log,eco_subnet,phy_topology,5)
    monitor.start()
    Timer(60,create_eco_subnet)
