#!/usr/bin/env python
# -*- coding:utf-8 -*-

# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
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

bug fix 
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpidToStr
from pox.lib.util import strToDPID
import networkx as nx

log = core.getLogger()
# physical topology graph 
##topo = nx.MultiGraph()
topo = nx.DiGraph()

# logaical topology graph
##eco_topo = nx.MultiGraph()
eco_topo = nx.DiGraph()

# ethaddr -> (switch,port)
mac_map = {}

# bin packing map [sw1][sw2]->[flow id]
## ToDo 作り直し
content_map = defaultdict(lambda:defaultdict(lambda:list()))

# flow_id
f_id = -1
# [flow_id]-> size
flow_map = {}

BANDWIDTH = 1000
ITEM_SIZE = 5
IDLE_TIMEOUT = 1000
HARD_TIMEOUT = 3000

def _calc_packing(p):
    contention = 0
    for s1,s2 in zip(p[:-1],p[1:]):
        contention += sum(content_map[s1][s2])
    return (BANDWIDTH -contention)

def _get_raw_path(src,dst):
    global eco_topo

    # print src,dst
    shortest_path_len = nx.dijkstra_path_length(eco_topo,dpidToStr(src.dpid),dpidToStr(dst.dpid))
    # get path list
    path_list = list(nx.all_simple_paths(eco_topo, source=dpidToStr(src.dpid),
                                         target=dpidToStr(dst.dpid), cutoff= shortest_path_len+1))
    # get max contention value
    bin_content =[]
    for i in range(len(path_list)):
        bin_content.append(_calc_packing(path_list[i]))

    # get max content index list
    index =[]
    for i,v in enumerate(bin_content):
        if(v == max(bin_content)):index.append(i)

    if len(index) == 1:
        # if max contention path is only 1!
        return path_list[index[0]]
    else :
        # not only 1 path are the same value of binの空き
        # calc hop count
        hop_list = []
        for i in index:
            hop_list.append(len(path_list[i]))
        
        # return min number of hops path_list
        # カウンタの値を参照する場合はここをいじる
        return path_list[hop_list[hop_list.index(min(hop_list))]]
    

def _check_path(p):
    global eco_topo
    for i in range(len(p) -1 ):
        if eco_topo[p[i][0]][p[i+1][0]] != p[i][1]:
            return False
    return True

def _get_path(src,dst,final_port):
    global f_id
    global eco_topo

    #print '_get_path', src,dst,final_port

    if src == dst:
        path = [str(src)]
    else:
        # path <- return path list src to dst express str(dpid)
        path = _get_raw_path(src, dst)
        if path is None: return None
        #path = [src] + path + [dst]
        print "raw:        ",path

    r = []
    
    for s1,s2 in zip(path[:-1],path[1:]):
        ## 怪しい only one switch の場合エラーl
        #port = eco_topo[s1][s2].values
        port = eco_topo[s1][s2]['port']
        r.append((s1,port))
        content_map[s1][s2].append(f_id)
        content_map[s2][s1].append(f_id)
    
    r.append((path[-1], final_port))

    #assert _check_path(r)

    return r
    
class PathInstalled(Event):
    """
    Fired when a path is installed
    """
    def __init__(self,path):
        Event.__init__(self)
        self.path = path


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
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.idle_timeout = IDLE_TIMEOUT
        msg.hard_timeout = HARD_TIMEOUT
        msg.actions.append(of.ofp_action_output(port = port))
        msg.buffer_id = buf
        switch.connection.send(msg)

    def _install_path(self, p, match, buffer_id=-1):
        for s,port in p[1:]:
            sw = eco_topo.node[s]['switch'] 
            self._install(sw, port, match)

        src_sw= eco_topo.node[p[0][0]]['switch']
        self._install(src_sw,p[0][1], match, buffer_id)

        core.eco_topology.raiseEvent(PathInstalled(p))

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
                msg = of.ofp_packet_out()
                msg.actions.append(of.ofp_action_output(port = event.port))
                msg.data = e.pack()
                self.connection.send(msg)

            return

        print 'will install this path:',p
        self._install_path(p,match,event.ofp.buffer_id)
        log.debug("Installing path for %s -> %s %04x (%i hops)",
                  match.dl_src,match.dl_dst,match.dl_type,len(p))
    
    def _handle_PacketIn(self, event):
        global f_id
        global eco_topo

        def flood():
            """ Flooding the packet"""
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)
        
        def drop():
            """Kill the buffer"""
            if event.ofp.buffer_id != -1:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                event.ofp.buffer_id = -1
                msg.in_port = event.port
                self.connection.send(msg)

        packet = event.parsed

        # loc = (switch, port)
        loc = (self,event.port)
        oldloc = mac_map.get(packet.src)

        if packet.type == packet.LLDP_TYPE:
            drop()
            return
        
        print packet.src,packet.dst,"*",loc,oldloc
        
        if oldloc is None:
            if packet.src.isMulticast() == False:
                mac_map[packet.src] = loc #learn position for ethaddr
                log.debug("Learned %s at %s.%i",packet.src, loc[0],loc[1])
        elif oldloc != loc:
            # ethaddr seen at different place
            # eco_topo[] is MultiGraph().neighbors(n)
            # input: node Returns: list node
            if eco_topo.has_node(dpidToStr(loc[0].dpid)) == True:
                if eco_topo[dpidToStr(loc[0].dpid)].has_key(loc[1])==False:
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
                f_id += 1
                dest = mac_map[packet.dst]
                match = of.ofp_match.from_packet(packet)
                flow_map[f_id]=ITEM_SIZE
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

class eco_topology(EventMixin):
    global topo
    global eco_topo
    _eventMixin_events = set([
        PathInstalled,
        ])

    def __init__(self):
        self.listenTo(core.openflow, priority=0)
        self.listenTo(core.openflow_discovery)

    def _handle_LinkEvent(self,event):
        global eco_topo
        global topo
        def flip(link):
            return Discovery.Link(link[2],link[3], link[0],link[1])

        l = event.link
        string_dpid1 = dpidToStr(l.dpid1)
        string_dpid2 = dpidToStr(l.dpid2)

        # clear all entry of switch
        clear = of.ofp_flow_mod(match=of.ofp_match(),command=of.OFPFC_DELETE)
        # index = str(dpid) , sw=Switch 
        for index,sw in topo.nodes_iter(data=True):
            sw.values()[0].connection.send(clear)
        flow_map.clear()
        
        if event.removed:
            if l.dpid2 in topo[string_dpid1]:
                topo.remove_edge(string_dpid1, string_dpid2)
            if l.dpid1 in topo[string_dpid2]:
                topo.remove_edge(string_dpid2, string_dpid1)

            for ll in core.openflow_discovery.adjacency:
                if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
                    if flip(ll) in core.openflow_discovery.adjacency:
                        #topo.add_edge(string_dpid1, string_dpid2, key='go',port=ll.port1)
                        #topo.add_edge(string_dpid2, string_dpid1,key='back',port=ll.port2)
                        topo.add_edge(string_dpid1, string_dpid2,port=ll.port1)
                        topo.add_edge(string_dpid2, string_dpid1,port=ll.port2)
                        break
        else:
            # もし、既に接続済みなら無視できる
            # 未接続ならば、
            if topo.has_edge(string_dpid1, string_dpid2) == False:
                if flip(l) in core.openflow_discovery.adjacency:
                    #topo.add_edge(string_dpid1, string_dpid2, key='go'port=l.port1)
                    topo.add_edge(string_dpid1, string_dpid2, port=l.port1)
                    #topo.add_edge(string_dpid1, string_dpid2, key='back',port=l.port2)
                    topo.add_edge(string_dpid2, string_dpid1, port=l.port2)

        # create eco topology
        # TODO debug
        temp1 = nx.Graph(topo)
        temp2 = nx.minimum_spanning_tree(temp1)
        eco_topo = nx.DiGraph(temp2)
        for e in topo.edges_iter():
            if (topo.has_edge(e[0],e[1]) == True and eco_topo.has_edge(e[0],e[1]) == True):
                if(topo[e[0]][e[1]]['port'] == eco_topo[e[0]][e[1]]['port']) == False:
                    eco_topo.add_edge(e[0],e[1],port=topo[e[0]][e[1]]['port'])
                else : continue
            else : continue
        
        #print eco_topo.node
        #print 'topo:', topo.edge
        #print 'eco:', eco_topo.edge
        for n in eco_topo.nodes_iter():
            physical_edge = topo.edges(n)
            logical_edge = eco_topo.edges(n)
            # fat treeからトポロジを吸収していく
            if(len(physical_edge) == 4 and len(logical_edge)==1):
		eco_topo.remove_edge(*logical_edge[0])
        
    def _handle_ConnectionUp(self, event):
        str_event_dpid = dpidToStr(event.dpid)
        if topo.has_node(str_event_dpid) == False:
            log.debug("hoge")
            # New Switch
            sw = Switch()
            topo.add_node(str_event_dpid,switch=sw)
            sw.connect(event.connection)
            print topo.node
        else:
            log.debug("event dpid is %s", str_event_dpid)
            sw = topo.node[str_event_dpid]['switch']
            sw.connect(event.connection)

def launch():
    if 'openflow_discovery' not in core.components:
        import pox.openflow.Discovery as discovery
        core.registerNew(discovery.Discovery)

    core.registerNew(eco_topology)

