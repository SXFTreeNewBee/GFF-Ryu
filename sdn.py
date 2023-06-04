from operator import attrgetter
from tkinter import ttk
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import api as topo_api
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
from ryu.topology.api import get_all_switch, get_link, get_switch
import networkx as nx
from ryu.ofproto import ether
import random
from ryu.base.app_manager import lookup_service_brick
class ryu(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
#==========Init====================
    def __init__(self, *args, **kwargs):
        super(ryu, self).__init__(*args, **kwargs)
        #flag
        self.init_flag=False
        #group table
        self.group={} # {((ip_src,ip_dst),sw_id):group_id}
        self.action_bucket={}   # {((ip_src,ip_dst),(sw_id,group_id)):buckets[actions.......]}

        #topology
        self.topology_api_app = self
        self.link_to_port = {}       # (src_dpid,dst_dpid)->(src_port,dst_port
        self.access_host={}#{(dpid):[host1,host2]}
        self.access_table = {}       # {(sw,port) : host_ip}
        self.switch_port_table = {}  # {dpip : set(port_num)}
        self.access_ports = {}       # {dpid : set(port_num)}
        self.interior_ports = {}     # {dpid : set(port_num)}
        self.datapaths = {}
        self.out_ports={}
        self.dps = {}  # {dpid : switch}
        self.switches = None
        #path
        self.cur_path={} # {(ip_src,ip_dst):cur_path[]}
        #parameter
        self.bandwidth=10   # Bandwidth
        self.tx_bytes = {}  # {(dpid,port_no) : tx_bytes}
        self.port_tx_speed = {}  # {(dpid,port_no) : speed}
        self.monitor_table = {}  # {(ip_src,ip_dst,tuple(path)):ava_bw}
        self.paths={} #{(ip_src,ip_dst):[path1[],path2[].......pathn[]]}
        self.flow_bytes={} #{(dpid,ip_src,ip_dst):flow_bytes}
        self.flow_speed={} # {(dpid,ip_src,ip_dst):speed}
        self.POD = 4  # 胖树层数
        self.SWITCHES_NUM = int(self.POD ** 2 + (self.POD / 2) ** 2)  # 交换机总数
        self.HOST_NUM = int(self.POD ** 3 / 4)
        self.ACCESS_SW_LIST = [i for i in range(31, 39)]  # 接入层交换机序号
        self.AGG_SW_LIST = [j for j in range(21, 29)]
        self.CORE_SW_LIST = [K for K in range(11, 15)]
        self.ele_flows={}
        self.sw_port_map={}
        #networkx
        self.graph = nx.DiGraph()
        self.discover_thread = hub.spawn(self._discover)
        #ele_flow_cost
        self.ele_cost=0
#=============discover=============
    def _discover(self):
        while True:
            for datapath in self.dps.values():
                self.request_stats(datapath)
                #self.send_echo_request()
            self.get_topology(None)
            self.Init_monitor_table()
            self.flows_monitor()
            print('大流调度开销：',self.ele_cost)
            hub.sleep(2)
#============topo================
    def get_topology(self, ev):
        """
            Get topology info
        """
        # print "get topo"
        switch_list = get_all_switch(self)
        # print switch_list
        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()
        links = get_link(self.topology_api_app, None)
        self.create_interior_links(links)
        self.create_access_ports()
        self.get_graph()
        #初始化
        self.core_pop_map()
        self.agg_pop_map()
        self.core_pop_rule()
        self.agg_pop_rule()
        self.agg_group()
    def register_access_info(self, dpid, in_port, ip, mac):
        """
            Register access host info into access table.
        """
        # print "register " + ip
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == ip:
                    return
                else:
                    self.access_table[(dpid, in_port)] = ip
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_host.setdefault(dpid,[])
                self.access_table[(dpid, in_port)] = ip
                self.access_host[dpid].append(ip)
                return
    def get_host_location(self, host_ip):
        """
            Get host location info:(datapath, port) according to host ip.
        """
        for key in self.access_table.keys():
            if self.access_table[key] == host_ip:
                return key
        self.logger.debug("%s location is not found." % host_ip)
        return None
    def get_switches(self):
        return self.switches
    def get_sw(self, dpid, in_port, src, dst):
        """
            Get pair of source and destination switches.
        """
        src_sw = dpid
        dst_sw = None
        dst_port = None

        src_location = self.get_host_location(src)#源交换机的id
        if in_port in self.access_ports[dpid]:
            if (dpid,  in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None

        dst_location = self.get_host_location(dst)#目的主机所连接的交换机的id，返回的是（dpid，in_port)
        if dst_location:
            dst_sw = dst_location[0]
            dst_port = dst_location[1]
        return src_sw, dst_sw, dst_port
    def get_links(self):
        return self.link_to_port
    def get_datapath(self, dpid):
        if dpid not in self.dps:
            switch = topo_api.get_switch(self, dpid)[0]
            self.dps[dpid] = switch.dp
            return switch.dp
        return self.dps[dpid]
    def create_port_map(self, switch_list):
        for sw in switch_list:
            dpid = sw.dp.id
            self.graph.add_node(dpid)
            self.dps[dpid] = sw.dp
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)
    def create_interior_links(self, link_list):
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[
                (src.dpid, dst.dpid)] = (src.port_no, dst.port_no)#1->2交换机的连接端口为：3->4

            # Find the access ports and interiorior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)
    def create_access_ports(self):
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            self.access_ports[sw] = all_port_table - interior_port#全部端口减去交换机互连端口得到主机端口
    def get_graph(self):
        link_list = topo_api.get_all_link(self)
        for link in link_list:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            port_key = (src_dpid, src_port)
            weight = 0
            lldp_delay=0
            if port_key in self.port_tx_speed.keys():
                weight = self.port_tx_speed[port_key]#将当前链路带宽作为权重
            self.graph.add_edge(src_dpid, dst_dpid,
                                src_port=src_port,
                                dst_port=dst_port,
                                weight=weight,
                                )
        return self.graph
#===========request=================
    def request_stats(self, datapath):
        """
            Sending request msg to datapath
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
        req=parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
#=============handler==============
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        dpid = datapath.id
        self.datapaths[dpid] = datapath

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        ignore_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        ignore_actions = []
        self.add_flow(datapath, 65534, ignore_match, ignore_actions)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if eth_type == ether_types.ETH_TYPE_LLDP:
            return

        if ip_pkt:
            src_ipv4 = ip_pkt.src
            src_mac = eth_pkt.src
            if src_ipv4 != '0.0.0.0' and src_ipv4 != '255.255.255.255':
                self.register_access_info(datapath.id, in_port, src_ipv4, src_mac)

        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac

            # Record the access info
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if isinstance(ip_pkt, ipv4.ipv4):
            if len(pkt.get_protocols(ethernet.ethernet)):
                self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst)

        '''if eth_type == ether_types.ETH_TYPE_LLDP:
            src_dpid, src_port = LLDPPacket.lldp_parse(msg.data)
            dst_dpid = msg.datapath.id
            if self.switch_brick is None:
                self.switch_brick=lookup_service_brick("switches")
            for port in self.switch_brick.ports.keys():
                if src_dpid == port.dpid and src_port == port.port_no:
                    port_data=self.switch_brick.ports[port]
                    timestamp = port_data.timestamp
                    if timestamp:
                        delay = time.time() - timestamp
                        self.lldp_delay[(src_dpid,dst_dpid)]=delay'''
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in sorted([flow for flow in body if ((flow.priority not in [0, 65535]) and (flow.match.get('ipv4_src')) and (flow.match.get('ipv4_dst')))],
                           key=lambda flow: (flow.priority, flow.match.get('ipv4_src'), flow.match.get('ipv4_dst')),reverse=False):
            #reverse=True 表示降序排序，默认是升序,表示在计算的过程中，只计算优先级最高的转发规则的流表数据
            ip_src = stat.match.get('ipv4_src')
            ip_dst = stat.match.get('ipv4_dst')
            key = (dpid, ip_src, ip_dst)
            value = (stat.byte_count, stat.duration_sec, stat.duration_nsec)
            if key in self.flow_bytes.keys():
                if key[0] in self.ACCESS_SW_LIST:
                    bytes = ((value[0] - self.flow_bytes[key][0]) / 1024/1024) * 8  # Mbit
                    #period = (value[1] + value[2] / (10 ** 9)) - (self.flow_bytes[key][1] + self.flow_bytes[key][2] / (10 ** 9))
                    self.flow_speed[key] = bytes / 2
            self.flow_bytes[key] = value
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.duration_sec, stat.duration_nsec)
                if key in self.tx_bytes.keys():
                    tx_speed = ((value[0] - self.tx_bytes[key][0]) / 1024/1024) * 8
                    period = (value[1] + value[2] / (10 ** 9)) - (
                                self.tx_bytes[key][1] + self.tx_bytes[key][2] / (10 ** 9))
                    self.port_tx_speed[key] = tx_speed / period
                self.tx_bytes[key] = value
#===========info====================
    def Init_monitor_table(self):
        # {(ip_src,ip_dst,tuple(path)):(Min_available_Bw,Max_bw}
        # {(ip_src,ip_dst):cur_path[]}
        if self.monitor_table.keys():
            for sw_path in self.monitor_table.keys():
                Max_bw = []
                for i in range(len(list(sw_path[2])) - 1):
                    Max_bw.append(self.graph[sw_path[2][i]][sw_path[2][i + 1]]["weight"])
                # update monitor_table
                if len(Max_bw) != 0:
                    self.monitor_table[(sw_path[0], sw_path[1], sw_path[2])] = self.bandwidth - max(Max_bw)
        else:
            return
    def flows_monitor(self):
        # flow_speed {(dpid,ip_src,ip_dst):speed} 其中dpid仅为接入层交换机
        if self.flow_speed.keys():
            for k in self.flow_speed.keys():
                self.flow_recognizer(src_dpid=k[0], ip_src=k[1], ip_dst=k[2])  # 先通过flow_speed全部更新ele_flows的数据，再进行策略选择
        else:
            return
#=========handler==================
    def core_pop_map(self):
        for core in self.CORE_SW_LIST:
            self.sw_port_map.setdefault(core,{})
            for agg in self.AGG_SW_LIST:
                if (core,agg) in self.link_to_port.keys():
                    self.sw_port_map[core][agg]=self.link_to_port[(core,agg)][0]#get core->agg out_port
    def agg_pop_map(self):
        for agg in self.AGG_SW_LIST:
            self.sw_port_map.setdefault(agg,{})
            for core in self.CORE_SW_LIST:
                if (agg, core) in self.link_to_port.keys():
                    self.sw_port_map[agg][core]=self.link_to_port[(agg,core)][0]
            for acc in self.ACCESS_SW_LIST:
                if (agg,acc) in self.link_to_port.keys():
                    self.sw_port_map[agg][acc]=self.link_to_port[(agg,acc)][0]
    def core_pop_rule(self):
        for dpid in self.CORE_SW_LIST:
            if dpid in self.dps:
                for acc in self.ACCESS_SW_LIST:
                    subnet = list(str(acc))[1]
                    dst_ip = '10.' + subnet + '.0.0/16'
                    match = self.get_datapath(dpid).ofproto_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ipv4_dst=dst_ip)
                    for agg in self.sw_port_map[dpid].keys():
                        if acc in self.sw_port_map[agg].keys():
                            actions = [self.get_datapath(dpid).ofproto_parser.OFPActionOutput(self.sw_port_map[dpid][agg])]
                            self.add_flow(dp=self.get_datapath(dpid), p=10, match=match, actions=actions,idle_timeout=0, hard_timeout=0)
    def agg_pop_rule(self):
        for dpid in self.AGG_SW_LIST:
            if dpid in self.dps:
                datapath = self.get_datapath(dpid)
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                for sw, port in self.sw_port_map[dpid].items():
                    if sw in self.ACCESS_SW_LIST:
                        subnet=list(str(sw))[1]
                        dst_ip='10.'+subnet+'.0.0/16'
                        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=dst_ip)
                        actions = [parser.OFPActionOutput(port)]
                        self.add_flow(dp=datapath, p=10, match=match, actions=actions, idle_timeout=0, hard_timeout=0)
    def group_mod(self,dpid,group_id,ip_src=None,ip_dst=None):
        datapath = self.get_datapath(dpid)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if ip_dst and ip_src:
            match = parser.OFPMatch(eth_type=0x0800,ipv4_src=ip_src,ipv4_dst=ip_dst)
        else:
            match=parser.OFPMatch(eth_type=0x0800)
        actions_1 = [parser.OFPActionOutput(1)]
        actions_2 = [parser.OFPActionOutput(2)]
        buckets = [parser.OFPBucket(weight=1, actions=actions_1), parser.OFPBucket(weight=1, actions=actions_2)]
        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_SELECT, group_id, buckets)
        datapath.send_msg(req)
        group_action = [parser.OFPActionGroup(group_id)]
        self.add_flow(dp=datapath, p=1, match=match, actions=group_action, idle_timeout=0, hard_timeout=0)
    def agg_group(self):
        group_id = 1
        for dpid in self.AGG_SW_LIST:
            if dpid in self.dps:
                self.group_mod(dpid=dpid,group_id=group_id,ip_src=None,ip_dst=None)
    def flow_recognizer(self,src_dpid=None,ip_src=None,ip_dst=None):
        #flow_speed {(dpid,ip_src,ip_dst):speed}
        #this func in Packet_In and Request func
        #ele_flows {(ip_src,ip_dst):speed} 大象流的速度
        speed=self.flow_speed[(src_dpid,ip_src,ip_dst)]
        src_dst=(ip_src,ip_dst)
        if speed>= self.bandwidth*0.1 :
            #GFF算法
            if self.get_host_location(ip_src)[0] in self.dps and self.get_host_location(ip_dst)[0] in self.dps:
                self.ele_flows[src_dst]=speed
                GFF_path=self.GFF(ip_src,ip_dst,speed)
                if GFF_path:
                    self.install_ele_path(GFF_path,ip_src,ip_dst)
                else:
                    pass
        else:
            if src_dst in self.ele_flows.keys():#如果该流量是大流转变过来的小流，那么ecmp，并pop该流
                self.group_mod(dpid=src_dpid,group_id=1,ip_src=ip_src,ip_dst=ip_dst)
                self.ele_flows.pop(src_dst)#pop掉
    def GFF(self,ip_src,ip_dst,speed):
        p = {}
        new_p = None
        for key, value in self.monitor_table.items():
            # {(ip_src,ip_dst,tuple(path)):ava_bw}
            if key[0] == ip_src and key[1] == ip_dst:
                p[(key[0], key[1], key[2])] = value
        for c, d in p.items():
            if d>=speed:
                new_p = list(c[2])#首次适应，有的话就直接返回轻负载路径
                break
            else:
                continue
        if new_p==None:
            return None
        else:
            return new_p
    def install_ele_path(self,path,src,dst):
        for index, dpid in enumerate(path[:-1]):
            dp = self.get_datapath(dpid)
            port_no = self.graph[path[index]][path[index + 1]]['src_port']
            match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=src,ipv4_dst=dst)
            actions=[dp.ofproto_parser.OFPActionOutput(port_no)]
            self.add_flow(dp,1,match,actions,5,0)
            self.ele_cost+=1
#==============forward==============
    def shortest_path(self,ip_src,ip_dst,src_dpid,dst_dpid,to_port_no,to_dst_match):
        shortest_paths_original = nx.all_shortest_paths(self.graph, src_dpid, dst_dpid)#get all paths from source to destination
        for path_correct in shortest_paths_original:
            if path_correct[0]== list(self.access_table.keys())[list(self.access_table.values()).index(ip_src)][0]:
                self.monitor_table[ip_src, ip_dst, tuple(path_correct)] = 10# Init monitor_table
        if src_dpid==dst_dpid:
            dp = self.get_datapath(src_dpid)
            actions = [dp.ofproto_parser.OFPActionOutput(to_port_no)]
            self.add_flow(dp, 50, to_dst_match, actions, 0, 0)
            port_no = to_port_no
        else:
            group_id=1
            path = nx.shortest_path(self.graph, src_dpid, dst_dpid)
            self.group_mod(dpid=src_dpid, group_id=group_id, ip_src=ip_src, ip_dst=ip_dst)
            dp = self.get_datapath(dst_dpid)
            actions = [dp.ofproto_parser.OFPActionOutput(to_port_no)]
            self.add_flow(dp, 50, to_dst_match, actions, 0, 0)
            port_no = self.graph[path[0]][path[1]]['src_port']
        return port_no
    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        """
            To calculate shortest forwarding path and install them into datapaths.

        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if result:
            src_sw, dst_sw, to_dst_port = result[0], result[1], result[2]#to_dst_port指的是目的主机与交换机连接的端口
            if dst_sw:
                # Path has already calculated, just get it.
                to_dst_match = parser.OFPMatch(
                    eth_type = eth_type, ipv4_dst = ip_dst)
                #to_src_match=parser.OFPMatch(eth_type=eth_type,ipv4_dst=ip_src)
                port_no = self.shortest_path(ip_src, ip_dst, src_sw, dst_sw, to_dst_port, to_dst_match)
                #self.install_group(self.paths[(ip_src,ip_dst)],ip_src,ip_dst)
                self.send_packet_out(datapath, msg.buffer_id, in_port, port_no, msg.data)
        return
#========install flow==============
    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)
#============Arp==================
    def arp_forwarding(self, msg, src_ip, dst_ip):
        """ Send ARP packet to the destination host,
            if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        result = self.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
        else:
            self.flood(msg)
#==========packetout=============
    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out
    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)
#==========flood================
    def flood(self, msg):
        """
            Flood ARP packet to the access port
            which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.access_ports:
            for port in self.access_ports[dpid]:
                if (dpid, port) not in self.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)

