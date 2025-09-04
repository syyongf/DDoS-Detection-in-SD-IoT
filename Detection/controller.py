from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub
import numpy as np
from ml_model import classifier
import pandas as pd

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # Switch related variables
        self.mac_to_port = {}
        
        # Stats collection related variables
        self.datapaths = {}
        self.lookup_count = 0
        self.src_ip_list = set()
        self.dst_ip_list = set()
        self.src_port_list = set()
        self.previous_stats = {
            "packet_count": 0,
            "lookup_count": 0,
            "pair_count": 0,
            "flow_count": 0
        }
        self.classifier_model = classifier()
        self.mitigation = 0
        
        # Start monitoring thread
        self.monitor_thread = hub.spawn(self.monitor)

    # Stats Collection and Monitoring
    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(5)

    def _get_priority_flows(self, body):
        """Helper function to get priority 1 flows in sorted order"""
        return sorted(
            [flow for flow in body if flow.priority == 1],
            key=lambda flow: (
                flow.match['eth_type'],
                flow.match['ipv4_src'],
                flow.match['ipv4_dst'],
                flow.match['ip_proto']
            )
        )

    def get_src_ip_count(self, body):
        """Calculate number of unique source IPs"""
        return len({
            flow.match['ipv4_src'] 
            for flow in self._get_priority_flows(body)
        })

    def get_src_port_count(self, body):
        """Calculate number of unique source ports"""
        ports = set()
        for flow in self._get_priority_flows(body):
            proto = flow.match['ip_proto']
            if proto == 1:  # ICMP
                ports.add(flow.match['icmpv4_code'])
            elif proto == 6:  # TCP
                ports.add(flow.match['tcp_src'])
            elif proto == 17:  # UDP
                ports.add(flow.match['udp_src'])
        return len(ports)

    def get_pair_count_ratio(self, body):
        """Calculate pair count ratio based on source-destination IP pairs"""
        priority_flows = self._get_priority_flows(body)
        src_ips = {flow.match['ipv4_src'] for flow in priority_flows}
        dst_ips = {flow.match['ipv4_dst'] for flow in priority_flows}
        
        pair_count = len(src_ips.intersection(dst_ips))
        flow_count_diff = abs(len(priority_flows) - self.previous_stats["flow_count"])
        pair_count_diff = abs(pair_count - self.previous_stats["pair_count"])
        
        return (
            pair_count_diff / flow_count_diff if flow_count_diff > 0 else 0,
            pair_count
        )

    def get_packet_count_diff(self, body):
        """Calculate packet count difference and current packet count"""
        current_packet_count = sum(
            flow.packet_count 
            for flow in self._get_priority_flows(body)
        )
        return (
            abs(current_packet_count - self.previous_stats["packet_count"]),
            current_packet_count
        )

    def get_lookup_count_diff(self):
        """Calculate lookup count difference"""
        return abs(self.lookup_count - self.previous_stats["lookup_count"])

    def get_average_packet_count(self, body):
        """Calculate average packet count per flow"""
        priority_flows = self._get_priority_flows(body)
        if not priority_flows:
            return 0
        
        total_packets = sum(flow.packet_count for flow in priority_flows)
        return total_packets / len(priority_flows)

    def get_average_byte_count(self, body):
        """Calculate average byte count per flow"""
        priority_flows = self._get_priority_flows(body)
        if not priority_flows:
            return 0
        
        total_bytes = sum(flow.byte_count for flow in priority_flows)
        return total_bytes / len(priority_flows)

    def get_packet_std_dev(self, body):
        """Calculate standard deviation for packets"""
        priority_flows = self._get_priority_flows(body)
        if not priority_flows:
            return 0
            
        packets = [flow.packet_count for flow in priority_flows]
        return np.std(packets)

    def get_byte_std_dev(self, body):
        """Calculate standard deviation for bytes"""
        priority_flows = self._get_priority_flows(body)
        if not priority_flows:
            return 0
            
        bytes_ = [flow.byte_count for flow in priority_flows]
        return np.std(bytes_)

    def get_duration_per_flow(self, body):
        """Calculate average duration per flow"""
        priority_flows = self._get_priority_flows(body)
        if not priority_flows:
            return 0
            
        total_duration = sum(
            flow.duration_sec + flow.duration_nsec/1e9 
            for flow in priority_flows
        )
        return total_duration / len(priority_flows)

    def get_protocol(self, body):
        """Get protocol from the first priority flow"""
        priority_flows = self._get_priority_flows(body)
        return priority_flows[0].match['ip_proto'] if priority_flows else 0

    # Switch Features and Flow Management
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  idle_timeout=idle, hard_timeout=hard,
                                  priority=priority, match=match,
                                  instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  idle_timeout=idle, hard_timeout=hard,
                                  match=match, instructions=inst)
        datapath.send_msg(mod)

    # Block flow
    def block_flow(self, datapath, portnumber, dstip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=portnumber, ipv4_dst=dstip)
        actions = []

        self.add_flow(datapath, 100, match, actions, idle=20, hard=100)
        self.mitigation = 0

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                            ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                if protocol == in_proto.IPPROTO_ICMP:
                    t = pkt.get_protocol(icmp.icmp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_src=srcip, ipv4_dst=dstip,
                                          ip_proto=protocol,icmpv4_code=t.code,
                                          icmpv4_type=t.type)

                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_src=srcip, ipv4_dst=dstip,
                                          ip_proto=protocol,
                                          tcp_src=t.src_port, tcp_dst=t.dst_port,)

                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_src=srcip, ipv4_dst=dstip,
                                          ip_proto=protocol,
                                          udp_src=u.src_port, udp_dst=u.dst_port,)

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=20, hard=100)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle=20, hard=100)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]



    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req_flow = parser.OFPFlowStatsRequest(datapath)
        req_table = parser.OFPTableStatsRequest(datapath)
        datapath.send_msg(req_flow)
        datapath.send_msg(req_table)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        # Get source IP count first as it's our validity check
        src_ip_count = self.get_src_ip_count(body)
        if src_ip_count == 0:
            return
        pair_count_ratio = self.get_pair_count_ratio(body)[0]
        packet_count_diff = self.get_packet_count_diff(body)[0]

        # Define headers and get corresponding values
        features = {
            'Count_of_Source_IP': src_ip_count,
            'Port_Count': self.get_src_port_count(body),
            'Pair_Count_Ratio': pair_count_ratio,  # Get ratio only
            'Packet_Count_Diff': packet_count_diff,  # Get diff only
            'Lookup_Count_Diff': self.get_lookup_count_diff(),
            'Protocol': self.get_protocol(body),
            'Average_Packet_Count': self.get_average_packet_count(body),
            'Average_Byte_Count': self.get_average_byte_count(body),
            'Packet_Std_Dev': self.get_packet_std_dev(body),
            'Byte_Std_Dev': self.get_byte_std_dev(body),
            'Duration_per_Flow': self.get_duration_per_flow(body)
        }

        # Create DataFrame from features dictionary
        data = pd.DataFrame([features])
        prediction = self.classifier_model.predict(data)
        
        if prediction == 1:
            # attack detected and mitigation is active
            print("Attack detected and mitigation is active")
            self.mitigation = 1
        else:
            # normal traffic
            print("Normal traffic")

        # Update previous stats
        self.previous_stats.update({
            "packet_count": self.get_packet_count_diff(body)[1],  # Get current packet count
            "lookup_count": self.lookup_count,
            "pair_count": self.get_pair_count_ratio(body)[1],  # Get current pair count
            "flow_count": len(self._get_priority_flows(body))
        })

    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def _table_stats_reply_handler(self, ev):
        body = ev.msg.body
        total_lookup_count = sum(stats.lookup_count for stats in body)
        if len(body) > 1:
            self.lookup_count = total_lookup_count