import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime
import numpy as np

class CollectTrainingStatsApp(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
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
        self.monitor_thread = hub.spawn(self.monitor)

        with open("traffic_log.csv","w") as file:
            file.write('Count of Source IP,Port Count,Flow Count,Packet Count,Lookup Count,Pair Count,Protocol\n')
        with open("values.csv","w") as file:
            file.write('Count of Source IP,Port Count,Pair Count Ratio,Packet Count Diff,Lookup Count Diff,Protocol,Average Packet Count,Average Byte Count,Packet Std Dev,Byte Std Dev,Duration per Flow,Label\n')

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


    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(5)


    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)

        parser = datapath.ofproto_parser

        req_flow = parser.OFPFlowStatsRequest(datapath)
        req_table = parser.OFPTableStatsRequest(datapath)
        datapath.send_msg(req_flow)
        datapath.send_msg(req_table)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        packet_count = 0
        byte_count = 0
        src_port = 0
        ip_proto = 0
        duration = 0
        body = ev.msg.body
        flow_count = len(body)
        flow_packets = []
        flow_bytes = []

        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):

            packet_count += stat.packet_count
            byte_count += stat.byte_count
            duration += (stat.duration_sec + stat.duration_nsec / 1000000000)
            ip_proto = stat.match['ip_proto']
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            
            if stat.match['ip_proto'] == 1:
                src_port = stat.match['icmpv4_code']

            elif stat.match['ip_proto'] == 6:
                src_port = stat.match['tcp_src']

            elif stat.match['ip_proto'] == 17:
                src_port = stat.match['udp_src']

            self.src_ip_list.add(ip_src)
            self.dst_ip_list.add(ip_dst)
            self.src_port_list.add(src_port)
            flow_packets.append(stat.packet_count)
            flow_bytes.append(stat.byte_count)
        src_ip_count = len(self.src_ip_list)
        src_port_count = len(self.src_port_list)
        pair_count = len(self.src_ip_list.intersection(self.dst_ip_list))

        average_packet_count = packet_count / flow_count
        average_byte_count = byte_count / flow_count
        packet_count_diff = abs(packet_count - self.previous_stats["packet_count"])
        lookup_count_diff = abs(self.lookup_count - self.previous_stats["lookup_count"])
        pair_count_diff = abs(pair_count - self.previous_stats["pair_count"])
        flow_count_diff = abs(flow_count - self.previous_stats["flow_count"])
        dur_per_flow = duration / flow_count if flow_count > 0 else 0
        pair_count_ratio = pair_count_diff / flow_count_diff if flow_count_diff > 0 else 0
        packet_std_dev = np.std(flow_packets) if flow_packets else 0
        byte_std_dev = np.std(flow_bytes) if flow_bytes else 0

        self.previous_stats["packet_count"] = packet_count
        self.previous_stats["lookup_count"] = self.lookup_count
        self.previous_stats["pair_count"] = pair_count
        self.previous_stats["flow_count"] = flow_count

        if src_ip_count == 0:
            return
        else:
            # Read current traffic label
            try:
                with open("traffic_label.txt", "r") as f:
                    label = int(f.read().strip())
            except:
                # Default to normal traffic if file doesn't exist
                label = 0

            with open("traffic_log.csv","a+") as file:
                file.write("{},{},{},{},{},{},{}\n"
                    .format(src_ip_count, src_port_count, flow_count, packet_count, self.lookup_count, pair_count, ip_proto))

            with open("values.csv","a+") as file: 
                file.write("{},{},{},{},{},{},{},{},{},{},{},{}\n"
                    .format(src_ip_count, src_port_count, pair_count_ratio, packet_count_diff, lookup_count_diff, ip_proto, average_packet_count, average_byte_count, packet_std_dev, byte_std_dev, dur_per_flow, label))

        self.src_ip_list.clear()
        self.dst_ip_list.clear()
        self.src_port_list.clear()
        self.lookup_count = 0


    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def _table_stats_reply_handler(self, ev):
        body = ev.msg.body
        total_lookup_count = 0

        for stats in body:
            total_lookup_count += stats.lookup_count
        
        if len(body) >1:
            self.lookup_count = total_lookup_count
    
