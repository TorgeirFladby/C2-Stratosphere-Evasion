import time, sys, os, random
from scapy.all import *
from collections import deque
import perturbation_optimizer as po
import md5
from stf.core import dataset

import glob, os, re, subprocess, pickle


#wrpcap("2016-01-12-capture_win7-modified.pcap", newpcap)


class Packet:

    def __init__(self, init_packet, packetNo):
        self.packetNo = packetNo
        self.packet = init_packet

class Flow:
    def __init__(self, init_packet):
        self.t1 = init_packet.packet.time
        self.t2 = None
        self.td = None

        self.length = len(init_packet.packet)

        self.src_ip = init_packet.packet[IP].src
        self.dst_ip = init_packet.packet[IP].dst
        self.src_port = init_packet.packet[IP].sport
        self.dst_port = init_packet.packet[IP].dport
        self.ToS = None
        self.packets = []
        self.packets.append(init_packet)
        self.td_list = []
        self.td_fractions = []
        self.time_until_next_flow = 0
        self.next_flow = None


    def get_duration(self):
        return self.td

    def belongs_in_flow(self, packet):
        return (packet[IP].src == self.src_ip and packet[IP].dst == self.dst_ip and packet[IP].dport == self.dst_port and packet[IP].sport == self.src_port) or (packet[IP].dst == self.src_ip and packet[IP].src == self.dst_ip and packet[IP].sport == self.dst_port)

    def add_to_flow(self, packet):
        self.packets.append(packet)
        self.length += len(packet.packet)

    def add_to_flow_not_IP(self, packet):
        self.packets.append(packet)
        self.length += len(packet.packet)

    def set_flow(self):
        self.t1 = self.packets[0].packet.time
        self.t2 = self.packets[-1].packet.time
        self.td = self.t2 - self.t1

    def same_ips(self, flow):
        return ((self.src_ip == flow.src_ip) and (self.dst_ip == flow.dst_ip))

    def set_timedeltas(self):
        if len(self.packets) > 1 and self.td != None:
            counter = 0
            for packet in self.packets[1:]:
                self.td_list.append(packet.packet.time - self.packets[counter].packet.time)
                frac = self.td_list[counter]/self.td
                self.td_fractions.append(frac)
                counter +=1
        else:
            self.td = 0
            self.td_list.append(0)
            self.td_fractions.append(1)

    def perturb_duration(self, perturbation):

        if len(self.packets) == 1 or perturbation == 0:
            return 0

        counter = 1
        pert_sum = 0

        old = self.t2
        pert_seconds = perturbation - self.td
        print "Pert seconds:", pert_seconds
        print "Perturbation:", perturbation
        print "Self.td: ", self.td
        for td_f in self.td_fractions:
            print td_f
            pert = pert_seconds * td_f
            print "Pert:", pert
            pert_sum += pert
            print "Pert sum: ", pert_sum
            if len(self.td_fractions) == counter:
                self.packets[counter].packet.time += pert_seconds
            else:
                self.packets[counter].packet.time += pert_sum
            counter +=1

        print "Old duration:\t", self.td
        self.set_flow()
        print "New duration:\t", self.td
        return self.packets[-1].packet.time

    def incr_timestamps(self, pert_td_next):
        prev_time = self.packets[-1].packet.time
        for packet in self.packets:
            packet.packet.time += pert_td_next

        print "The last packet in this flow was changed from time: %f to %f" % (prev_time, self.packets[-1].packet.time)
        self.set_flow()
        return self.packets[-1].packet.time - prev_time


    def scew_flow_by(self, seconds):
        for packet in self.packets:
            packet.packet.time += seconds
        self.set_flow()

    def get_flow_size(self):
        return self.length

    def __str__(self):
        return str(self.src_ip) + "\t" + str(self.src_port) + "\t" + str(self.dst_ip) + "\t" +  str(self.dst_port)

def parse_pcap_to_deque(target_tuples, packets):
    """
    Ommitting ARP and IPv6.

    We assume that the attacker knows which IPs are malicious.
    """

    flows = deque()

    counter = 0
    prev_flow = None
    print "Parsing scapy packet set..."
    for packet in packets[1:]:
        print "Parsing packet number: \t", counter
        added_to_flow = False
        cur_packet = Packet(packet, counter)
        if IP in packet:
            if ((packet[IP].src, packet[IP].dst) or (packet[IP].dst, packet[IP].src)) in target_tuples:
                cur_flow = Flow(cur_packet)
                if len(flows) != 0:
                    for flow in flows:
                        if isinstance(flow, Flow) and not added_to_flow:
                            if flow.belongs_in_flow(packet):
                                flow.add_to_flow(cur_packet)
                                added_to_flow = True
                                break
                    if not added_to_flow:
                        flows.append(cur_flow)
                else:
                    flows.append(cur_flow)
            else:
                flows.append(cur_packet)
        else:
            flows.append(cur_packet)
        counter +=1
    print "Added packet set to flows."
    print "Setting flow parameters..."
    for i in flows:
        if isinstance(i, Flow):
            i.set_flow()
            i.set_timedeltas()
    return flows

def get_timedelta_next_flow_in(deque, index, tuple, cur_flow):

    found = False
    counter = 1
    while not found:
        if index + counter >= len(deque):
            return None, 0
        next_flow = deque[index+counter]
        if isinstance(next_flow, Flow):
            if next_flow.src_ip == tuple[0] and next_flow.dst_ip == tuple[1] and (next_flow not in cur_flow.packets and next_flow.packets[0].packet.time > cur_flow.packets[0].packet.time):
                found = True
                return next_flow, next_flow.packets[0].packet.time - cur_flow.packets[0].packet.time
        elif isinstance(next_flow, Packet):
            if (next_flow.packet.src == tuple[0] and next_flow.packet.dst == tuple[1]) and (next_flow not in cur_flow.packets and next_flow.packet.time > cur_flow.packets[0].packet.time):
                found = True
                return next_flow, next_flow.packet.time - cur_flow.packets[0].packet.time
        counter += 1
    return None, 0


def measure_time_between_flows(target_tuple, malware):

    flows = parse_pcap_to_deque(target_tuple, malware)

    counter = 0
    for flow in flows:
        if isinstance(flow, Flow):
            if(flow.src_ip, flow.dst_ip) in target_tuple:
                flow.next_flow, flow.time_until_next_flow = get_timedelta_next_flow_in(flows, counter, (flow.src_ip, flow.dst_ip), flow)
                counter +=1
    return flows


def write_flows_to_pcap_ordered_by_time(flows, outfile):
    tmp_flows_dict = {}

    for flow in flows:
        if isinstance(flow, Flow):
            for i in flow.packets:
                tmp_flows_dict[i.packet.time] = i.packet
        else:
            tmp_flows_dict[flow.packet.time] = flow.packet

    print "Finished indexing Packets. Sorting Packets and Flows..."
    od = collections.OrderedDict(sorted(tmp_flows_dict.items()))
    print "Finished sorting Packets and Flows. Writing pcap..."
    for k, v in od.iteritems():
        wrpcap("trials/" + outfile, v, append=True)


def write_flows_to_pcap_ordered_by_number(flows, outfile):
    tmp_flows_dict = {}

    for flow in flows:
        if isinstance(flow, Flow):
            for i in flow.packets:
                tmp_flows_dict[i.packetNo] = i.packet
        else:
            tmp_flows_dict[flow.packetNo] = flow.packet

    print "Finished indexing Packets. Sorting Packets and Flows..."
    od = collections.OrderedDict(sorted(tmp_flows_dict.items()))
    print "Finished sorting Packets and Flows. Writing pcap..."
    for k, v in od.iteritems():
        wrpcap("trials/" + outfile, v, append=True)



def redefine_stored_network_flows(target_tuples, evolving_params, iterationNo, flows):
    outfile = "2015-03-09_capture-win7-first1k-" + str(iterationNo) + ".pcap"

    total_bytes = 0.0
    total_duration = 0.0
    total_duration_perturbation = 0.0
    pert_incr = 0
    pert_data = {}

    optimizer = po.PerturbationOptimizer()

    print "Altering duration of packets..."
    counter = 0
    for flow in flows:
        original_timestamp = 0
        if not isinstance(flow, Flow):
            original_timestamp = flow.packet.time
        else:
            original_timestamp = flow.packets[-1].packet.time
        if isinstance(flow, Flow):
            if (flow.src_ip, flow.dst_ip) in target_tuples:
                positive = True
                td_next = flow.time_until_next_flow
                pre_pert_tu = flow.time_until_next_flow
                pre_pert_td = flow.td
                pre_perturbation = flow.packets[-1].packet.time
                total_loss = 0
                print "Flow length: %f \t Flow duration: %f \t Time until next flow: %f" % (flow.length, flow.td, td_next)
                pert, loss = po.run_spsa([flow.length, flow.td, td_next], beta_vector=evolving_params)
                #omit negative perturbations
                positive = all( i >= 0 for i in pert)
                while not positive:
                    pert, loss = po.run_spsa([flow.length, flow.td, td_next], beta_vector=evolving_params)
                    pert_incr += 1
                    positive = all( i >= 0 for i in pert )
                print "Perturbation parameters (pert, loss): [%f, %f, %f] \t %f" % (pert[0], pert[1], pert[2], loss)
                total_bytes+=pert[0]
                total_duration_perturbation+=(pert[1]-flow.td)+(pert[2]-td_next)
                pert_td_next = pert[2]
                pert_td = pert[2]
                flow_incr = 0
                if len(flow.packets) > 1:
                    # We may perturb duration
                    if flow.next_flow != None:
                        flow_incr = flow.next_flow.incr_timestamps(pert_td-td_next)
                        total_duration += flow_incr
                    new_timestamp = flow.perturb_duration(pert[1])
                    pert_data[counter] = [counter, pert_td_next-td_next, pre_perturbation, new_timestamp, flow_incr, pert, [flow.length, pre_pert_td, pre_pert_tu]]
                    total_duration += flow.td
                else:
                    # We may not pertub duration, only time_until_next_flow and optionally byte size
                    if flow.next_flow != None:
                        flow_incr = flow.next_flow.incr_timestamps(pert_td-td_next)
                        total_duration += flow_incr
                        total_loss += loss
                    new_timestamp = pre_perturbation
                    pert_data[counter] = [counter, pert_td_next-td_next, pre_perturbation, new_timestamp, flow_incr, pert, [flow.length, pre_pert_td, pre_pert_tu]]
                cur_packet = flow.packets[-1]
                counter += 1
            else:
                cur_packet = flow.packets[-1]
                pert_data[counter] = [counter, 0, cur_packet.packet.time, cur_packet.packet.time, cur_packet.packet.time, [0,0,0], [0, 0, 0]]
                counter += 1
        else:
            cur_packet = flow
            pert_data[counter] = [counter, 0, cur_packet.packet.time, cur_packet.packet.time, cur_packet.packet.time, [0,0,0], [0, 0, 0]]
            counter += 1
        print "Original_timestamp: %f \t timestamp: %f \t packet number: %d" % (original_timestamp, cur_packet.packet.time, cur_packet.packetNo)



    write_flows_to_pcap_ordered_by_time(flows, outfile)

    # Create binetflow file of the new pcap
    print "Generating binetflow file.."
    current_datasets = dataset.Datasets()
    current_datasets.create("/home/ubuntu/SlipsExperiments/trials/" + outfile)
    current_datasets.generate_argus_files()
    #current_dataset.set_folder("/home/ubuntu/SlipsExperiments/trials/")
    #current_dataset.add_file("/home/ubuntu/SlipsExperiments/trials/" + outfile)
    #current_dataset.generate_biargus()
    #current_dataset.generate_binetflow()
    print "Binetflow file generated."

    throughput = 0.1
    if total_bytes > 0 and total_duration > 0:
        throughput = total_bytes/(total_duration)
    print total_bytes, total_duration
    #Total throughput for the modified flows
    return throughput, [total_bytes, total_duration_perturbation, total_duration, pert_data, evolving_params], total_loss


def test_binetflow_using_slips():
    list_of_files = glob.glob("trials/*.binetflow")
    latest_file = max(list_of_files, os.path.getctime)
    try:
        return subprocess.call("python /home/ubuntu/StratosphereLinuxIPS/slips.py -f /home/ubuntu/StratosphereLinuxIPS/models/ -d -r /home/ubuntu/SlipsExperiments/" + latest_file[0], shell=True)
    except Exception as e:
        return None

def was_feasible():

    list_of_files = glob.glob("/home/ubuntu/SlipsExperiments/logs/*")
    latest_file = max(list_of_files, os.path.getctime)

    with open(latest_file[0], "r") as f:
        line = f.read()
        if "detected as malicious" in line:
            theline = line
    alert = theline.split("\n")[-1]
    m = re.match(r'\d+', alert)
    det = m.group(0)
    print det
    if det == '0':
        return True
    return False

"""
Using original binetflow file, Slips gives the following output for malicious DNS connections:
    DstIP: 8.8.8.8,
    Label: From-Botnet-UDP-DNS-DGA-17 ,
    Detection Time: 1970-01-01 01:34:18.872789,
    State(100 max): 44.R+R.U.u.a.a.d.a.d.a.a.d.d.a.d.a.a.a.d.a.a.a.a.a.a.a.d.d.a.a.a.a.a.a.a.a.a.a.d.d.a.a.d.a.d.a.a.d.d

Using the binetflow file with modified duration parameters, Slips gives the following output for malicious DNS connections:
    DstIP: 8.8.8.8,
    Label: 0 ,
    Detection Time: 1970-01-01 06:01:46.305854,
    State(100 max): 55,S+S,v,v.s,B,e,s.v,B,B,E,v.B,v.B,s,b,E,B,s,s,s,s,s,B,v,E,s,s,B,s.b.B.s,s,s,s,E,v,s,B,v,B.v,b,s,E,v

    Sjekk ut: Simultaenous perturbation stoachastic approximation


Regarding padding of DNS packets:
    -> Is there a point in adding payload to DNS packets? isn't DNS used just for issuing botnet commands, rather than extracting data?
    -> DNS is only used for looking up domains through DGAs that lookup domains. The domain may contain commands that should be executed.
    -> For that reason, there is no point in padding packets that use DNS for C2 communication.

    -> Padding of packets should be used when there is a TCP connection with a C2 server. Check out the datasets and see if there is traffic that contain TCP traffic.
    -> It is, however, interesting to look at whether perturbation to connection duration, flow duration and offline duration causes DNS traffic to be rendered undetected.

Reviewing the current implementation of the pcap-parser:
- Network flows cannot be defined by a time window.
- Rather, let's define it as requests from a particular source port on a particular source IP to a corresponding IP/port.

Cisco standard NetFlow version 5 defines a flow as a unidirectional sequence of packets that all share the following 7 values:[2]

Ingress interface (SNMP ifIndex)
Source IP address
Destination IP address
IP protocol
Source port for UDP or TCP, 0 for other protocols
Destination port for UDP or TCP, type and code for ICMP, or 0 for other protocols
IP Type of Service

"""
