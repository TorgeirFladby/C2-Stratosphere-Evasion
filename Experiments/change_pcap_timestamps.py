import time, sys, os, random
from scapy.all import *
from collections import deque
from adaptive_random_search import PerturbationOptimizer
import md5
from spsa_slips import *
from stf.core import dataset
import subprocess, glob


#zbot = rdpcap("/Users/torgeirfladby/Documents/Masteroppgave/netfiles/2014-02-07_capture-win3-edited.pcap")
cridex = rdpcap("/home/ubuntu/SlipsExperiments/trials/2015-03-09_capture-win7-first1k.pcap")
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
        self.src_port = None
        self.dst_port = None
        self.src_port = init_packet.packet[IP].sport
        self.dst_port = init_packet.packet[IP].dport
        self.ToS = None
        self.packets = []
        self.packets.append(init_packet)
        self.td_list = []
        self.td_fractions = []
        self.time_until_next_flow = None
        self.next_flow = None


    def get_duration(self):
        return self.td

    def belongs_in_flow(self, packet):
        return packet[IP].src == self.src_ip and packet[IP].dst == self.dst_ip and packet[IP].sport == self.src_port and packet[IP].dport == self.dst_port

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

    def set_timedeltas(self):
        if len(self.packets) > 1 and self.td != None:
            counter = 0
            for packet in self.packets[1:]:
                self.td_list.append(packet.packet.time - self.packets[counter].packet.time)
                self.td_fractions.append(self.td_list[counter]/self.td)
                counter +=1
    def perturb_duration(self, perturbation):
        """
        We receive a perturbation parameter for this flow.
        Can be positive or negative, but should ultimately affect the time-delta value of this flow.

        1. Decide how to distribute perturbation load over the different packets.
            1.1 time-deltas are computed and the duration is distributed evenly over the different connections.
        2. To perturb the first td, td1 -> td1^p, set timestamp t1 = t1 + (pert*tdp1)
        3. Should also take offline_duration as parameter


        FIX THIS:
        when subtracting duration, we must subtract time from all connections in the flow. figure out a better way to do this.
        """
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
        return pert_seconds

    def incr_timestamps(self, incr, offline_duration):
        default_incr = incr + offline_duration
        prev_time = self.packets[-1].packet.time
        for packet in self.packets:
            packet.packet.time += default_incr

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


perturbator = PerturbationOptimizer()


def parse_pcap_to_deque(packets):
    """
    Ommitting ARP and IPv6.

    We assume that the attacker knows which IPs are malicious.
    """

    flows = deque()

    counter = 0
    prev_flow = None
    for packet in packets[1:]:
        added_to_flow = False
        cur_packet = Packet(packet, counter)
        if IP in packet:
            cur_flow = Flow(cur_packet)
            if len(flows) != 0:
                for flow in flows:
                    if isinstance(flow, Flow):
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
        counter +=1

    for i in flows:
        if isinstance(i, Flow):
            i.set_flow()
            i.set_timedeltas()
    return flows

def measure_offline_duration(target_tuple, flows = None):

    if not flows:
        flows = parse_pcap_to_deque(cridex)


    durations_dict = {}
    for i in target_tuple:
        print i[0]+i[1]
        durations_dict[i[0]+i[1]] = []

    actual_durations_dict = {}

    offline_durations = []
    actual_durations = deque()
    durations = []
    new_flow = True
    for flow in flows:
        if isinstance(flow, Flow):
            for name in target_tuple:
                if(flow.src_ip, flow.dst_ip) == name:
                    if len(durations_dict[str(flow.src_ip + flow.dst_ip)]) == 0:
                        durations_dict[str(flow.src_ip + flow.dst_ip)].append(flow.packets[-1].packet.time)
                    else:
                        durations_dict[str(flow.src_ip + flow.dst_ip)].append(flow.packets[0].packet.time)
                        durations_dict[str(flow.src_ip + flow.dst_ip)].append(flow.packets[-1].packet.time)
                #print offline_durations[-1]


    print durations_dict
    print "LENGTH OF DURATIONS"
    for key in durations_dict:
        print len(durations_dict[key])

    for key in durations_dict:
        actual_durations_dict[key] = deque()

    for key in actual_durations_dict:
        counter = 0
        for i in durations_dict[key][1:]:
            if counter % 2 == 0:
                actual_durations_dict[key].append(i-durations_dict[key][counter])
            counter += 1

    print actual_durations_dict
    return actual_durations_dict, flows


def write_flows_to_pcap_ordered_by_time(flows, outfile):
    tmp_flows_dict = {}

    for flow in flows:
        if isinstance(flow, Flow):
            for i in flow.packets:
                tmp_flows_dict[i.packet.time] = i.packet
        else:
            tmp_flows_dict[flow.packet.time] = flow.packet

    od = collections.OrderedDict(sorted(tmp_flows_dict.items()))
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

    od = collections.OrderedDict(sorted(tmp_flows_dict.items()))
    for k, v in od.iteritems():
        wrpcap("trials/" + outfile, v, append=True)



def redefine_stored_network_flows(target_tuples, evolving_params, iterationNo, durations, flows):

    incr, timestamp, counter = 0, flows[0].packet.time, 0
    outfile = "2015-03-09-1k-modded-TrialNo" + str(iterationNo) + ".pcap"


    total_bytes = 0.0
    total_duration = 0.0
    pert_incr = 0.0
    pert_data = {}

    print "PARAMS:", evolving_params

    print "Altering duration of packets..."

    for flow in flows:
        counter = 0
        original_timestamp = 0
        if not isinstance(flow, Flow):
            original_timestamp = flow.packet.time
        else:
            original_timestamp = flow.packets[-1].packet.time

        timestamp = original_timestamp + incr
        if isinstance(flow, Flow):
            if len(durations) > 0:
                if (flow.src_ip, flow.dst_ip) in target_tuples:
                    negative = True
                    actual_offline = durations[flow.src_ip+flow.dst_ip].pop()
                    pert = run_spsa([flow.get_flow_size(), flow.get_duration(), actual_offline], evolving_params)
                    #omit negative perturbations
                    while negative:
                        pert = run_spsa([flow.get_flow_size(), flow.get_duration(), actual_offline], evolving_params)
                        negative = False
                        for i in pert:
                            if i < 0:
                                negative = True
                    print "pert parameters:", pert
                    total_bytes+=pert[0]
                    total_duration+=pert[1]+pert[2]
                    print total_bytes, total_duration
                    offline_duration = pert[2]
                    # Set increment to be the absolute change in differences of timestamps.
                    incr = flow.incr_timestamps(incr, (offline_duration-actual_offline))
                    # Add to increment the difference after perturbing parameters. Usually has a negative impact on the increment value.
                    pert_incr = flow.perturb_duration(pert[1])
                    incr += pert_incr
                    pert_data[counter] = (pert_incr, offline_duration-actual_offline)
                    if len(durations[flow.src_ip + flow.dst_ip]) == 0:
                        durations[flow.src_ip + flow.dst_ip].appendleft(actual_offline)
                else:
                    flow.incr_timestamps(incr, 0)
            else:
                flow.incr_timestamps(incr, 0)
        else:
            flow.packet.time = timestamp
        print "Original_timestamp: %f \t increment: %f \t timestamp: %f" % (original_timestamp, incr, original_timestamp + incr)



    write_flows_to_pcap_ordered_by_time(flows, outfile)

    # Create binetflow file of the new pcap
    print "Generating binetflow file.."
    current_dataset = dataset.Dataset(iterationNo)
    current_dataset.set_folder("/home/ubuntu/SlipsExperiments/trials/")
    current_dataset.add_file("/home/ubuntu/SlipsExperiments/trials/" + outfile)
    current_dataset.generate_biargus()
    current_dataset.generate_binetflow()
    print "Binetflow file generated."
    print total_bytes, total_duration
    #Total throughput for this modified flow
    return total_bytes/total_duration, [total_bytes, total_duration, incr, pert_data]


def test_binetflow_using_slips():
    list_of_files = glob.glob("trials/*.binetflow")
    latest_file = max(list_of_files, os.path.getctime)
    try:
        return subprocess.call("python /home/ubuntu/StratosphereLinuxIPS/slips.py -f /home/ubuntu/StratosphereLinuxIPS/models/ -d -r /home/ubuntu/SlipsExperiments/" + latest_file[0], shell=True)
    except Exception as e:
        return None



#redefine_networkflows(30, zbot, ['10.0.2.103'], ['8.8.8.8'])

#redefine_stored_network_flows([('10.0.2.107','212.59.117.207'), ('10.0.2.107','91.222.139.45')])


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
