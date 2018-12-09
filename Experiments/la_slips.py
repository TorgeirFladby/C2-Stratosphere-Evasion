import change_pcap_timestamps as cpt
import random
import math
from datetime import datetime
import glob, os, re, subprocess, pickle


niterations = 150

target_tuples = [('10.0.2.107','212.59.117.207'), ('10.0.2.107','91.222.139.45')]

lmba=0.1

N_a = 100
min_a = 0.1
max_a = 1

N_b = 100
min_b = 0.05
max_b = 0.5

A = [min_a+i*1.0*(max_a-min_a) / N_a for i in range(N_a)]
B = [min_b+i*1.0*(max_b-min_b) / N_a for i in range(N_b)]

P_A = [0.5 for i in range(N_a)]
P_B = [0.5 for i in range(N_b)]



def was_feasible():

    list_of_files = glob.glob("/home/ubuntu/StratosphereLinuxIPS/logs/*")
    latest_file = max(list_of_files, os.path.getctime)

    with open(latest_file[0], "r") as f:
        line = f.read()
        if "detected as malicious" in line:
            theline = line
    alert = theline.split("\n")[-1]
    m = re.match(r'\d+', alert)
    det = m.group(0)
    if det == '0':
        return True
    return False

def throughput_function(a, b, iter):
    durations, flows = cpt.measure_offline_duration(target_tuples)

    throughput, data = cpt.redefine_stored_network_flows(target_tuples, [b, a], iter, durations, flows)
    res = cpt.test_binetflow_using_slips()
    data.append(throughput)
    if res == '0':
        print "Successfully tested binetflow using Slips... Checking if result is feasible"
        data.append(True)
    else:
        data.append(False)
    return throughput, was_feasible(), data

def roulette_selection(weights):
    totals = []

    running_total = 0

    for w in weights:
        running_total += w
        totals.append(running_total)

    rnd = (random.random() * running_total)

    for i, total in enumerate(totals):
        if rnd < total:
            return i

def init_la(n_iterations):


    best_throughput_so_far = 0

    best_index_a = 0
    best_index_b = 0

    allData = {}

    filename = "slips_data_" + datetime.now().strftime("%Y_%M_%h_%m_%s") + ".dat"

    for iter in range(n_iterations):
        # Pick index for the value a according to probability vector P_A
        index_a = roulette_selection(P_A)
        # Pick index for the value b according to probability vector P_B
        index_b = roulette_selection(P_B)

        improvement = False
        feasible = True

        current_throughput, feasible, data = throughput_function(A[index_a], B[index_b], iter)

        if current_throughput > best_throughput_so_far and feasible == True:
            print "The throughput was nice, and we were not detected!"
            best_throughput_so_far = current_throughput
            improvement = True
            best_index_a = index_a
            best_index_b = index_b

        for index in range(N_a):
            if index == best_index_a:
                P_A[index] = P_A[index] + lmba*(1-P_A[index])
            else:
                P_A[index] = P_A[index] + lmba*(0-P_A[index])

        for index in range(N_b):
            if index == best_index_b:
                P_B[index] = P_B[index] + lmba*(1-P_B[index])
            else:
                P_B[index] = P_B[index] + lmba*(0-P_B[index])

        if iter % 10 == 0:
            print "---"*10
            print "---"*10
            print "Probablity for choice of A", P_A
            print "Probablity for choice of B", P_B
            print "Best so far", best_throughput_so_far

        allData[iter] = data

    with open(filename, 'wb') as output:
        pickle.dump(allData, output, pickle.HIGHEST_PROTOCOL)

    print "execution finished"
    print "Final Probablity for choice of A", P_A
    print "Final Probablity for choice of B", P_B
    print "---"*10
    print "---"*10
    print "best index of A value ", best_index_a," which corresponds to", A[best_index_a]
    print "best index of B value ", best_index_b," which corresponds to", B[best_index_b]
    print "---"*10
    print "Given these two best values, the Optimal found throughput (max in all iterations so far)", best_throughput_so_far

init_la(niterations)
