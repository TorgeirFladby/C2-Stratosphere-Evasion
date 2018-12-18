import pandas as pd
import pickle
import numpy as np
import matplotlib.pyplot as plt

df1 = pd.read_pickle("data/slips_data_2_2018_01_Dec_12_1544929318.dat")
df2 = pd.read_pickle("data/slips_data_2_2018_10_Dec_12_1544929848.dat")
df3 = pd.read_pickle("data/slips_data_2_2018_15_Dec_12_1544930139.dat")
df4 = pd.read_pickle("data/slips_data_2_2018_55_Dec_12_1544928900.dat")

durations = np.array([0, 0])

for i in df2["pert_data"]:
    for k, v in i.iteritems():
        if v[5] != [0, 0, 0]:
            np.vstack((durations, np.array([v[0], v[1]])))

durframe = pd.DataFrame(durations, columns=['Timestamp', 'Perturbation (Seconds)'])

ax1 = durframe.plot.scatter(x='Timestamp', y='Perturbation (Seconds)')
