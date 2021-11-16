import csv
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt

xtick_l = [0,1,2,3,4]
xtick_r = ['DAIET','MARINA-S','MARINA-H']

x = np.arange(len(xtick_r))
print(x)

output_total = [53.9436113, 66.509117, 98.0914834]
output_A1 = [98.9890654, 99.9797612, 99.9595224]
output_A2 = [66.3074521, 84.3764189, 99.2848494]
output_A3 = [44.5562355, 55.5003022, 97.3875507]

SMALL_SIZE = 8
MEDIUM_SIZE = 10
BIGGER_SIZE = 12

plt.rc('font', size=BIGGER_SIZE) # controls default text sizes
plt.rc('axes', titlesize=BIGGER_SIZE) # fontsize of the axes title
plt.rc('axes', labelsize=20) # fontsize of the x and y labels
plt.rc('xtick', labelsize=BIGGER_SIZE+5) # fontsize of the tick labels
plt.rc('ytick', labelsize=BIGGER_SIZE+5) # fontsize of the tick labels
plt.rc('legend', fontsize=15) # legend fontsize
plt.rc('figure', titlesize=BIGGER_SIZE) # fontsize of the figure title


plt.rcParams['figure.figsize'] = [12, 12]
plt.bar(x - 0.225, output_total, label='Total', width=0.15,color='tab:blue' , edgecolor='black' , hatch='//')
plt.bar(x - 0.075, output_A1, label='App 1', width=0.15,color='tab:gray' , edgecolor='black' , hatch='-')
plt.bar(x + 0.075, output_A2, label='App 2', width=0.15,color='antiquewhite' , edgecolor='black' , hatch='////')
plt.bar(x + 0.225, output_A3, label='App 3', width=0.15,color='tab:red' , edgecolor='black' , hatch='')
plt.xticks( x, xtick_r)


plt.xlim(-0.5,2.5)
plt.ylim(0,119)
# plt.grid(True, axis='y')
plt.grid(True, axis='y', color='gray', alpha=0.5, linestyle='--')
plt.legend()
plt.ylabel('Reduction ratio (%)')
plt.xlabel('Type of tree')
plt.savefig('graph-fat_tree_final_bar_tri_200sdfsdf00.png')