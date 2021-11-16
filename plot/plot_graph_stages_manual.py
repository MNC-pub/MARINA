import csv
import matplotlib
import matplotlib.pyplot as plt
import numpy as np

a = []

def reduction_ratio(num):
    ratio = (2000-num)/(2000-100)*100
    print(ratio)
    return ratio

for i in range (0,6):
    f = open('/home/mnc/p4-dev/topk/logs/mininet/topk/topk-stage{}-single-2000-z-1000-1.1-2-1.csv'.format(2*i+1), 'r')
    opened_file = f.readlines()
    a.append(int(opened_file[-1].split(',')[1]))

#1000
top1_1000 = a[0]
top3_1000 = a[1]
top5_1000 = a[2]
top7_1000 = a[3]
top9_1000 = a[4]
top11_1000 = a[5]

top1_1000 = reduction_ratio(top1_1000)
top3_1000 = reduction_ratio(top3_1000)
top5_1000 = reduction_ratio(top5_1000)
top7_1000 = reduction_ratio(top7_1000)
top9_1000 = reduction_ratio(top9_1000)
top11_1000 = reduction_ratio(top11_1000)

plt.bar('1', top1_1000, color='white', edgecolor="black", hatch='//////')
plt.bar('3', top3_1000, color='white', edgecolor="black", hatch='//////')
plt.bar('5', top5_1000, color='white', edgecolor="black", hatch='//////')
plt.bar('7', top7_1000, color='white', edgecolor="black", hatch='//////')
plt.bar('9', top9_1000, color='white', edgecolor="black", hatch='//////')
plt.bar('11', top11_1000, color='white', edgecolor="black", hatch='//////')
plt.xlabel('The number of stages')
plt.ylabel('Reduction ratio (%)')
plt.grid(True, axis='y', color='gray', alpha=0.5, linestyle='--',zorder=3)
plt.axis([-0.65, 5.65, 50, 100])

plt.subplots_adjust(left=0.125, bottom=0.1,  right=0.9, top=0.9, wspace=0.2, hspace=0.35)
plt.savefig('graph_stages_2000.png')


