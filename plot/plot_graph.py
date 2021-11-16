import csv
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt




# t = 'daiet'

result_daiet = {}
output_daiet = []
result_topk = {}
output_topk = []

result_topk11 = {}
output_topk11 = []
result_topk12 = {}
output_topk12 = []
result_topk13 = {}
output_topk13 = []

result_daiet2  = {}
result_topk2  = {}
output_daiet2  = []
output_topk2  = []

result_daiet3  = {}
result_topk3  = {}
output_daiet3  = []
output_topk3  = []

xtick_l = []
xtick_r = []
k = -1

## Parameters
p = '1.1'
p2 = '2'
num = 15000
num_exp = 1

for entry in [500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 4500, 5000, 5500, 6000, 6500, 7000, 7500, 8000]:
# for entry in [1000,2000,3000,4000,5000,6000,7000,8000,9000,10000,11000,12000,13000,14000,15000]: #,5000]: # FIXME : modify just this line
#for entry in [1000,2000,3000,4000,5000,6000,7000,8000,9000,10000,11000,12000,13000,14000,15000]: #,5000]: # FIXME : modify just this line

    k = k + 1
    result_daiet[ str(entry) ] = []
    result_topk[ str(entry) ] = []
    result_daiet2[ str(entry) ] = []
    result_topk2[ str(entry) ] = []
    result_daiet3[ str(entry) ] = []
    result_topk3[ str(entry) ] = []

    result_topk11[ str(entry) ] = []
    result_topk12[ str(entry) ] = []
    result_topk13[ str(entry) ] = []

    for i in range (1,num_exp+1):
        dist = 'z'
        t = 'topk'
        f = open('/home/mnc/p4-dev/topk/logs/mininet/daiet/daiet-fat_tree_reg1500-{}-{}-{}-{}-{}.csv'.format(dist,p,num,entry,i), 'r') #daiet-fat_tree-z-1.1-1000-5000-1
        opened_file = f.readlines()
        a = opened_file[-1].split(',')[1]
        b = float(opened_file[-1].split(',')[3]) /10
        print(a)
        print(b)
        print((1-float(a)/(float(b)-entry/10))*100)
        # result_daiet[str(entry)].append(1-int(a)/(12*num))
        
        result_daiet[str(entry)].append((1-float(a)/(float(b)-entry/10))*100)
        f.close()

        # f = open('/home/mnc/p4-dev/topk/logs/mininet/daiet/daiet-fat_tree-{}-{}-{}-{}-{}.csv'.format(dist,p2,num,entry,i), 'r')
        # opened_file = f.readlines()
        # a = opened_file[-1].split(',')[1]
        # result_daiet2[str(entry)].append(1-int(a)/(12*num))
        
        # f.close()

        # dist = 'u'
        # f = open('/home/mnc/p4-dev/topk/logs/mininet/daiet/{}-{}-{}-{}.csv'.format(t,num,i,dist), 'r')
        # opened_file = f.readlines()
        # a = opened_file[-1].split(',')[1]
        # result_daiet3[str(entry)].append(1-int(a)/(12*num))
        
        # f.close()
############
    for i in range (1,num_exp+1): 
        dist = 'z'
        t = 'topk'
        f = open('/home/mnc/p4-dev/topk/logs/mininet/topk/topk-fat_tree_reg1500-{}-{}-{}-{}-{}.csv'.format(dist,p,num,entry,i), 'r') #topk-fat_tree-z-1.1-1000-1000-1
        opened_file = f.readlines()
        a = opened_file[-1].split(',')[1]
        b = float(opened_file[-1].split(',')[3]) / 10
        print(a)
        print(b)
        print((1-float(a)/(float(b)-entry/10))*100)
        # result_topk[str(entry)].append(1-int(a)/(12*num))
        result_topk[str(entry)].append((1-float(a)/(float(b)-entry/10))*100)
        f.close()

    # for i in range (1,num_exp+1):
    #     dist = 'z'
    #     t = 'topk'
    #     f = open('/home/mnc/p4-dev/topk/logs/mininet/topk/count1/topk-fat_tree-{}-{}-{}-{}-{}.csv'.format(dist,p,num,entry,i), 'r') #topk-fat_tree-z-1.1-1000-1000-1
    #     opened_file = f.readlines()
    #     a = opened_file[-1].split(',')[1]
    #     result_topk11[str(entry)].append(1-int(a)/(12*num))
    #     f.close()

    # for i in range (1,num_exp+1):
    #     dist = 'z'
    #     t = 'topk'
    #     f = open('/home/mnc/p4-dev/topk/logs/mininet/topk/count5/topk-fat_tree-{}-{}-{}-{}-{}.csv'.format(dist,p,num,entry,i), 'r') #topk-fat_tree-z-1.1-1000-1000-1
    #     opened_file = f.readlines()
    #     a = opened_file[-1].split(',')[1]
    #     result_topk12[str(entry)].append(1-int(a)/(12*num))
    #     f.close()
        
    # for i in range (1,num_exp+1):
    #     dist = 'z'
    #     t = 'topk'
    #     f = open('/home/mnc/p4-dev/topk/logs/mininet/topk/count10/topk-fat_tree-{}-{}-{}-{}-{}.csv'.format(dist,p,num,entry,i), 'r') #topk-fat_tree-z-1.1-1000-1000-1
    #     opened_file = f.readlines()
    #     a = opened_file[-1].split(',')[1]
    #     result_topk13[str(entry)].append(1-int(a)/(12*num))
    #     f.close()

        # f = open('/home/mnc/p4-dev/topk/logs/mininet/topk/topk-fat_tree-{}-{}-{}-{}-{}.csv'.format(dist,p2,num,entry,i), 'r')
        # opened_file = f.readlines()
        # a = opened_file[-1].split(',')[1]
        # result_topk2[str(entry)].append(1-int(a)/(12*num))
        # f.close()

        # dist = 'u'
        # f = open('/home/mnc/p4-dev/topk/logs/mininet/topk/{}-{}-{}-{}.csv'.format(t,num,i,dist), 'r')
        # opened_file = f.readlines()
        # a = opened_file[-1].split(',')[1]
        # result_topk3[str(entry)].append(1-int(a)/(12*num))
        # f.close()

    output_daiet.append(result_daiet[str(entry)])
    output_topk.append(result_topk[str(entry)])
    # output_daiet2.append(result_daiet2[str(entry)])
    # output_topk2.append(result_topk2[str(entry)])
    # output_daiet3.append(result_daiet3[str(entry)])
    # output_topk3.append(result_topk3[str(entry)])
    # output_topk11.append(result_topk11[str(entry)])
    # output_topk12.append(result_topk12[str(entry)])
    # output_topk13.append(result_topk13[str(entry)])

    xtick_l.append(k)
    print(xtick_l)
    xtick_r.append(str(entry))
    print(xtick_r)

print(output_daiet)
print(output_topk)
ouput_marina_dh = [[91.2060302], [82.979798], [75.3299492], [68.8265306], [64.4615385], [58.7628866], 
[55.9067358], [52.1875], [48.7434555], [44.9473684], [42.3280423], 
[39.5744681], [37.3262032], [34.9462366], [34.2702703], [32.173913]]

# # print(output_daiet2)
# # print(output_topk2)

# # plt.boxplot( output_daiet, 0, '',patch_artist=True)
# # plt.boxplot( output_topk, 0, '',patch_artist=True)
# plt.rcParams['figure.figsize'] = [10, 7.5]
# plt.plot( output_daiet, label='DAIET (zipf, a= 1.1)', marker=".")
# plt.plot( output_topk, label='AggHDR (zipf, a= 1.1)', marker="." )
# # plt.plot( output_daiet2, label='DAIET (zipf: 2.0)', marker=".")
# # plt.plot( output_topk2, label='AggHDR (zipf: 2.0)', marker="." )
# # plt.plot( output_daiet3, label='DAIET (uniform)', marker=".")
# # plt.plot( output_topk3, label='AggHDR (uniform)', marker="." )
# # plt.plot( output_topk11, label='AggHDR (count = 1)', marker="." )
# # plt.plot( output_topk12, label='AggHDR (count = 5)', marker="." )
# # plt.plot( output_topk13, label='AggHDR (count = 10)', marker="." )



# plt.legend()

# plt.ylabel('Reduction ratio')
# plt.xlabel('The number of entry types (fat-tree)')
# # plt.xticks([1, 2, 3], ['10', '100', '500'])
# plt.xticks( xtick_l , xtick_r )
# plt.yticks(np.arange(0.5,1.05,0.1))
# # plt.savefig('%s.png' %t)
# plt.savefig('graph-fat_tree_vareg_{}.png'.format(num))

SMALL_SIZE = 8
MEDIUM_SIZE = 10
BIGGER_SIZE = 12

plt.rc('font', size=BIGGER_SIZE) # controls default text sizes
plt.rc('axes', titlesize=BIGGER_SIZE) # fontsize of the axes title
plt.rc('axes', labelsize=16) # fontsize of the x and y labels
plt.rc('xtick', labelsize=BIGGER_SIZE) # fontsize of the tick labels
plt.rc('ytick', labelsize=BIGGER_SIZE) # fontsize of the tick labels
plt.rc('legend', fontsize=18) # legend fontsize
plt.rc('figure', titlesize=BIGGER_SIZE) # fontsize of the figure title

plt.rcParams['figure.figsize'] = [12, 7.5]

plt.plot( output_daiet, label='DAIET', marker="^", markersize=13)
plt.plot( output_topk, label='MARINA-DH', marker="D", markersize=10)
plt.plot( ouput_marina_dh, label= 'MARINA-SH',marker="D", markersize=10)

plt.legend()

plt.ylabel('Reduction ratio (%)')
plt.xlabel('The number of key-value pairs (fat-tree)')
plt.xticks( xtick_l , xtick_r )
print(xtick_l)
print(xtick_r)
plt.yticks(np.arange(0,105,10))
plt.savefig('graph-fat_tree_reg1500_15000_subin.png')