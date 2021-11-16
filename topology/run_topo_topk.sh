##########################
BMV2_PATH=~/behavioral-model
P4C_BM_PATH=/home/mnc/behavioral-model/p4c-bm
##########################

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py
SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch
CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI

sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python2 /home/mnc/p4-dev/topk/topology/topo_topk_hw.py \
    --behavioral-exe $BMV2_PATH/targets/simple_switch/simple_switch \
    --switch /home/mnc/p4-dev/topk/topk_for_daiet_same.json \
    --switch0 /home/mnc/p4-dev/topk/topk_for_daiet_same_stage3.json \
    --switch12 /home/mnc/p4-dev/topk/topk_for_daiet_A12.json \
    --switch21 /home/mnc/p4-dev/topk/topk_for_daiet_A21.json \
    --switch23 /home/mnc/p4-dev/topk/topk_for_daiet_A23.json \
    --switch32 /home/mnc/p4-dev/topk/topk_for_daiet_A32.json \
    --switch123 /home/mnc/p4-dev/topk/topk_for_daiet_A123.json \
    --switch213 /home/mnc/p4-dev/topk/topk_for_daiet_A213.json \
    --switch312 /home/mnc/p4-dev/topk/topk_for_daiet_A312.json \
    --cli $CLI_PATH 