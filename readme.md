# MARINA
a multi-tenancy- and redundancy-aware in-network aggregation scheme that improves in-network aggregation performance by employing 1) multi-tenancy-aware aggregation tree construction and 2) top-k data aggregation. In the multi-tenancy-aware aggregation tree construction, MARINA constructs an aggregation tree by jointly considering both the remaining switch resources and the amount of data generated by each application. In addition, in the top-k data aggregation, highly redundant data are preferentially aggregated further to reduce the traffic load under the given switch resources. 

We implemented MARINA on a well-known programmable software switch (i.e., behavioral model version 2 (BMv2)) and programmable hardware switch with Tofino chip.

## Tofino
Our code is now available in SDE 9.2.0.
1. Complie P4 program
```
   ./p4_build.sh ._path/marina_tf.p4
```
2. Run switch model
```
   ./run_tofino_model.sh –p marina_tf
```
3. Run switch driver
```
   ./run_switchd.sh –p marina_tf
```
4. Packet generation
Aggregated key-value pairs are transferred through veth3, and you can see the number of aggregated key-value pairs and the total packet through below command line.
```
   python send.py && receive.py
```



## BMv2
1. Generate rules for MARINA
```
   python ._path/generate_rules_topk_##.py
```
  Python files for creating various types of rules are available in the rules folder. You can create a rule by entering the desired file name in place of ##.


2. Select topology file
Command line to select topology file 
```
   sudo cp -f ._path/topo_topk_hw_##.py ._path/topo_topk_hw.py
```

3. Run Demo
To run test, simply do:
```
   bash ._path/run_fat_tree.sh
```
You can see the test results through this command line.
```
   tail -f topk-fat-tree_reg#_stage#_diff-z-1.1-#-#.csv
```
In the shell file, you can adjust parameters such as register size, stage number, data distribution, etc., and put the parameter in place of # to check the log.

