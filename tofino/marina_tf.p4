#include <core.p4>
#include <tna.p4>

// fw

const bit<16> TYPE_NSH = 0x894f;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ETHER = 0x6558;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;

#define NUM 128

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16>     srcPort;
    bit<16>     dstPort;
    bit<32>     seqNo;
    bit<32>     ackNo;
    bit<4>      dataOffset;
    bit<4>      res;
    bit<8>      flags;
    bit<16>     windows;
    bit<16>     checksum;
    bit<16>     urgenPtr;

}

header udp_t {
    bit<16>    srcPort;
    bit<16>    dstPort;
    bit<16>    length_;
    bit<16>    checksum;
}

header frame_type_t {
    bit<8>      frame_type;
}

header entry_t {
    bit<32>    key;
    bit<32>    value;
}

header entry_flush_t {
    bit<32>    key1;
    bit<32>    value1;
    bit<32>    key2;
    bit<32>    value2;
}


header rec_hdr_t {
    bit<32>     table1_register_idx;
    bit<32>     table2_register_idx;
    bit<32>     table1_key;
    bit<32>     table2_key;
    bit<32>     table1_valid_entries_index;
    bit<32>     table2_valid_entries_index;
    bit<32>     table1_valid_entries_stack;
    bit<32>     table2_valid_entries_stack;
    bit<8>      pushout_flag;
    bit<8>      save_bitmap;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    frame_type_t frame_type;
    entry_t      entry;
    entry_flush_t entry_flush;
    rec_hdr_t    rec_hdr;
}

struct metadata_t {
    bit<32> p_key; // previous
    bit<32> p_counter;
    bit<32> p_value;
    bit<32> c_key; // current (register)
    bit<32> c_counter;
    bit<32> c_value;
    bit<32> register_idx1;
    bit<32> register_idx2;
    bit<32> table1_valid_entries_index;
    bit<32> table2_valid_entries_index;
    bit<32> table1_valid_entries_stack;
    bit<32> table2_valid_entries_stack;
    bit<32> tree_id;
    bit<32> number_of_entries1;
    bit<32> number_of_entries2;
    bit<2>  is_saved;
    bit<32> temp;
    bit<32> temp2;
}

//////////////////* Metadata *//////////////////
//////////////////* Metadata *//////////////////
//////////////////* Metadata *//////////////////


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SwitchIngressParser(
                packet_in pkt,
                out headers hdr,
               out metadata_t meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition parse_port_metadata;
    }
    
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_frame_type;
    }

    state parse_frame_type {
        pkt.extract(hdr.frame_type);
        transition select(hdr.frame_type.frame_type) {
            0: parse_entry;
            11: parse_rec_hdr;
            default: parse_entry;
        }
    }

    state parse_entry {
        pkt.extract(hdr.entry);
        transition accept;
    }

    state parse_rec_hdr {
        pkt.extract(hdr.entry);
        pkt.extract(hdr.rec_hdr);
        transition accept;
    }
}




/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchIngress(
        inout headers hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
                      ) {
                    
    action pass() {
    }

    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }


/****************** Ingress Tables*******************/
/****************** Ingress Tables*******************/
/****************** Ingress Tables*******************/
/****************** Ingress Tables*******************/
/****************** Ingress Tables*******************/
/****************** Ingress Tables*******************/


    table fw_ip {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            drop;
            pass;
            send;
        }
        const entries = {
            0x0A000201 : send(160); // 10.0.2.1
        }
    }
    table fw_tcp {
        key = {
            hdr.tcp.dstPort : exact;
        }
        actions = {
            drop;
            pass;
            send;
        }
        const entries = {
            80 : pass();
        }
    }



Hash<bit<16>> (HashAlgorithm_t.CRC16) hash_crc16;
Hash<bit<32>> (HashAlgorithm_t.CRC32) hash_crc32;


Register<bit<32>, bit<32>>(NUM) key_table1;
Register<bit<32>, bit<32>>(NUM) value_table1;
Register<bit<32>, bit<32>>(NUM) counter_table1;

Register<bit<32>, bit<32>>(NUM) key_table2;
Register<bit<32>, bit<32>>(NUM) value_table2;
Register<bit<32>, bit<32>>(NUM) counter_table2;

Register<bit<32>, bit<32>>(NUM) key_table3;
Register<bit<32>, bit<32>>(NUM) value_table3;
Register<bit<32>, bit<32>>(NUM) counter_table3;

Register<bit<32>, bit<32>>(NUM) table1_valid_entries_index;
Register<bit<32>, bit<32>>(NUM) table1_valid_entries_stack;

Register<bit<32>, bit<32>>(NUM) table2_valid_entries_index;
Register<bit<32>, bit<32>>(NUM) table2_valid_entries_stack;

Register<bit<32>, bit<32>>(NUM) table3_valid_entries_index;
Register<bit<32>, bit<32>>(NUM) table3_valid_entries_stack;

// 1
RegisterAction<bit<32>, bit<32>, bit<32>>(key_table1) key_table1_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(key_table1) key_table1_write = { 
    void apply(inout bit<32> value){ 
        value = hdr.rec_hdr.table1_key; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(counter_table1) counter_table1_update  = { 
    void apply(inout bit<32> value){ 
        value = value + 1;  
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(counter_table1) counter_table1_initialize  = { 
    void apply(inout bit<32> value){ 
        value = 1;  
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(counter_table1) counter_table1_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
        value = meta.p_counter;  
        // } 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(value_table1) value_table1_for_same  = { 
    void apply(inout bit<32> value){ 
        value = value + meta.p_value; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(value_table1) value_table1_for_different  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
        value = meta.p_value; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(value_table1) value_table1_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
    } 
}; 





// 2
RegisterAction<bit<32>, bit<32>, bit<32>>(key_table2) key_table2_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(key_table2) key_table2_write = { 
    void apply(inout bit<32> value){ 
        value = hdr.rec_hdr.table2_key; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(counter_table2) counter_table2_update  = { 
    void apply(inout bit<32> value){ 
        value = value + 1;  
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(counter_table2) counter_table2_initialize  = { 
    void apply(inout bit<32> value){ 
        value = meta.p_counter;  
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(counter_table2) counter_table2_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
        if(value >= meta.p_counter){  
            value = value;  
        } 
        else{ 
            value = meta.p_counter;  
        } 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(value_table2) value_table2_for_same  = { 
    void apply(inout bit<32> value){ 
        value = value + meta.p_value; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(value_table2) value_table2_for_different  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
        value = meta.p_value; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(value_table2) value_table2_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
    } 
}; 



RegisterAction<bit<32>, bit<32>, bit<32>>(table1_valid_entries_index) table1_valid_entries_index_write  = { 
    void apply(inout bit<32> value){ 
        value = hdr.rec_hdr.table1_valid_entries_index; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(table1_valid_entries_index) table1_valid_entries_index_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(table1_valid_entries_index) table1_valid_entries_index_read_write  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        if (value == 0){
            value = -1;
        }
        else{
            value = value - 1;
        }
        read_value = value + 1;
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(table1_valid_entries_index) table1_valid_entries_index_update  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        value = value + 1;
        read_value = value;
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(table1_valid_entries_stack) table1_valid_entries_stack_write  = { 
    void apply(inout bit<32> value){ 
        value = hdr.rec_hdr.table1_register_idx;  
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(table1_valid_entries_stack) table1_valid_entries_stack_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
    } 
}; 


RegisterAction<bit<32>, bit<32>, bit<32>>(table2_valid_entries_index) table2_valid_entries_index_write  = { 
    void apply(inout bit<32> value){ 
        value = hdr.rec_hdr.table2_valid_entries_index; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(table2_valid_entries_index) table2_valid_entries_index_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(table2_valid_entries_index) table2_valid_entries_index_read_write  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        if (value == 0){
            value = -1;
        }
        else{
            value = value - 1;
        }
        read_value = value + 1;
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(table2_valid_entries_index) table2_valid_entries_index_update  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        value = value + 1;
        read_value = value;
    } 
}; RegisterAction<bit<32>, bit<32>, bit<32>>(table2_valid_entries_stack) table2_valid_entries_stack_write  = { 
    void apply(inout bit<32> value){ 
        value = hdr.rec_hdr.table2_register_idx;  
    } 
}; 
RegisterAction<bit<32>, bit<32>, bit<32>>(table2_valid_entries_stack) table2_valid_entries_stack_read  = { 
    void apply(inout bit<32> value, out bit<32> read_value){ 
        read_value = value; 
    } 
}; 

action read_index2() {
    meta.table2_valid_entries_index = table2_valid_entries_index_read.execute(meta.tree_id);
    // meta.register_idx2 = hash_crc32.get({hdr.entry.key});
    // meta.register_idx2 = hdr.ipv4.dstAddr; //FIXME:
}

action get_hash2() {
    meta.register_idx2 = (bit<32>)hash_crc32.get({hdr.entry.key})[31:25];
}

action subtract_action(bit<32> a, bit<32> b){
    meta.temp = a-b;
}
action subtract_action2(bit<32> c, bit<32> d){
    meta.temp2 = c-d;
}




action swap1(){
    meta.p_counter = meta.c_counter; 
    meta.p_value = value_table1_for_different.execute(meta.register_idx1); // 
    hdr.rec_hdr.table1_key = meta.p_key; 
    hdr.rec_hdr.table1_register_idx = meta.register_idx1;
    meta.p_key = meta.c_key;    
}

action swap2_2(){
    hdr.rec_hdr.table2_key = meta.p_key; 
    hdr.rec_hdr.table2_register_idx = meta.register_idx2;
    meta.p_key = meta.c_key;    
}


action swap2(){
    meta.p_counter = meta.c_counter; 
    meta.p_value = value_table2_for_different.execute(meta.register_idx2); // 
 
}


table compare_table1{
    key={
        meta.temp : ternary;
    }
    actions = {
        swap1();
        NoAction();
    }
    const entries= {

        0x80000000 &&& 0x80000000 : swap1(); // negative
    }

}

table compare_table2{
    key={
        meta.temp2 : ternary;
    }
    actions = {
        swap2();
        NoAction();
    }
    const entries= {

        0x80000000 &&& 0x80000000 : swap2(); // negative
    }

}

table compare_table2_2{
    key={
        meta.temp2 : ternary;
    }
    actions = {
        swap2_2();
        NoAction();
    }
    const entries= {

        0x80000000 &&& 0x80000000 : swap2_2(); // negative
    }

}

action flush_action1(){
    meta.number_of_entries1 = table1_valid_entries_index_read_write.execute(meta.tree_id);
}

action flush_action1_1(){
    meta.register_idx1 = table1_valid_entries_stack_read.execute(meta.number_of_entries1);
}
action flush_action1_2(){
    hdr.entry_flush.key1 = key_table1_read.execute(meta.register_idx1);
}
action flush_action1_3(){
    hdr.entry_flush.value1 = value_table1_read.execute(meta.register_idx1);
}









    apply{
        bit<32>stored_key;
        bit<32>stored_value;
        bit<32>counter_value;
        bit<32>register_idx;
        bit<4> is_saved;
        ig_tm_md.bypass_egress = 1;


        if(hdr.frame_type.frame_type == 0 ){

            meta.p_key = hdr.entry.key; 
            meta.p_value = hdr.entry.value;
            meta.p_counter = 1; // initial value
            

            /* Stage 1 */
            /* Stage 1 */
            /* Stage 1 */

            meta.table1_valid_entries_index = table1_valid_entries_index_read.execute(meta.tree_id); 
            meta.register_idx1 = (bit<32>)hash_crc16.get({hdr.entry.key})[15:9];
            meta.c_key = key_table1_read.execute(meta.register_idx1);
            if (meta.c_key == 0) { // Case 1
                value_table1_for_same.execute(meta.register_idx1); // store value in empty register
                counter_table1_initialize.execute(meta.register_idx1); // set counter value : 1
                meta.table1_valid_entries_index = meta.table1_valid_entries_index + 1; // num_entries ++
                hdr.rec_hdr.table1_valid_entries_index = meta.table1_valid_entries_index; // num_entries ++
                hdr.rec_hdr.table1_key = meta.p_key; 
                hdr.rec_hdr.table1_register_idx = meta.register_idx1;
                meta.is_saved = 1;
                hdr.rec_hdr.save_bitmap = 1;
            }
            else if(meta.p_key == meta.c_key){ // Case 2
                value_table1_for_same.execute(meta.register_idx1);
                counter_table1_update.execute(meta.register_idx1);
                meta.is_saved = 1;
            }
            else{ // meta.p_key != meta.c_key
                meta.c_counter = counter_table1_read.execute(meta.register_idx1);
                subtract_action(meta.c_counter, meta.p_counter);
                swap1(); 
                hdr.rec_hdr.save_bitmap =  1;
                hdr.rec_hdr.table1_valid_entries_index = meta.table1_valid_entries_index;
            }


            if(meta.is_saved != 1){
                read_index2(); 
                get_hash2();
                meta.c_key = key_table2_read.execute(meta.register_idx2); 
                if (meta.c_key == 0){ 
                    value_table2_for_same.execute(meta.register_idx2); // store value in empty register
                    counter_table2_initialize.execute(meta.register_idx2); // set counter value : 1
                    meta.table2_valid_entries_index = meta.table2_valid_entries_index + 1;
                    hdr.rec_hdr.table2_valid_entries_index = meta.table2_valid_entries_index; // num_entries ++
                    hdr.rec_hdr.table2_key = meta.p_key; 
                    hdr.rec_hdr.table2_register_idx = meta.register_idx2;
                    meta.is_saved = 1;
                    hdr.rec_hdr.save_bitmap = hdr.rec_hdr.save_bitmap + 2;
                }            
                else if (meta.p_key == meta.c_key){ // 
                    value_table2_for_same.execute(meta.register_idx2);
                    counter_table2_update.execute(meta.register_idx2);
                    meta.is_saved = 1;
                }
                else{ // meta.p_key != meta.c_key
                    meta.c_counter = counter_table2_read.execute(meta.register_idx2);
                    subtract_action2(meta.c_counter, meta.p_counter);
                    compare_table2.apply(); 
                    compare_table2_2.apply();
                    hdr.rec_hdr.save_bitmap = hdr.rec_hdr.save_bitmap + 2;
                    hdr.rec_hdr.table2_valid_entries_index = meta.table2_valid_entries_index;
                }
            }


            /* Packet is not saved -> Pushout */
            if(meta.is_saved != 1){
                hdr.entry.key = meta.p_key;
                hdr.entry.value = meta.p_value;
                hdr.rec_hdr.pushout_flag = 1;
            }


            hdr.frame_type.frame_type = 11;
            ig_tm_md.ucast_egress_port = 68;
            hdr.rec_hdr.setValid();

            
        }

        else if(hdr.frame_type.frame_type == 11 ){ 
            if(hdr.rec_hdr.save_bitmap & 1 == 1){
                table1_valid_entries_index_write.execute(meta.tree_id);
                table1_valid_entries_stack_write.execute(hdr.rec_hdr.table1_valid_entries_index); // store num_entries
                key_table1_write.execute(hdr.rec_hdr.table1_register_idx); //
            }

            if(hdr.rec_hdr.save_bitmap & 2 == 2){
                table2_valid_entries_index_write.execute(meta.tree_id);
                table2_valid_entries_stack_write.execute(hdr.rec_hdr.table2_valid_entries_index); // store num_entries
                key_table2_write.execute(hdr.rec_hdr.table2_register_idx); //
            }

            if(hdr.rec_hdr.pushout_flag == 1){
                ig_tm_md.ucast_egress_port = 1;
                hdr.frame_type.frame_type = 3; // pushout packet
            }   

            

        }


 }



    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control SwitchIngressDeparser(
        packet_out packet,
        inout headers hdr,
        in metadata_t meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    
    
    apply{
        packet.emit(hdr);
    }
    
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

parser EgressParser(
   packet_in packet,
   out headers hdr,
   out metadata_t meta,
   out egress_intrinsic_metadata_t eg_intr_md){

   state start {
       packet.extract(eg_intr_md);
        transition parse_ethernet;
   }
   
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
    }

}

control Egress(
   inout headers hdr,
   inout metadata_t meta,
   in egress_intrinsic_metadata_t eg_intr_md,
   in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
   inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
   inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport){



   apply{
        hdr.ethernet.dstAddr = eg_prsr_md.global_tstamp; 
    }

}

control EgressDeparser(
   packet_out packet,
   inout headers hdr,
   in metadata_t eg_md,
   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

   apply{
        packet.emit(hdr);
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EgressParser(),
         Egress(),
         EgressDeparser()) pipe;

Switch(pipe) main;
