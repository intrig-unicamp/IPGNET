#include <core.p4>
#include <tna.p4>
//#include "include/headers.p4"
#include "include/parser.p4"
//#include "include/constants.p4"
#define THRESHOLD 20

const bit<32> th = 100;

/*********************  I N G R E S S   P R O C E S S I N G  ********************************************/


control SwitchIngress(
        inout header_t hdr,
        inout ingress_metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

	Register <bit<16>, _> (32w2048)  rIPGw;
	Register <bit<32>, _> (32w2048)  rTSlast;
	Register <bit<1>,  _> (32w2048)  rIPGflag;

	//Register <bit<16>, _>(1) aa;

	Hash<bit<11>>(HashAlgorithm_t.CRC32) hTableIndex;
	MathUnit<bit<16>>(MathOp_t.MUL, 1, 16) right_shift;


//-----------------------------------Compute Flow Index-------------------------------------------------/
	action computeFIndex() {   
    	meta.hash_meta.mIndex = hTableIndex.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr,hdr.ipv4.protocol, 									meta.hash_meta.l4_sport, meta.hash_meta.l4_dport}); 
	}
	
//-----------------------------------Compute IPG Flag---------------------------------------------------/
	RegisterAction<bit<1>, bit<11>, bit<1>>(rIPGflag) rIPGflag_action = {
    	void apply(inout bit<1> value, out bit<1> readvalue){
 	       readvalue = value;
           value = 1;
        }
    };

//--------------------------------Case 1: new entry in vacant slot--------------------------------------/

	RegisterAction<bit<16>, bit<11>, bit<16>>(rIPGw) rIPGw_action1 = {
    	void apply(inout bit<16> value, out bit<16> output){
 	    	value = (bit<16>)(1400);//IPG_INIT;
   		    output = (bit<16>)(1400);//IPG_INIT;
        }
    };

	RegisterAction<bit<32>, bit<11>, bit<32>>(rTSlast) rTSlast_action1 = {
    	void apply(inout bit<32> value){
        	value =  (bit<32>)meta.hash_meta.TS[30:0];
        }
    };

//------------------------------Case 2: update entry---------------------------------------------------

	RegisterAction<bit<32>, rSize, bit<32>>(rTSlast) rTSlast_action2 = {
              void apply(inout bit<32> value, out bit<32> readvalue){
                  bit<32> tmp;
                  if (value >  (bit<32>)meta.hash_meta.TS[30:0]) {
                     tmp = value + 0x80000000;
                     readvalue = tmp;
                  } else { tmp = value; readvalue = tmp;}
                  value = (bit<32>)meta.hash_meta.TS[30:0];
          }
       };
 
      /**** Update IPG weighted (approximate calclution) **************/

	RegisterAction<bit<16>, rSize, bit<16>>(rIPGw) rIPGw_action3 = {
              void apply(inout bit<16> value, out bit<16> readvalue){
                    //readvalue = value;
                    if (value > meta.hash_meta.IPGc) {
                          value = value - right_shift.execute(value);
                    } 
                    else {
			  //value = value + right_shift.execute(value);
                          value = value + meta.hash_meta.IPGcComp;
                    }
					readvalue = value;
					meta.hash_meta.IPGw = value;
             }
       };
	
	action computeTSlast() {
                 meta.hash_meta.TSlastComp  =  rTSlast_action2.execute(meta.hash_meta.mIndex);
       }
       action computeTSc() {
                 /*********** Set wraptime 4096 microseconds ***********************/ 
                 meta.hash_meta.TSc     =  (bit<32>)(meta.hash_meta.TS[30:0]);
                 meta.hash_meta.TSlast  =  (bit<32>)(meta.hash_meta.TSlastComp[30:0]);
       }
       action computeIPGc_wt() {
                 meta.hash_meta.IPGc = meta.hash_meta.Diff + (bit<16>)meta.hash_meta.TSc;
       }
       action computeIPGc() {
                 meta.hash_meta.IPGc = (bit<16>)(meta.hash_meta.TSc - meta.hash_meta.TSlast);
       }
	

	action set_ipg_header(){
		hdr.ipv4.total_len = hdr.ipv4.total_len + 24;//era 16
		
		hdr.ipv4.ihl = hdr.ipv4.ihl + 6;//era 4


		hdr.ipv4_option.setValid();
		hdr.ipv4_option.optionLength = 24; // telemetry(48) + IPOption(16) = 64 bites ==> 64/8 = 8 octets 
		hdr.ipv4_option.option = TYPE_TELEMETRY;


		hdr.ipg.setValid();
		hdr.ipg.seq = 1;
		hdr.ipg.IPGw = meta.hash_meta.IPGw;
		//hdr.ipg.ts = ig_intr_md.ingress_mac_tstamp;
		//hdr.ipg.ts = ig_intr_md.ingress_mac_tstamp;
		hdr.ipg.new = (bit<32>)meta.hash_meta.mIndex;
		hdr.ipg.pad = meta.hash_meta.IPGcComp;
		//hdr.ipg.pad = meta.hash_meta.IPGcComp;
	}

	action set_ipg_header2(){
		
		hdr.ipg.seq = hdr.ipg.seq + 1;
		hdr.ipg.IPGw = meta.hash_meta.IPGw;
		//hdr.ipg.ts = ig_intr_md.ingress_mac_tstamp;
		
		//hdr.ipg.new = (bit<32>)meta.hash_meta.mIndex;
		//hdr.ipg.pad = meta.hash_meta.IPGcComp;
		
	}

	action tt(){
		//ig_tm_md.ucast_egress_port = 144;//tofino 2
		ig_tm_md.ucast_egress_port = 136;//netfpga
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	action ta(){
		ig_tm_md.ucast_egress_port = 24;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	action te(){
		ig_tm_md.ucast_egress_port = 25;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}



/********** forwarding packets to output port ***********************************/
	action setOutputPort(port_t port) {
    	ig_tm_md.ucast_egress_port = port;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    /*   
	table tblForwarding {
    	key = {
        	hdr.ipv4.src_addr :  exact;
        }
		actions = {
	    	setOutputPort; 
			NoAction; 
		}
       size = 512;
       default_action = NoAction;
	}*/

//-----------------------------Apply Block ----------------------------------------------------
	apply{

		computeFIndex();
		//meta.hash_meta.TS = ig_prsr_md.global_tstamp;
		meta.hash_meta.TS = ig_intr_md.ingress_mac_tstamp;
		meta.hash_meta.IPGflag  = rIPGflag_action.execute(meta.hash_meta.mIndex);
		bit<16> result=1;
		bit<32> ff = 0;
		bit<16> gg = 58;
//-----------------------------Case 1 -----------------------------------------------------------
		if(meta.hash_meta.IPGflag==0){ //case 1, slot vacant
			meta.hash_meta.IPGw  = rIPGw_action1.execute(meta.hash_meta.mIndex);
			rTSlast_action1.execute(meta.hash_meta.mIndex);
		}
//-----------------------------Case 2 ------------------------------------------------------------		
		else{
			
			computeTSlast();
			computeTSc();
	    
			if (meta.hash_meta.TSlastComp[31:31] == 0x1) {
				meta.hash_meta.Diff = (bit<16>)(WRAPTIME - meta.hash_meta.TSlast);
				computeIPGc_wt();
				ff=1;
			}else {
				computeIPGc();
				ff=2;
			}
				
			meta.hash_meta.IPGcComp = (bit<16>) (meta.hash_meta.IPGc[15:4]);
			meta.hash_meta.IPGw = rIPGw_action3.execute(meta.hash_meta.mIndex);
		}

		if(hdr.ipv4_option.isValid()){
			//set_ipg_header2();
			hdr.ipg.seq = hdr.ipg.seq + 1;
			hdr.ipg.IPGw = meta.hash_meta.IPGw;

		}else{
		set_ipg_header();

		}
		//tblForwarding.apply();

		
		tt();
		
		//ig_tm_md.bypass_egress = 1w1;
	}



}


/*********************  E G R E S S   P R O C E S S I N G  ********************************************/
control SwitchEgress(
		inout header_t hdr,
        inout ingress_metadata_t meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

	Register <bit<16>, _> (32w1)  rIPGw;
	Register <bit<1>,  _> (32w1)  rIPGflag;
	Register <bit<32>,  _> (32w1)  rAux;

	MathUnit<bit<16>>(MathOp_t.MUL, 1, 16) right_shift;

	RegisterAction<bit<1>, bit<11>, bit<1>>(rIPGflag) rIPGflag_action = {
    	void apply(inout bit<1> value, out bit<1> readvalue){
 	       readvalue = value;
           value = 1;
        }
    };

	RegisterAction<bit<32>, bit<11>, bit<1>>(rAux) rTest_action = {
		void apply(inout bit<32> value, out bit<1> readvalue){
			if((bit<32>)eg_intr_md.enq_qdepth >= THRESHOLD)
				readvalue = 1;
			else
				readvalue = 0;
        }
	};

//--------------------------------Case 1: new entry in vacant slot--------------------------------------/

	RegisterAction<bit<16>, bit<11>, bit<16>>(rIPGw) rIPGw_action1 = {
    	void apply(inout bit<16> value, out bit<16> output){
 	    	value = (bit<16>)(1400);//IPG_INIT;
   		    //output = (bit<16>)(1400);//IPG_INIT;
		output = 0;
        }
    };

//------------------------------Case 2: update entry---------------------------------------------------

	RegisterAction<bit<16>, rSize, bit<16>>(rIPGw) rIPGw_action3 = {
		void apply(inout bit<16> value, out bit<16> readvalue){
                //readvalue = value;
        	if (value > meta.hash_meta.IPGc) {
				readvalue = value;            	
				value = value - right_shift.execute(value);
				//readvalue = value; 
				//meta.hash_meta.IPGw = value;
            } 
            else {
				value = value + meta.hash_meta.IPGcComp;
				readvalue = 0;
				//meta.hash_meta.IPGw = 0;
            }
					//readvalue = value;
					//meta.hash_meta.IPGw = value;
					
             }
       };

	action remove_int(){
		hdr.ipv4.total_len = hdr.ipv4.total_len - 24;
		
		hdr.ipv4.ihl = hdr.ipv4.ihl - 6;


		hdr.ipv4_option.setInvalid();
		hdr.ipg.setInvalid();

	}

	
//-----------------------------Apply Block ----------------------------------------------------
	apply{


		bit<1> aux=0;
		if(hdr.ipg.isValid()){		
			aux = rIPGflag_action.execute(0);
			bit<1> f = 0;
			if(aux==0){
				meta.hash_meta.IPGw  = rIPGw_action1.execute(0);
			}else{
				meta.hash_meta.IPGc = hdr.ipg.IPGw;
				meta.hash_meta.IPGcComp = (bit<16>) (meta.hash_meta.IPGc[15:4]);

				//f = rIPGw_action3.execute(0);

				meta.hash_meta.IPGw = rIPGw_action3.execute(0);
			}

			bit<1> flag = rTest_action.execute(0);
			if(flag==1){
				if(meta.hash_meta.IPGw==0){
					remove_int();
					//hdr.ipg.pad = meta.hash_meta.IPGc;
				}
				else{
					hdr.ipg.pad = meta.hash_meta.IPGw;
					hdr.ipg.ts = (bit<48>)eg_intr_md.enq_qdepth;
					if(hdr.tcp.isValid()){
						hdr.tcp.srcPort = 1999;
					}
					if(hdr.udp.isValid()){
						hdr.udp.srcPort = 1999;
					}
					

					//change();
					//remove_int();
				}
			}
			else{
				remove_int();
			}
		}
	      	

	}
}    



/********************************  S* W I T C H  ******************************************************/
Pipeline(SwitchIngressParser(),
		SwitchIngress(),
        SwitchIngressDeparser(),
        SwitchEgressParser(),
        SwitchEgress(),
        SwitchEgressDeparser()) pipe;


Switch(pipe) main;

/*************************************** End ************************************************************/
