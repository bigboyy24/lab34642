# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import pcaplib
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
import dpkt



print("\n HEY IT WORKS\n")

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.pcap_writer = pcaplib.Writer(open('pcapnew1.pcap','wb'))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

#********************************************************************************************
        ip = pkt.get_protocol(ipv4.ipv4)
        #type(ip)
        #Defines the source packet to be analysed for malicious activity
        src_ip = ip.src
        print src_ip

        if ip:
        	if ip.proto == in_proto.IPPROTO_UDP:
	    		#self.logger.info(msg.data)
	        	self.pcap_writer.write_pkt(msg.data)

	        	pcap0 = dpkt.pcap.Reader(open('pcapnew1.pcap','rb'))

	        	if pcap0:
	        		print('Pcap Being Analysed\n')
	        		for ts, buf in pcap0:
	        			eth0 = dpkt.ethernet.Ethernet(buf)
	        			ip0 = eth0.data
	        			print ip0
	        			#elf.logger.info("*******************************************************")
                    	#self.logger.info("The logger ip packet %s",ip0)
	        			if ip0.p:
		        			if ip0.p !=17:
        						#print('Hello WOrld1\n')	
		        				continue
		        			try:
		        				udp = ip0.data
		        				#print('Hello WOrld2\n')
		        			except: 
		        				continue
		        			if udp.sport !=53 and udp.dport!=53:
		        				#print('Hello WOrld3\n')
		        				continue
		        			try:
		        				dns = dpkt.dns.DNS(udp.data)
		        				#print('Hello WOrld4\n')
		        			except:
		        				continue
		        			for qname in dns.qd:
		        				#gets your query name
		        				self.logger.info("The domain name ************ %s \n",qname.name)
		        				domain = qname.name
		        				d_len = len(domain)
		        			
		        				sub =''
		        				subs =[]
		        				#print("******************\n")
		        				#print(type(domain))
		        				#print("*****************\n")
		        				

		        				for i in domain:
		        					if i!= '.':
		        						sub = sub + i
	        						else:
		        						subs.append(sub)
		        						sub =''

		        				subs.append(sub)
		        				num_of_subs=len(subs)
		        				upper = []
		        				lower = []
		        				number = []				
		        				
		        				for i in subs:
		        					upper.append(sum(1 for c in i if c.isupper()))
		        					lower.append(sum(1 for c in i if c.islower()))
		        					number.append(sum(1 for c in i if c.isdigit()))

		        				#print('{}'.format(domain))
		        				#Analysing the subdomain
								#print ("Upper data is {} \n".format(upper))
								#print("Lower data is {}\n".format(lower))
								#print("Number data is {}\n".format(number))
				else:			
					self.logger.info("NO PCAP **********")    
        '''
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
            '''
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            self.add_flow(datapath, 1, match, actions)
       
       	if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
