#pragma once
#include <string>
#include <pcap.h>
#include "MYWPCAP.h"

using namespace std;
class CPublicData
{
	public:
		//抓包
		static pcap_t* my_adhandle;
		static int my_cnt;
		//eth
		static	Ethernet ethetnetlist[100];
		static int packet_number;
		//ip
		static MyIp iplist[100] ;
		static int IP_Number;
		//tcp
		static MyTcp tcplist[100];
		static int TCP_Number;
		//总包数显示序号
		static int t_eth; 
		static int t_ip;
		static int t_tcp;

};


