#include "pch.h"
#include "CPublicData.h"

//抓包
pcap_t* CPublicData::my_adhandle = nullptr;
int CPublicData::my_cnt = 0;

//以太网
Ethernet CPublicData::ethetnetlist[100] = {0};
int CPublicData::packet_number = 0;
//IP
MyIp CPublicData::iplist[100] = {0};
int CPublicData::IP_Number=0;
//TCP
MyTcp CPublicData::tcplist[100] = {0};
int CPublicData::TCP_Number=0;
//总包数显示序号
int CPublicData::t_eth = 1; 
int CPublicData::t_ip = 1;
int CPublicData::t_tcp = 1;