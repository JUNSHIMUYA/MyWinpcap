
#ifndef MYWPCAP_H
#define MYWPCAP_H

#pragma once

#define WIN32

#include <iostream>
#include <pcap.h>
#include <Winsock2.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <map>

using namespace std;





typedef struct ethernet_header
{
    u_int8_t ether_dhost[6];  /*目的以太地址*/
    u_int8_t ether_shost[6];  /*源以太网地址*/
    u_int16_t ether_type;      /*以太网类型*/
}Ethernet;

/*ip地址格式*/
typedef u_int32_t in_addr_t;

 struct ip_header
{
#ifdef WORKS_BIGENDIAN
    u_int8_t ip_version : 4,    /*version:4*/
        ip_header_length : 4; /*IP协议首部长度Header Length*/
#else
    u_int8_t ip_header_length : 4,
        ip_version : 4;
#endif
    u_int8_t ip_tos;         /*服务类型Differentiated Services  Field*/
    u_int16_t ip_length;  /*总长度Total Length*/
    u_int16_t ip_id;         /*标识identification*/
    u_int16_t ip_off;        /*片偏移*/
    u_int8_t ip_ttl;            /*生存时间Time To Live*/
    u_int8_t ip_protocol;        /*协议类型（TCP或者UDP协议）*/
    u_int16_t ip_checksum;  /*首部检验和*/
    struct in_addr  ip_source_address; /*源IP*/
    struct in_addr  ip_destination_address; /*目的IP*/
};

/*关于tcp头部的定义*/
struct tcp_header
{
    u_int16_t tcp_source_port;		  //源端口号

    u_int16_t tcp_destination_port;	//目的端口号

    u_int32_t tcp_acknowledgement;	//序号

    u_int32_t tcp_ack;	//确认号字段
#ifdef WORDS_BIGENDIAN
    u_int8_t tcp_offset : 4,
        tcp_reserved : 4;
#else
    u_int8_t tcp_reserved : 4,
        tcp_offset : 4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows;	//窗口字段
    u_int16_t tcp_checksum;	//检验和
    u_int16_t tcp_urgent_pointer;	//紧急指针字段
};



typedef struct my_ip_header
{

    u_int ip_header_length;
    u_int8_t ip_version;

    u_int8_t ip_tos;         /*服务类型Differentiated Services  Field*/
    u_int16_t ip_length;  /*总长度Total Length*/
    u_int16_t ip_id;         /*标识identification*/
    u_int16_t ip_off;        /*片偏移*/
    u_int8_t ip_ttl;            /*生存时间Time To Live*/
    u_int8_t ip_protocol;        /*协议类型（TCP或者UDP协议）*/
    u_int16_t ip_checksum;  /*首部检验和*/
    string ip_source_address; /*源IP*/
    string ip_destination_address; /*目的IP*/
}MyIp;


typedef struct my_tcp_header
{
    u_int16_t tcp_source_port;		  //源端口号
    u_int16_t tcp_destination_port;	//目的端口号
    int header_L; //头部长度
    u_int tcp_acknowledgement;	//序列号
    u_int tcp_ack;	//确认号
    u_int16_t tcp_windows;	//窗口字段
    u_int16_t tcp_urgent_pointer;	//紧急指针字段
    u_int8_t tcp_flags; //控制位
    u_int16_t tcp_checksum;	//检验和
    u_int8_t tcp_reserved;//保留字段

   
}MyTcp;

#endif MYWPCAP_H