
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
    u_int8_t ether_dhost[6];  /*Ŀ����̫��ַ*/
    u_int8_t ether_shost[6];  /*Դ��̫����ַ*/
    u_int16_t ether_type;      /*��̫������*/
}Ethernet;

/*ip��ַ��ʽ*/
typedef u_int32_t in_addr_t;

 struct ip_header
{
#ifdef WORKS_BIGENDIAN
    u_int8_t ip_version : 4,    /*version:4*/
        ip_header_length : 4; /*IPЭ���ײ�����Header Length*/
#else
    u_int8_t ip_header_length : 4,
        ip_version : 4;
#endif
    u_int8_t ip_tos;         /*��������Differentiated Services  Field*/
    u_int16_t ip_length;  /*�ܳ���Total Length*/
    u_int16_t ip_id;         /*��ʶidentification*/
    u_int16_t ip_off;        /*Ƭƫ��*/
    u_int8_t ip_ttl;            /*����ʱ��Time To Live*/
    u_int8_t ip_protocol;        /*Э�����ͣ�TCP����UDPЭ�飩*/
    u_int16_t ip_checksum;  /*�ײ������*/
    struct in_addr  ip_source_address; /*ԴIP*/
    struct in_addr  ip_destination_address; /*Ŀ��IP*/
};

/*����tcpͷ���Ķ���*/
struct tcp_header
{
    u_int16_t tcp_source_port;		  //Դ�˿ں�

    u_int16_t tcp_destination_port;	//Ŀ�Ķ˿ں�

    u_int32_t tcp_acknowledgement;	//���

    u_int32_t tcp_ack;	//ȷ�Ϻ��ֶ�
#ifdef WORDS_BIGENDIAN
    u_int8_t tcp_offset : 4,
        tcp_reserved : 4;
#else
    u_int8_t tcp_reserved : 4,
        tcp_offset : 4;
#endif
    u_int8_t tcp_flags;
    u_int16_t tcp_windows;	//�����ֶ�
    u_int16_t tcp_checksum;	//�����
    u_int16_t tcp_urgent_pointer;	//����ָ���ֶ�
};



typedef struct my_ip_header
{

    u_int ip_header_length;
    u_int8_t ip_version;

    u_int8_t ip_tos;         /*��������Differentiated Services  Field*/
    u_int16_t ip_length;  /*�ܳ���Total Length*/
    u_int16_t ip_id;         /*��ʶidentification*/
    u_int16_t ip_off;        /*Ƭƫ��*/
    u_int8_t ip_ttl;            /*����ʱ��Time To Live*/
    u_int8_t ip_protocol;        /*Э�����ͣ�TCP����UDPЭ�飩*/
    u_int16_t ip_checksum;  /*�ײ������*/
    string ip_source_address; /*ԴIP*/
    string ip_destination_address; /*Ŀ��IP*/
}MyIp;


typedef struct my_tcp_header
{
    u_int16_t tcp_source_port;		  //Դ�˿ں�
    u_int16_t tcp_destination_port;	//Ŀ�Ķ˿ں�
    int header_L; //ͷ������
    u_int tcp_acknowledgement;	//���к�
    u_int tcp_ack;	//ȷ�Ϻ�
    u_int16_t tcp_windows;	//�����ֶ�
    u_int16_t tcp_urgent_pointer;	//����ָ���ֶ�
    u_int8_t tcp_flags; //����λ
    u_int16_t tcp_checksum;	//�����
    u_int8_t tcp_reserved;//�����ֶ�

   
}MyTcp;

#endif MYWPCAP_H