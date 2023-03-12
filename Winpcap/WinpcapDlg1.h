
// WinpcapDlg.h: 头文件
//
#include "CPublicData.h"


#pragma once



// CWinpcapDlg 对话框


class CWinpcapDlg : public CDialogEx
{
	// 构造
public:
	/*CWinpcapDlg(CWnd* pParent = nullptr) {
		argument1 = this;
	}*/

	CWinpcapDlg(CWnd* pParent = nullptr);	// 标准构造函数

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_WINPCAP_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


	// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:

	CListCtrl m_listc1;//显示
	CListCtrl CAP_R;
	CListCtrl IP_SHOW;
	CListCtrl TCP_SHOW;

	CEdit SelectWKID;  //选择网卡
	CString w_id;

	afx_msg void OnBnClickedBucap();

	
	pcap_if_t* alldevs;//抓包
	pcap_if_t* d;
	pcap_t* adhandle;
	int inum = 0;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	string HexToAscii(unsigned char* pHex);//数据转换
	map<int, char>MyMap;

	void IP_Display();
	void TCP_Display();
	void Eth_DisPlay();

	//线程与刷新
	afx_msg void OnBnClickedclose();
	HANDLE m_hThread;
	afx_msg void OnTimer(UINT_PTR nIDEvent);
};



UINT MyThreadFunction(LPVOID pParam); //线程函数
DWORD WINAPI ThreadFunction(LPVOID lpParam);
void ethernet_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content);
void ip_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content);
void tcp_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content);