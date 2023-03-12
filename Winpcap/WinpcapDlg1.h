
// WinpcapDlg.h: ͷ�ļ�
//
#include "CPublicData.h"


#pragma once



// CWinpcapDlg �Ի���


class CWinpcapDlg : public CDialogEx
{
	// ����
public:
	/*CWinpcapDlg(CWnd* pParent = nullptr) {
		argument1 = this;
	}*/

	CWinpcapDlg(CWnd* pParent = nullptr);	// ��׼���캯��

	// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_WINPCAP_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


	// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:

	CListCtrl m_listc1;//��ʾ
	CListCtrl CAP_R;
	CListCtrl IP_SHOW;
	CListCtrl TCP_SHOW;

	CEdit SelectWKID;  //ѡ������
	CString w_id;

	afx_msg void OnBnClickedBucap();

	
	pcap_if_t* alldevs;//ץ��
	pcap_if_t* d;
	pcap_t* adhandle;
	int inum = 0;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	string HexToAscii(unsigned char* pHex);//����ת��
	map<int, char>MyMap;

	void IP_Display();
	void TCP_Display();
	void Eth_DisPlay();

	//�߳���ˢ��
	afx_msg void OnBnClickedclose();
	HANDLE m_hThread;
	afx_msg void OnTimer(UINT_PTR nIDEvent);
};



UINT MyThreadFunction(LPVOID pParam); //�̺߳���
DWORD WINAPI ThreadFunction(LPVOID lpParam);
void ethernet_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content);
void ip_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content);
void tcp_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content);