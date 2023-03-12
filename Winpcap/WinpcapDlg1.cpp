
// WinpcapDlg.cpp: ʵ���ļ�
//

#include "pch.h"
#include "framework.h"
#include "Winpcap.h"
#include "WinpcapDlg1.h"
#include "afxdialogex.h"
#include "CPublicData.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CWinpcapDlg �Ի���



CWinpcapDlg::CWinpcapDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_WINPCAP_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	
}

void CWinpcapDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_listc1);
	DDX_Control(pDX, WK_ID, SelectWKID);

	DDX_Control(pDX, IDC_LIST2, CAP_R);
	DDX_Control(pDX, IDC_IPShow, IP_SHOW);
	DDX_Control(pDX, IDC_TCPShow, TCP_SHOW);

}

BEGIN_MESSAGE_MAP(CWinpcapDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(BuCap, &CWinpcapDlg::OnBnClickedBucap)
	ON_WM_TIMER()
	ON_BN_CLICKED(IDC_close, &CWinpcapDlg::OnBnClickedclose)
END_MESSAGE_MAP()


// CWinpcapDlg ��Ϣ�������


BOOL CWinpcapDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�
	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	//����
	// ��ʽ����Ϊ����ѡ��������
	m_listc1.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_listc1.InsertColumn(0, _T("�� ��"), LVCFMT_CENTER, 100);
	m_listc1.InsertColumn(1, _T("������"), LVCFMT_CENTER, 360);
	m_listc1.InsertColumn(2, _T("��ע"), LVCFMT_CENTER, 320);

	//������·��
	// ��ʽ����Ϊ����ѡ��������
	CAP_R.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	CAP_R.InsertColumn(0, _T("�� ��"), LVCFMT_CENTER, 200);
	CAP_R.InsertColumn(1, _T("Ŀ��MAC��ַ"), LVCFMT_CENTER, 200);
	CAP_R.InsertColumn(2, _T("ԴMAC��ַ"), LVCFMT_CENTER, 200);
	CAP_R.InsertColumn(3, _T("�����Э��"), LVCFMT_CENTER, 200);

	//�����
	// ��ʽ����Ϊ����ѡ��������
	IP_SHOW.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	IP_SHOW.InsertColumn(0, _T("�� ��"), LVCFMT_CENTER, 50);
	IP_SHOW.InsertColumn(1, _T("IP�汾"), LVCFMT_CENTER, 70);
	IP_SHOW.InsertColumn(2, _T("�ײ�����"), LVCFMT_CENTER, 70);
	IP_SHOW.InsertColumn(3, _T("��������"), LVCFMT_CENTER, 70);
	IP_SHOW.InsertColumn(4, _T("�ܳ���"), LVCFMT_CENTER, 50);
	IP_SHOW.InsertColumn(5, _T("��ʶ"), LVCFMT_CENTER, 50);
	IP_SHOW.InsertColumn(6, _T("Ƭƫ��"), LVCFMT_CENTER, 50);
	IP_SHOW.InsertColumn(7, _T("����ʱ��"), LVCFMT_CENTER, 100);
	IP_SHOW.InsertColumn(8, _T("�ײ������"), LVCFMT_CENTER, 100);
	IP_SHOW.InsertColumn(9, _T("ԴIP"), LVCFMT_CENTER, 125);
	IP_SHOW.InsertColumn(10, _T("Ŀ��IP"), LVCFMT_CENTER, 125);
	IP_SHOW.InsertColumn(11, _T("�����Э��"), LVCFMT_CENTER, 100);

	//�����
	TCP_SHOW.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	TCP_SHOW.InsertColumn(0, _T("�� ��"), LVCFMT_CENTER, 40);
	TCP_SHOW.InsertColumn(1, _T("Դ�˿�"), LVCFMT_CENTER, 50);
	TCP_SHOW.InsertColumn(2, _T("Ŀ�Ķ˿�"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(3, _T("Ӧ�ò�Э��"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(4, _T("���к�"), LVCFMT_CENTER, 100);
	TCP_SHOW.InsertColumn(5, _T("ȷ�Ϻ�"), LVCFMT_CENTER, 100);
	TCP_SHOW.InsertColumn(6, _T("�ײ�����"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(7, _T("�����ֶ�"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(8, _T("����λ"), LVCFMT_CENTER, 50);
	TCP_SHOW.InsertColumn(9, _T("���ڴ�С"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(10, _T("�����"), LVCFMT_CENTER, 50);
	TCP_SHOW.InsertColumn(11, _T("����ָ���ֶ�"), LVCFMT_CENTER, 130);


	pcap_findalldevs(&alldevs, errbuf);
	/* ��ӡ������Ϣ */
	for (d = alldevs; d; d = d->next)
	{
		++i;
		CString str;
		str.Format(_T("%d"), i);
		LPCTSTR  pStr = LPCTSTR(str);

		int nRow = m_listc1.InsertItem(i, pStr);
		m_listc1.SetItemText(nRow, 1, CString(d->name));
		m_listc1.SetItemText(nRow, 2, CString(d->description));
	}

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CWinpcapDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CWinpcapDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CWinpcapDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CWinpcapDlg::OnBnClickedBucap()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	for (int i = 0; i < 26; i++) {
		MyMap[i] = char(i + '0');
	}
	MyMap[10] = 'A';
	MyMap[11] = 'B';
	MyMap[12] = 'C';
	MyMap[13] = 'D';
	MyMap[14] = 'E';
	MyMap[15] = 'F';

	//ѡ������
	CEdit* pBoxOne;
	pBoxOne = (CEdit*)GetDlgItem(WK_ID);
	//ȡֵ
	pBoxOne->GetWindowText(w_id);
	//����ѡ�������
	inum = _ttoi(w_id);
	MessageBox(_T("ѡ�������ɹ�"), _T("��ʾ"), MB_OK);
	w_id.ReleaseBuffer();
	
	CPublicData::my_cnt =10; //ÿ��ץ������

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
		MessageBox(_T("�޷���������"), _T("��ʾ"), MB_OK);
		pcap_freealldevs(alldevs);
	}
	CPublicData::my_adhandle = adhandle;


   // CWinThread* pThread = AfxBeginThread(MyThreadFunction, 0);
	
	m_hThread=CreateThread(NULL, 0, ThreadFunction, 0, 0, 0);
	SetTimer(1, 500, NULL);
}

//eth_cap
void ethernet_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content)
{


	u_short ethernet_type;/*��̫��Э������*/
	struct ethernet_header* ethernet_protocol;/*��̫��Э�����*/

	ethernet_protocol = (struct ethernet_header*)packet_content;/*���һ̫��Э����������*/
	ethernet_type = ntohs(ethernet_protocol->ether_type); /*�����̫������*/

	
	CPublicData::ethetnetlist[CPublicData::packet_number].ether_type = ethernet_type;

	for (int i = 0; i < 6; i++) {
		CPublicData::ethetnetlist[CPublicData::packet_number].ether_dhost[i] = ethernet_protocol->ether_dhost[i];
		CPublicData::ethetnetlist[CPublicData::packet_number].ether_shost[i] = ethernet_protocol->ether_shost[i];
	}

	switch (ethernet_type)
	{
	case 0x0800:/*����ϲ���IPv4ipЭ��,�͵��÷���ipЭ��ĺ�����ip�����з���*/
		ip_protocol_packet_callback(argument, packet_header, packet_content);
		break;
	default:break;
	}

	CPublicData::packet_number++;
}

 //ip_cap
void ip_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	// TODO: �ڴ˴����ʵ�ִ���.

	struct ip_header* ip_protocol;/*ipЭ�����*/
	u_int header_length;/*����*/
	u_int offset;/*Ƭƫ��*/
	u_char tos;/*��������*/
	u_int16_t checksum;/*�ײ������*/
	ip_protocol = (struct ip_header*)(packet_content + 14); /*���ip���ݰ�������ȥ����̫ͷ��*/
	checksum = ntohs(ip_protocol->ip_checksum);/*���У���*/
	header_length = ip_protocol->ip_header_length * 4; /*��ó���*/
	tos = ip_protocol->ip_tos;/*���tos*/
	offset = ntohs(ip_protocol->ip_off);/*���ƫ����*/

	//printf("IP�汾:\t\tIPv%d\n", ip_protocol->ip_version);
	CPublicData::iplist[CPublicData::IP_Number].ip_version = ip_protocol->ip_version;
	//printf("IPЭ���ײ�����:\t%d\n", header_length);
	CPublicData::iplist[CPublicData::IP_Number].ip_header_length = header_length;
	//printf("��������:\t%d\n", tos);
	CPublicData::iplist[CPublicData::IP_Number].ip_tos = tos;
	//printf("�ܳ���:\t\t%d\n", ntohs(ip_protocol->ip_length));/*����ܳ���*/
	CPublicData::iplist[CPublicData::IP_Number].ip_length = ntohs(ip_protocol->ip_length);
	//printf("��ʶ:\t\t%d\n", ntohs(ip_protocol->ip_id));/*��ñ�ʶ*/
	CPublicData::iplist[CPublicData::IP_Number].ip_id = ntohs(ip_protocol->ip_id);
	//printf("Ƭƫ��:\t\t%d\n", (offset & 0x1fff) * 8);/**/
	CPublicData::iplist[CPublicData::IP_Number].ip_off = (offset & 0x1fff) * 8;
	//printf("����ʱ��:\t%d\n", ip_protocol->ip_ttl);/*���ttl*/
	CPublicData::iplist[CPublicData::IP_Number].ip_ttl = ip_protocol->ip_ttl;
	//printf("�ײ������:\t%d\n", checksum);
	CPublicData::iplist[CPublicData::IP_Number].ip_checksum = checksum;
	//printf("ԴIP:\t%s\n", inet_ntoa(ip_protocol->ip_source_address));/*���Դip��ַ*/
	CPublicData::iplist[CPublicData::IP_Number].ip_source_address = (string)inet_ntoa(ip_protocol->ip_source_address);
	//printf("Ŀ��IP:\t%s\n", inet_ntoa(ip_protocol->ip_destination_address));/*���Ŀ��ip��ַ*/
	CPublicData::iplist[CPublicData::IP_Number].ip_destination_address = (string)inet_ntoa(ip_protocol->ip_destination_address);
	//printf("Э���:\t%d\n", ip_protocol->ip_protocol);/*���Э������*/
	CPublicData::iplist[CPublicData::IP_Number].ip_protocol = ip_protocol->ip_protocol;

	//�����Э����
	if (ip_protocol->ip_protocol == 6)
		tcp_protocol_packet_callback(argument, packet_header, packet_content);


	CPublicData::IP_Number++;
}

//tcp_cap
void tcp_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	// TODO: �ڴ˴����ʵ�ִ���.
	struct tcp_header* tcp_protocol;/*tcpЭ�����*/
	u_char flags;/*���*/
	int header_length;/*ͷ����*/
	u_short source_port;/*Դ�˿�*/
	u_short destination_port;/*Ŀ�Ķ˿�*/
	u_short windows;/*���ڴ�С*/
	u_short urgent_pointer;/*����ָ��*/
	u_int sequence;/*���к�*/
	u_int acknowledgement;/*ȷ�Ϻ�*/
	u_int16_t checksum; /*�����*/
	tcp_protocol = (struct tcp_header*)(packet_content + 14 + 20);/*���tcp�ײ�����*/

	source_port = ntohs(tcp_protocol->tcp_source_port);/*���Դ�˿ں�*/
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_source_port = source_port;

	destination_port = ntohs(tcp_protocol->tcp_destination_port); /*���Ŀ�Ķ˿ں�*/
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_destination_port = destination_port;

	header_length = tcp_protocol->tcp_offset * 4;/*����ײ�����*/
	CPublicData::tcplist[CPublicData::TCP_Number].header_L = header_length;

	sequence = ntohl(tcp_protocol->tcp_acknowledgement);/*������к�*/
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_acknowledgement = sequence;

	acknowledgement = ntohl(tcp_protocol->tcp_ack);//ȷ�Ϻ�
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_ack = acknowledgement;

	windows = ntohs(tcp_protocol->tcp_windows);//����
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_windows = windows;

	urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);//����ָ���ֶ�
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_urgent_pointer = urgent_pointer;

	flags = tcp_protocol->tcp_flags;//����λ
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_flags = flags;

	checksum = ntohs(tcp_protocol->tcp_checksum);//У���
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_checksum = checksum;

	CPublicData::tcplist[CPublicData::TCP_Number].tcp_reserved = tcp_protocol->tcp_reserved;//�����ֶ�

	
	CPublicData::TCP_Number++;
}

//��ʾ
void CWinpcapDlg::Eth_DisPlay()
{
	// TODO: �ڴ˴����ʵ�ִ���.

	for (int i = 0; i < CPublicData::packet_number; i++) {
		CString str;
		str.Format(_T("%d"), CPublicData::t_eth);
		CPublicData::t_eth++;
		LPCTSTR  pStr = LPCTSTR(str);
		int nRow = CAP_R.InsertItem(i, pStr);

		string dhost = HexToAscii(CPublicData::ethetnetlist[i].ether_dhost);
		CString csName1;
		csName1.Format("%s", dhost.c_str());
		CAP_R.SetItemText(nRow, 1, csName1);

		string shost = HexToAscii(CPublicData::ethetnetlist[i].ether_shost);
		CString csName2;
		csName2.Format("%s", shost.c_str());
		CAP_R.SetItemText(nRow, 2, csName2);


		if (CPublicData::ethetnetlist[i].ether_type == 0x0800) CAP_R.SetItemText(nRow, 3, _T("IPv4Э��"));
		if (CPublicData::ethetnetlist[i].ether_type == 0x0806) CAP_R.SetItemText(nRow, 3, _T("ARPЭ��"));
		if (CPublicData::ethetnetlist[i].ether_type == 0x8035) CAP_R.SetItemText(nRow, 3, _T("RARP Э��"));
	}
	
}

void CWinpcapDlg::IP_Display()
{
	 //TODO: �ڴ˴����ʵ�ִ���.
	
	for (int i = 0; i < CPublicData::IP_Number; i++) {
		CString str;
		str.Format(_T("%d"), CPublicData::t_ip);
		CPublicData::t_ip++;
		LPCTSTR  pStr = LPCTSTR(str);
		int nRow = IP_SHOW.InsertItem(i, pStr);
		//�汾
		CString version;
		version.Format(_T("IPv%d"), CPublicData::iplist[i].ip_version);
		IP_SHOW.SetItemText(nRow, 1, version);
		//�ײ�����
		CString header_L;
		header_L.Format(_T("%d"), CPublicData::iplist[i].ip_header_length);
		IP_SHOW.SetItemText(nRow, 2, header_L);
		// ��������
		CString tos;
		tos.Format(_T("%d"), CPublicData::iplist[i].ip_tos);
		IP_SHOW.SetItemText(nRow, 3, tos);
		//�ܳ���
		CString Toll_L;
		Toll_L.Format(_T("%d"), CPublicData::iplist[i].ip_length);
		IP_SHOW.SetItemText(nRow, 4, Toll_L);
		//��ʶ
		CString ipIDs;
		ipIDs.Format(_T("%d"), CPublicData::iplist[i].ip_id);
		IP_SHOW.SetItemText(nRow, 5, ipIDs);
		//Ƭƫ��
		CString ipoff;
		ipoff.Format(_T("%d"), CPublicData::iplist[i].ip_off);
		IP_SHOW.SetItemText(nRow, 6, ipoff);
		//����ʱ��
		CString tll;
		tll.Format(_T("%d"), CPublicData::iplist[i].ip_ttl);
		IP_SHOW.SetItemText(nRow, 7, tll);
		//�ײ������
		CString isum;
		isum.Format(_T("%d"), CPublicData::iplist[i].ip_checksum);
		IP_SHOW.SetItemText(nRow, 8, isum);
		//ԴIP
		CString s_ip;
		s_ip.Format("%s", CPublicData::iplist[i].ip_source_address.c_str());
		IP_SHOW.SetItemText(nRow, 9, s_ip);
		//Ŀ��IP
		CString d_ip;
		d_ip.Format("%s", CPublicData::iplist[i].ip_destination_address.c_str());
		IP_SHOW.SetItemText(nRow, 10, d_ip);
		//Э���

		switch (CPublicData::iplist[i].ip_protocol)
		{
		case 6:
			IP_SHOW.SetItemText(nRow, 11, _T("TCP"));
			//tcp_protocol_packet_callback(argument, packet_header, packet_content);
			break; /*Э��������6����TCP*/
		case 17:
			IP_SHOW.SetItemText(nRow, 11, _T("UDP"));
			break;/*17����UDP*/
		case 1:
			IP_SHOW.SetItemText(nRow, 11, _T("ICMP"));
			break;/*����ICMP*/
		case 2:
			IP_SHOW.SetItemText(nRow, 11, _T("IGMP"));
			break;/*����IGMP*/
		default:break;
		}
	}
}

void CWinpcapDlg::TCP_Display()
{
	// TODO: �ڴ˴����ʵ�ִ���.

	for (int i = 0; i < CPublicData::TCP_Number; i++) {
		CString str;
		str.Format(_T("%d"), CPublicData::t_tcp);
		CPublicData::t_tcp++;
		LPCTSTR  pStr = LPCTSTR(str);
		int nRow = TCP_SHOW.InsertItem(i, pStr);
		//Դ�˿�
		CString sp_id;
		sp_id.Format(_T("%d"), CPublicData::tcplist[i].tcp_source_port);
		TCP_SHOW.SetItemText(nRow, 1, sp_id);
		//Ŀ�Ķ˿�
		CString d_id;
		d_id.Format(_T("%d"), CPublicData::tcplist[i].tcp_destination_port);
		TCP_SHOW.SetItemText(nRow, 2, d_id);
		//Ӧ�ò�Э��
		int min = (CPublicData::tcplist[i].tcp_destination_port < CPublicData::tcplist[i].tcp_source_port) ? CPublicData::tcplist[i].tcp_destination_port : CPublicData::tcplist[i].tcp_source_port;
		switch (min)
		{
		case 80:
			TCP_SHOW.SetItemText(nRow, 3, _T("HTTP"));
			break;

		case 21:
			TCP_SHOW.SetItemText(nRow, 3, _T("FTP"));
			break;

		case 23:
			TCP_SHOW.SetItemText(nRow, 3, _T("Tel"));
			break;

		case 25:
			TCP_SHOW.SetItemText(nRow, 3, _T("SMTP"));
			break;

		case 110:
			TCP_SHOW.SetItemText(nRow, 3, _T("pop3"));
			break;

		case 443:
			TCP_SHOW.SetItemText(nRow, 3, _T("HTTPS"));
			break;

		default:
			break;
		}
		//���к�
		CString sq;
		sq.Format(_T("%u"), CPublicData::tcplist[i].tcp_acknowledgement);
		TCP_SHOW.SetItemText(nRow, 4, sq);
		//ȷ�Ϻ�
		CString ack;
		ack.Format(_T("%u"), CPublicData::tcplist[i].tcp_ack);
		TCP_SHOW.SetItemText(nRow, 5, ack);
		//�ײ�����
		CString h_L;
		h_L.Format(_T("%d"), CPublicData::tcplist[i].header_L);
		TCP_SHOW.SetItemText(nRow, 6, h_L);
		//�����ֶ�
		CString R;
		R.Format(_T("%d"), CPublicData::tcplist[i].tcp_reserved);
		TCP_SHOW.SetItemText(nRow, 7, R);
		//����λ
		if (CPublicData::tcplist[i].tcp_flags & 0x08) TCP_SHOW.SetItemText(nRow, 8, _T("PSH"));
		if (CPublicData::tcplist[i].tcp_flags & 0x10) TCP_SHOW.SetItemText(nRow, 8, _T("ACK"));
		if (CPublicData::tcplist[i].tcp_flags & 0x02) TCP_SHOW.SetItemText(nRow, 8, _T("SYN"));
		if (CPublicData::tcplist[i].tcp_flags & 0x20) TCP_SHOW.SetItemText(nRow, 8, _T("URG"));
		if (CPublicData::tcplist[i].tcp_flags & 0x01) TCP_SHOW.SetItemText(nRow, 8, _T("FIN"));
		if (CPublicData::tcplist[i].tcp_flags & 0x04) TCP_SHOW.SetItemText(nRow, 8, _T("RST"));
		//���ڴ�С
		CString w;
		w.Format(_T("%d"), CPublicData::tcplist[i].tcp_windows);
		TCP_SHOW.SetItemText(nRow, 9, w);
		//�����
		CString isum;
		isum.Format(_T("%d"), CPublicData::tcplist[i].tcp_checksum);
		TCP_SHOW.SetItemText(nRow, 10, isum);
		//����ָ���ֶ�
		CString u;
		u.Format(_T("%d"), CPublicData::tcplist[i].tcp_urgent_pointer);
		TCP_SHOW.SetItemText(nRow, 11, u);


	}
}

//ץ���߳�
UINT MyThreadFunction(LPVOID pParam) {
	pcap_loop(CPublicData::my_adhandle, CPublicData::my_cnt, (pcap_handler)ethernet_protocol_packet_callback, NULL);
	return 0;
}

DWORD WINAPI  ThreadFunction(LPVOID lpParam) {
	while (1)
	{
		CPublicData::packet_number = 0;
		CPublicData::IP_Number = 0;
		CPublicData::TCP_Number = 0;
		pcap_loop(CPublicData::my_adhandle, CPublicData::my_cnt, (pcap_handler)ethernet_protocol_packet_callback, NULL);
		Sleep(1500);
	}
	
	return 0;
}

void CWinpcapDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	
	Eth_DisPlay();
	IP_Display();
	TCP_Display();
	CDialogEx::OnTimer(nIDEvent);
}

void CWinpcapDlg::OnBnClickedclose()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	KillTimer(1);
	CloseHandle(m_hThread);
}

string CWinpcapDlg::HexToAscii(unsigned char* r)
{
	// TODO: �ڴ˴����ʵ�ִ���.
	string t;
	for (int i = 0; i < 6; i++) {
		t.push_back(MyMap[(r[i] & 0xF0) >> 4]);
		t.push_back(MyMap[(r[i] & 0x0F)]);
		t.push_back(':');
	}
	t.pop_back();
	return t;
}