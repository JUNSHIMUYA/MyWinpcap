
// WinpcapDlg.cpp: 实现文件
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


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	// 实现
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


// CWinpcapDlg 对话框



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


// CWinpcapDlg 消息处理程序


BOOL CWinpcapDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。
	// TODO: 在此添加额外的初始化代码

	//网卡
	// 样式设置为整行选择、网格线
	m_listc1.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_listc1.InsertColumn(0, _T("序 号"), LVCFMT_CENTER, 100);
	m_listc1.InsertColumn(1, _T("网卡号"), LVCFMT_CENTER, 360);
	m_listc1.InsertColumn(2, _T("备注"), LVCFMT_CENTER, 320);

	//数据链路层
	// 样式设置为整行选择、网格线
	CAP_R.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	CAP_R.InsertColumn(0, _T("序 号"), LVCFMT_CENTER, 200);
	CAP_R.InsertColumn(1, _T("目的MAC地址"), LVCFMT_CENTER, 200);
	CAP_R.InsertColumn(2, _T("源MAC地址"), LVCFMT_CENTER, 200);
	CAP_R.InsertColumn(3, _T("网络层协议"), LVCFMT_CENTER, 200);

	//网络层
	// 样式设置为整行选择、网格线
	IP_SHOW.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	IP_SHOW.InsertColumn(0, _T("序 号"), LVCFMT_CENTER, 50);
	IP_SHOW.InsertColumn(1, _T("IP版本"), LVCFMT_CENTER, 70);
	IP_SHOW.InsertColumn(2, _T("首部长度"), LVCFMT_CENTER, 70);
	IP_SHOW.InsertColumn(3, _T("服务类型"), LVCFMT_CENTER, 70);
	IP_SHOW.InsertColumn(4, _T("总长度"), LVCFMT_CENTER, 50);
	IP_SHOW.InsertColumn(5, _T("标识"), LVCFMT_CENTER, 50);
	IP_SHOW.InsertColumn(6, _T("片偏移"), LVCFMT_CENTER, 50);
	IP_SHOW.InsertColumn(7, _T("生存时间"), LVCFMT_CENTER, 100);
	IP_SHOW.InsertColumn(8, _T("首部检验和"), LVCFMT_CENTER, 100);
	IP_SHOW.InsertColumn(9, _T("源IP"), LVCFMT_CENTER, 125);
	IP_SHOW.InsertColumn(10, _T("目的IP"), LVCFMT_CENTER, 125);
	IP_SHOW.InsertColumn(11, _T("传输层协议"), LVCFMT_CENTER, 100);

	//传输层
	TCP_SHOW.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	TCP_SHOW.InsertColumn(0, _T("序 号"), LVCFMT_CENTER, 40);
	TCP_SHOW.InsertColumn(1, _T("源端口"), LVCFMT_CENTER, 50);
	TCP_SHOW.InsertColumn(2, _T("目的端口"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(3, _T("应用层协议"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(4, _T("序列号"), LVCFMT_CENTER, 100);
	TCP_SHOW.InsertColumn(5, _T("确认号"), LVCFMT_CENTER, 100);
	TCP_SHOW.InsertColumn(6, _T("首部长度"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(7, _T("保留字段"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(8, _T("控制位"), LVCFMT_CENTER, 50);
	TCP_SHOW.InsertColumn(9, _T("窗口大小"), LVCFMT_CENTER, 80);
	TCP_SHOW.InsertColumn(10, _T("检验和"), LVCFMT_CENTER, 50);
	TCP_SHOW.InsertColumn(11, _T("紧急指针字段"), LVCFMT_CENTER, 130);


	pcap_findalldevs(&alldevs, errbuf);
	/* 打印网卡信息 */
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

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CWinpcapDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CWinpcapDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CWinpcapDlg::OnBnClickedBucap()
{
	// TODO: 在此添加控件通知处理程序代码

	for (int i = 0; i < 26; i++) {
		MyMap[i] = char(i + '0');
	}
	MyMap[10] = 'A';
	MyMap[11] = 'B';
	MyMap[12] = 'C';
	MyMap[13] = 'D';
	MyMap[14] = 'E';
	MyMap[15] = 'F';

	//选择网卡
	CEdit* pBoxOne;
	pBoxOne = (CEdit*)GetDlgItem(WK_ID);
	//取值
	pBoxOne->GetWindowText(w_id);
	//处理选择的网卡
	inum = _ttoi(w_id);
	MessageBox(_T("选择网卡成功"), _T("提示"), MB_OK);
	w_id.ReleaseBuffer();
	
	CPublicData::my_cnt =10; //每次抓包数量

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
		MessageBox(_T("无法打开适配器"), _T("提示"), MB_OK);
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


	u_short ethernet_type;/*以太网协议类型*/
	struct ethernet_header* ethernet_protocol;/*以太网协议变量*/

	ethernet_protocol = (struct ethernet_header*)packet_content;/*获得一太网协议数据内容*/
	ethernet_type = ntohs(ethernet_protocol->ether_type); /*获得以太网类型*/

	
	CPublicData::ethetnetlist[CPublicData::packet_number].ether_type = ethernet_type;

	for (int i = 0; i < 6; i++) {
		CPublicData::ethetnetlist[CPublicData::packet_number].ether_dhost[i] = ethernet_protocol->ether_dhost[i];
		CPublicData::ethetnetlist[CPublicData::packet_number].ether_shost[i] = ethernet_protocol->ether_shost[i];
	}

	switch (ethernet_type)
	{
	case 0x0800:/*如果上层是IPv4ip协议,就调用分析ip协议的函数对ip包进行贩治*/
		ip_protocol_packet_callback(argument, packet_header, packet_content);
		break;
	default:break;
	}

	CPublicData::packet_number++;
}

 //ip_cap
void ip_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	// TODO: 在此处添加实现代码.

	struct ip_header* ip_protocol;/*ip协议变量*/
	u_int header_length;/*长度*/
	u_int offset;/*片偏移*/
	u_char tos;/*服务类型*/
	u_int16_t checksum;/*首部检验和*/
	ip_protocol = (struct ip_header*)(packet_content + 14); /*获得ip数据包的内容去掉以太头部*/
	checksum = ntohs(ip_protocol->ip_checksum);/*获得校验和*/
	header_length = ip_protocol->ip_header_length * 4; /*获得长度*/
	tos = ip_protocol->ip_tos;/*获得tos*/
	offset = ntohs(ip_protocol->ip_off);/*获得偏移量*/

	//printf("IP版本:\t\tIPv%d\n", ip_protocol->ip_version);
	CPublicData::iplist[CPublicData::IP_Number].ip_version = ip_protocol->ip_version;
	//printf("IP协议首部长度:\t%d\n", header_length);
	CPublicData::iplist[CPublicData::IP_Number].ip_header_length = header_length;
	//printf("服务类型:\t%d\n", tos);
	CPublicData::iplist[CPublicData::IP_Number].ip_tos = tos;
	//printf("总长度:\t\t%d\n", ntohs(ip_protocol->ip_length));/*获得总长度*/
	CPublicData::iplist[CPublicData::IP_Number].ip_length = ntohs(ip_protocol->ip_length);
	//printf("标识:\t\t%d\n", ntohs(ip_protocol->ip_id));/*获得标识*/
	CPublicData::iplist[CPublicData::IP_Number].ip_id = ntohs(ip_protocol->ip_id);
	//printf("片偏移:\t\t%d\n", (offset & 0x1fff) * 8);/**/
	CPublicData::iplist[CPublicData::IP_Number].ip_off = (offset & 0x1fff) * 8;
	//printf("生存时间:\t%d\n", ip_protocol->ip_ttl);/*获得ttl*/
	CPublicData::iplist[CPublicData::IP_Number].ip_ttl = ip_protocol->ip_ttl;
	//printf("首部检验和:\t%d\n", checksum);
	CPublicData::iplist[CPublicData::IP_Number].ip_checksum = checksum;
	//printf("源IP:\t%s\n", inet_ntoa(ip_protocol->ip_source_address));/*获得源ip地址*/
	CPublicData::iplist[CPublicData::IP_Number].ip_source_address = (string)inet_ntoa(ip_protocol->ip_source_address);
	//printf("目的IP:\t%s\n", inet_ntoa(ip_protocol->ip_destination_address));/*获得目的ip地址*/
	CPublicData::iplist[CPublicData::IP_Number].ip_destination_address = (string)inet_ntoa(ip_protocol->ip_destination_address);
	//printf("协议号:\t%d\n", ip_protocol->ip_protocol);/*获得协议类型*/
	CPublicData::iplist[CPublicData::IP_Number].ip_protocol = ip_protocol->ip_protocol;

	//传输层协议是
	if (ip_protocol->ip_protocol == 6)
		tcp_protocol_packet_callback(argument, packet_header, packet_content);


	CPublicData::IP_Number++;
}

//tcp_cap
void tcp_protocol_packet_callback(u_char* argument, struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	// TODO: 在此处添加实现代码.
	struct tcp_header* tcp_protocol;/*tcp协议变量*/
	u_char flags;/*标记*/
	int header_length;/*头长度*/
	u_short source_port;/*源端口*/
	u_short destination_port;/*目的端口*/
	u_short windows;/*窗口大小*/
	u_short urgent_pointer;/*紧急指针*/
	u_int sequence;/*序列号*/
	u_int acknowledgement;/*确认号*/
	u_int16_t checksum; /*检验和*/
	tcp_protocol = (struct tcp_header*)(packet_content + 14 + 20);/*获得tcp首部内容*/

	source_port = ntohs(tcp_protocol->tcp_source_port);/*获得源端口号*/
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_source_port = source_port;

	destination_port = ntohs(tcp_protocol->tcp_destination_port); /*获得目的端口号*/
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_destination_port = destination_port;

	header_length = tcp_protocol->tcp_offset * 4;/*获得首部长度*/
	CPublicData::tcplist[CPublicData::TCP_Number].header_L = header_length;

	sequence = ntohl(tcp_protocol->tcp_acknowledgement);/*获得序列号*/
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_acknowledgement = sequence;

	acknowledgement = ntohl(tcp_protocol->tcp_ack);//确认号
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_ack = acknowledgement;

	windows = ntohs(tcp_protocol->tcp_windows);//窗口
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_windows = windows;

	urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);//紧急指针字段
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_urgent_pointer = urgent_pointer;

	flags = tcp_protocol->tcp_flags;//控制位
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_flags = flags;

	checksum = ntohs(tcp_protocol->tcp_checksum);//校验和
	CPublicData::tcplist[CPublicData::TCP_Number].tcp_checksum = checksum;

	CPublicData::tcplist[CPublicData::TCP_Number].tcp_reserved = tcp_protocol->tcp_reserved;//保留字段

	
	CPublicData::TCP_Number++;
}

//显示
void CWinpcapDlg::Eth_DisPlay()
{
	// TODO: 在此处添加实现代码.

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


		if (CPublicData::ethetnetlist[i].ether_type == 0x0800) CAP_R.SetItemText(nRow, 3, _T("IPv4协议"));
		if (CPublicData::ethetnetlist[i].ether_type == 0x0806) CAP_R.SetItemText(nRow, 3, _T("ARP协议"));
		if (CPublicData::ethetnetlist[i].ether_type == 0x8035) CAP_R.SetItemText(nRow, 3, _T("RARP 协议"));
	}
	
}

void CWinpcapDlg::IP_Display()
{
	 //TODO: 在此处添加实现代码.
	
	for (int i = 0; i < CPublicData::IP_Number; i++) {
		CString str;
		str.Format(_T("%d"), CPublicData::t_ip);
		CPublicData::t_ip++;
		LPCTSTR  pStr = LPCTSTR(str);
		int nRow = IP_SHOW.InsertItem(i, pStr);
		//版本
		CString version;
		version.Format(_T("IPv%d"), CPublicData::iplist[i].ip_version);
		IP_SHOW.SetItemText(nRow, 1, version);
		//首部长度
		CString header_L;
		header_L.Format(_T("%d"), CPublicData::iplist[i].ip_header_length);
		IP_SHOW.SetItemText(nRow, 2, header_L);
		// 服务类型
		CString tos;
		tos.Format(_T("%d"), CPublicData::iplist[i].ip_tos);
		IP_SHOW.SetItemText(nRow, 3, tos);
		//总长度
		CString Toll_L;
		Toll_L.Format(_T("%d"), CPublicData::iplist[i].ip_length);
		IP_SHOW.SetItemText(nRow, 4, Toll_L);
		//标识
		CString ipIDs;
		ipIDs.Format(_T("%d"), CPublicData::iplist[i].ip_id);
		IP_SHOW.SetItemText(nRow, 5, ipIDs);
		//片偏移
		CString ipoff;
		ipoff.Format(_T("%d"), CPublicData::iplist[i].ip_off);
		IP_SHOW.SetItemText(nRow, 6, ipoff);
		//生存时间
		CString tll;
		tll.Format(_T("%d"), CPublicData::iplist[i].ip_ttl);
		IP_SHOW.SetItemText(nRow, 7, tll);
		//首部检验和
		CString isum;
		isum.Format(_T("%d"), CPublicData::iplist[i].ip_checksum);
		IP_SHOW.SetItemText(nRow, 8, isum);
		//源IP
		CString s_ip;
		s_ip.Format("%s", CPublicData::iplist[i].ip_source_address.c_str());
		IP_SHOW.SetItemText(nRow, 9, s_ip);
		//目的IP
		CString d_ip;
		d_ip.Format("%s", CPublicData::iplist[i].ip_destination_address.c_str());
		IP_SHOW.SetItemText(nRow, 10, d_ip);
		//协议号

		switch (CPublicData::iplist[i].ip_protocol)
		{
		case 6:
			IP_SHOW.SetItemText(nRow, 11, _T("TCP"));
			//tcp_protocol_packet_callback(argument, packet_header, packet_content);
			break; /*协议类型是6代表TCP*/
		case 17:
			IP_SHOW.SetItemText(nRow, 11, _T("UDP"));
			break;/*17代表UDP*/
		case 1:
			IP_SHOW.SetItemText(nRow, 11, _T("ICMP"));
			break;/*代表ICMP*/
		case 2:
			IP_SHOW.SetItemText(nRow, 11, _T("IGMP"));
			break;/*代表IGMP*/
		default:break;
		}
	}
}

void CWinpcapDlg::TCP_Display()
{
	// TODO: 在此处添加实现代码.

	for (int i = 0; i < CPublicData::TCP_Number; i++) {
		CString str;
		str.Format(_T("%d"), CPublicData::t_tcp);
		CPublicData::t_tcp++;
		LPCTSTR  pStr = LPCTSTR(str);
		int nRow = TCP_SHOW.InsertItem(i, pStr);
		//源端口
		CString sp_id;
		sp_id.Format(_T("%d"), CPublicData::tcplist[i].tcp_source_port);
		TCP_SHOW.SetItemText(nRow, 1, sp_id);
		//目的端口
		CString d_id;
		d_id.Format(_T("%d"), CPublicData::tcplist[i].tcp_destination_port);
		TCP_SHOW.SetItemText(nRow, 2, d_id);
		//应用层协议
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
		//序列号
		CString sq;
		sq.Format(_T("%u"), CPublicData::tcplist[i].tcp_acknowledgement);
		TCP_SHOW.SetItemText(nRow, 4, sq);
		//确认号
		CString ack;
		ack.Format(_T("%u"), CPublicData::tcplist[i].tcp_ack);
		TCP_SHOW.SetItemText(nRow, 5, ack);
		//首部长度
		CString h_L;
		h_L.Format(_T("%d"), CPublicData::tcplist[i].header_L);
		TCP_SHOW.SetItemText(nRow, 6, h_L);
		//保留字段
		CString R;
		R.Format(_T("%d"), CPublicData::tcplist[i].tcp_reserved);
		TCP_SHOW.SetItemText(nRow, 7, R);
		//控制位
		if (CPublicData::tcplist[i].tcp_flags & 0x08) TCP_SHOW.SetItemText(nRow, 8, _T("PSH"));
		if (CPublicData::tcplist[i].tcp_flags & 0x10) TCP_SHOW.SetItemText(nRow, 8, _T("ACK"));
		if (CPublicData::tcplist[i].tcp_flags & 0x02) TCP_SHOW.SetItemText(nRow, 8, _T("SYN"));
		if (CPublicData::tcplist[i].tcp_flags & 0x20) TCP_SHOW.SetItemText(nRow, 8, _T("URG"));
		if (CPublicData::tcplist[i].tcp_flags & 0x01) TCP_SHOW.SetItemText(nRow, 8, _T("FIN"));
		if (CPublicData::tcplist[i].tcp_flags & 0x04) TCP_SHOW.SetItemText(nRow, 8, _T("RST"));
		//窗口大小
		CString w;
		w.Format(_T("%d"), CPublicData::tcplist[i].tcp_windows);
		TCP_SHOW.SetItemText(nRow, 9, w);
		//检验和
		CString isum;
		isum.Format(_T("%d"), CPublicData::tcplist[i].tcp_checksum);
		TCP_SHOW.SetItemText(nRow, 10, isum);
		//紧急指针字段
		CString u;
		u.Format(_T("%d"), CPublicData::tcplist[i].tcp_urgent_pointer);
		TCP_SHOW.SetItemText(nRow, 11, u);


	}
}

//抓包线程
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
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	
	Eth_DisPlay();
	IP_Display();
	TCP_Display();
	CDialogEx::OnTimer(nIDEvent);
}

void CWinpcapDlg::OnBnClickedclose()
{
	// TODO: 在此添加控件通知处理程序代码
	KillTimer(1);
	CloseHandle(m_hThread);
}

string CWinpcapDlg::HexToAscii(unsigned char* r)
{
	// TODO: 在此处添加实现代码.
	string t;
	for (int i = 0; i < 6; i++) {
		t.push_back(MyMap[(r[i] & 0xF0) >> 4]);
		t.push_back(MyMap[(r[i] & 0x0F)]);
		t.push_back(':');
	}
	t.pop_back();
	return t;
}