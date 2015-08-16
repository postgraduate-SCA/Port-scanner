#include <stdio.h>
//#include <windows.h>
#include "inisock.h"
#include "resource.h"
#include "IPHlpApi.h"
#include  <commctrl.h>
#include <tlhelp32.h>
#include <conio.h>
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib,"IPHlpApi.Lib")
CInitSock thesock;//初始化winsock库

typedef struct mainthreadparam //主扫描线程参数结构体
{   
	DWORD sip;
	DWORD eip;
	DWORD sp;
	DWORD ep;
	HANDLE hcopyevent; //通知父线程参数复制完毕
}MPARAM;

typedef struct portscanthreadparam //connet线程参数结构体
{
	DWORD dip; //目标IP
	DWORD dp;
	HANDLE hcopyok;
	HANDLE hthreadnum; //信号量对象，通过它实现对线程总数的控制
}PSPARAM;

HINSTANCE hInst;
HWND hdlg2;//扫描窗口句柄
HWND hlist;//系统消息列表框句柄
HWND hlistproc; //进程列表框句柄
LVCOLUMN lvcol,lvcolproc;
LVITEM lvitem,lvitemproc;

LRESULT CALLBACK DlgProc1( HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);//主窗口
LRESULT CALLBACK DlgProc2( HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);//扫描窗口
LRESULT CALLBACK DlgProc3( HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);//主机信息窗口
LRESULT CALLBACK DlgProc4( HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);//本地进程管理窗口
BOOL StartScan(DWORD sip, DWORD eip, DWORD sp, DWORD ep);
DWORD WINAPI MainScanThread(LPVOID lpParam);
DWORD WINAPI PortScanThread(LPVOID lpParam);
BOOL PInfo(char *buf);
void GetSysInfo();
BOOL GetProcInfo();
BOOL DelProc();


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd )
{
	InitCommonControls();
	hInst = hInstance;
	DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG1),NULL,(DLGPROC)DlgProc1);
	return 0;
}

LRESULT CALLBACK DlgProc1( HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_SCAN:
			DialogBox(hInst,MAKEINTRESOURCE(IDD_DIALOG2),NULL,(DLGPROC)DlgProc2);
			break;
		case IDC_INFO:
            DialogBox(hInst,MAKEINTRESOURCE(IDD_DIALOG3),NULL,(DLGPROC)DlgProc3);
			break;
		case IDC_PROCCOL:
			DialogBox(hInst,MAKEINTRESOURCE(IDD_DIALOG4),NULL,(DLGPROC)DlgProc4);

		}
		break;
	case WM_CLOSE:
			EndDialog(hwnd,NULL);
			DestroyWindow(hwnd);
			break;
	default:
		break;
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////
//远程端口扫描部分
//////////////////////////////////////////////////////////////////////////

LRESULT CALLBACK DlgProc2( HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//起止IP
	DWORD sip; 
	DWORD eip;
	//起止端口
	DWORD sp; 
	DWORD ep;
	//判断扫描状态
	BOOL flag = TRUE;
    hdlg2 = hwnd;
	switch(uMsg)
	{
	case WM_INITDIALOG:
	
		break;
	case WM_COMMAND:
		switch(LOWORD(wParam))
		{
		case IDC_BEGIN:
			if(flag)
			{
				SendMessage(GetDlgItem(hwnd,IDC_LIST),LB_RESETCONTENT,NULL,NULL); //清空列表框
                //获得起止IP和起止端口号
				SendMessage(GetDlgItem(hwnd,IDC_IPADDRESS1),IPM_GETADDRESS,NULL,(LPARAM)&sip);
				SendMessage(GetDlgItem(hwnd,IDC_IPADDRESS2),IPM_GETADDRESS,NULL,(LPARAM)&eip);
				sp = GetDlgItemInt(hwnd,IDC_EDIT1,NULL,FALSE);
				ep = GetDlgItemInt(hwnd,IDC_EDIT2,NULL,FALSE);

				//开始扫描
                StartScan(sip,eip,sp,ep);
			}
			break;
		case IDC_EXIT:
			EndDialog(hwnd,NULL);
			DestroyWindow(hwnd);
			break;
		}
		break;
	case WM_CLOSE:
		EndDialog(hwnd,NULL);
		DestroyWindow(hwnd);
		break;
	default:
		break;
	}
	return 0;
}

BOOL StartScan(DWORD sip, DWORD eip, DWORD sp, DWORD ep)
{
	MPARAM mp;
	mp.hcopyevent = CreateEvent(NULL,TRUE,FALSE,NULL);//通过该事件对象通知父线程参数复制完毕
	mp.sip = sip;
	mp.eip = eip;
	mp.sp = sp;
	mp.ep = ep;
    //创建扫描线程
	CreateThread(NULL,NULL,MainScanThread,(LPVOID*)&mp,0,NULL);
	//等待扫描线程中参数复制完毕
	WaitForSingleObject(mp.hcopyevent,INFINITE);
	ResetEvent(mp.hcopyevent);
	return TRUE;
}

DWORD WINAPI MainScanThread(LPVOID lpParam)
{
	MPARAM pmp;
	PSPARAM psp;

	MoveMemory(&pmp,lpParam,sizeof(pmp));
	SetEvent(pmp.hcopyevent);
    psp.hcopyok = CreateEvent(NULL,TRUE,FALSE,NULL);
	//创建一个信号量控制子线程总量，定义总量不超过256
	HANDLE htn = CreateSemaphore(NULL,256,256,NULL);
	psp.hthreadnum = htn;
	//循环创建新线程，在扫描线程中进行connet
	for(DWORD ip = pmp.sip; ip <= pmp.eip; ip++)
	{
		for(DWORD port = pmp.sp; port <= pmp.ep; port++)
		{
			DWORD ret;
			ret = WaitForSingleObject(htn,200);
			if(ret == WAIT_OBJECT_0)
			{
				psp.dip = ip;
				psp.dp = port;
				CreateThread(NULL,NULL,PortScanThread,&psp,0,NULL);
				WaitForSingleObject(psp.hcopyok,INFINITE);
				ResetEvent(psp.hcopyok);
			}
			else if(ret == WAIT_TIMEOUT)
			{
				port--;
				continue;
			}
		}
	}
	return 0;
}

DWORD WINAPI PortScanThread(LPVOID lpParam)
{
	PSPARAM psp;

	MoveMemory(&psp,lpParam,sizeof(psp));
	SetEvent(psp.hcopyok); //参数复制完毕，可以创建下一个线程

	SOCKET sockfd;
	SOCKADDR_IN desaddr;
	sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(sockfd == INVALID_SOCKET)
	{
		MessageBox(NULL,"socket error","error",NULL);
		return 0;	
	}
	desaddr.sin_family = AF_INET;
	desaddr.sin_port = htons(psp.dp);
	desaddr.sin_addr.S_un.S_addr = htonl(psp.dip);
	//转化IP地址为字符串
	char *ip = inet_ntoa(desaddr.sin_addr);
	//连接测试
	char str[200];
	if(connect(sockfd,(SOCKADDR *)&desaddr,sizeof(desaddr)) == 0)
	{
		sprintf(str,"IP: %s  Port: %d  端口开放",ip,psp.dp);
	}
	else
	{
		sprintf(str,"IP: %s  Port: %d  端口关闭",ip,psp.dp);
	}
	//打印结果
	PInfo(str);
	ReleaseSemaphore(psp.hthreadnum,1,NULL);
	closesocket(sockfd);
	return 0;
	
}

BOOL PInfo(char *buf)
{
	SendMessage(GetDlgItem(hdlg2,IDC_LIST),LB_ADDSTRING,NULL,(LPARAM)buf);
	return TRUE;
}

/////////////////////////////////////////////////////////////////////////
//获取系统信息代码部分
////////////////////////////////////////////////////////////////////////

LRESULT CALLBACK DlgProc3( HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    
	char string[10][50] = {"用户名","计算机名","内存信息","处理机数目","系统目录","模式","CPU类型","操作系统版本","物理网卡","无线网卡"};
	int i;

	switch(uMsg)
	{
	case WM_INITDIALOG:
		hlist = GetDlgItem(hwnd,IDC_INFOM);
		ListView_SetExtendedListViewStyle(hlist,LVS_EX_GRIDLINES|LVS_EX_FULLROWSELECT);
		lvcol.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
		lvcol.fmt = LVCFMT_LEFT;
		lvcol.cx = 100;
		lvcol.pszText = "信息类型";
        SendMessage(hlist,LVM_INSERTCOLUMN,0,(LPARAM)&lvcol);
		hlist = GetDlgItem(hwnd,IDC_INFOM);
		lvcol.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
		lvcol.fmt = LVCFMT_LEFT;
		lvcol.cx = 400;
		lvcol.pszText = "值";
        SendMessage(hlist,LVM_INSERTCOLUMN,1,(LPARAM)&lvcol);
		for(i = 0; i < 10; i++)
		{
			lvitem.iItem = i;
			lvitem.iSubItem = 0;
			lvitem.mask = LVIF_TEXT;
			lvitem.pszText = string[i];
			SendMessage(hlist,LVM_INSERTITEM,i,(LPARAM)&lvitem);
		}
        GetSysInfo();
		break;
	case WM_CLOSE:
		EndDialog(hwnd,NULL);
		DestroyWindow(hwnd);
		break;
	default:
		break;
	}
	return 0;
	
}

void GetSysInfo()
{
	char sysinfo[10][200];
	DWORD len;

	//主机用户名
	len = sizeof(sysinfo[0]);
	GetUserName(sysinfo[0],&len);

    //计算机名
	len = sizeof(sysinfo[1]);
	GetComputerName(sysinfo[1],&len);

	//内存信息
	MEMORYSTATUS ms;
	GlobalMemoryStatus(&ms);
	if (ms.dwTotalPhys >= 1000000)
	{
		double mem = (double)ms.dwTotalPhys/(double)1024000000;
		sprintf(sysinfo[2],"%u%%usage (Total:%0.2lfGB)",ms.dwMemoryLoad,mem);
	}
	else
	{
		double mem = (double)ms.dwTotalPhys/(double)1024000;
		sprintf(sysinfo[2],"%u%%usage (Total:%0.2lfMB)",ms.dwMemoryLoad,mem);
	}

	//处理机数目
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	sprintf(sysinfo[3],"%d",si.dwNumberOfProcessors);

	//系统目录
	GetSystemDirectory(sysinfo[4],sizeof(sysinfo[4]));

	//模式
	HKEY hKey;
	int nRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",NULL,KEY_READ,&hKey);
	if (nRet != ERROR_SUCCESS)
	{
		memcpy(sysinfo[5],"NULL",sizeof(sysinfo[5]));
	}
	int dwSize = sizeof(sysinfo[5]);
	nRet = RegQueryValueEx(hKey,TEXT("Identifier"),NULL,NULL,(unsigned char*)sysinfo[5],(LPDWORD)&dwSize);
	if (nRet != ERROR_SUCCESS)
	{
		memcpy(sysinfo[5],"NULL",sizeof(sysinfo[5]));
	}

    //CPU类型
    nRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",NULL,KEY_READ,&hKey);
	if (nRet != ERROR_SUCCESS)
	{
		memcpy(sysinfo[6],"NULL",sizeof(sysinfo[6]));
	}
    dwSize = sizeof(sysinfo[6]);
	nRet = RegQueryValueEx(hKey,TEXT("ProcessorNameString"),NULL,NULL,(unsigned char*)sysinfo[6],(LPDWORD)&dwSize);
	if (nRet != ERROR_SUCCESS)
	{
		memcpy(sysinfo[6],"NULL",sizeof(sysinfo[6]));
	}

	//系统版本
	nRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,"Software\\Microsoft\\Windows NT\\CurrentVersion",NULL,KEY_READ,&hKey);
	if (nRet != ERROR_SUCCESS)
	{
		memcpy(sysinfo[7],"NULL",sizeof(sysinfo[7]));
	}
    dwSize = sizeof(sysinfo[7]);
	nRet = RegQueryValueEx(hKey,TEXT("ProductName"),NULL,NULL,(unsigned char*)sysinfo[7],(LPDWORD)&dwSize);
	if (nRet != ERROR_SUCCESS)
	{
		memcpy(sysinfo[7],"NULL",sizeof(sysinfo[7]));
	}

   //网卡信息
   	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	ULONG ulOutBufLen;
	pAdapterInfo=(PIP_ADAPTER_INFO)malloc(sizeof(IP_ADAPTER_INFO));
    ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	if (GetAdaptersInfo( pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *) malloc (ulOutBufLen); 
	}
	
	if ((dwRetVal = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		while(pAdapter)
		{
			if(strstr(pAdapter->Description,"PCI")>0) //pAdapter->Description中包含"PCI"为：物理网卡
			sprintf(sysinfo[8],"%s",pAdapter->Description);
			if(pAdapter->Type == 71)//是71为：无线网卡
			sprintf(sysinfo[9],"%s",pAdapter->Description);
			pAdapter = pAdapter->Next;
		}
	}
	for(int i = 0; i < 10; i++)
	{
		lvitem.iItem = i;
		lvitem.iSubItem = 1;
		lvitem.mask = LVIF_TEXT;
		lvitem.pszText = sysinfo[i];
	    SendMessage(hlist,LVM_SETITEMTEXT,i,(LPARAM)&lvitem);
	}
}

/////////////////////////////////////////////////////////////
//本地进程管理部分
///////////////////////////////////////////////////////////

LRESULT CALLBACK DlgProc4( HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
		case WM_INITDIALOG:
			hlistproc = GetDlgItem(hwnd,IDC_PROC);
			ListView_SetExtendedListViewStyle(hlistproc,LVS_EX_GRIDLINES|LVS_EX_FULLROWSELECT);
			lvcolproc.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
			lvcolproc.fmt = LVCFMT_LEFT;
			lvcolproc.cx = 50;
			lvcolproc.pszText = "PID";
			SendMessage(hlistproc,LVM_INSERTCOLUMN,0,(LPARAM)&lvcolproc);
			hlist = GetDlgItem(hwnd,IDC_PROC);
			lvcolproc.mask = LVCF_TEXT|LVCF_FMT|LVCF_WIDTH;
			lvcolproc.fmt = LVCFMT_LEFT;
			lvcolproc.cx = 250;
			lvcolproc.pszText = "进程名称";
            SendMessage(hlistproc,LVM_INSERTCOLUMN,1,(LPARAM)&lvcolproc);
            GetProcInfo();
			break;
		case WM_COMMAND:
			{
				switch (LOWORD(wParam))
				{
				case IDC_DELETE:
					 DelProc();
			         break;
				}
			}
			break;
		case WM_CLOSE:
			EndDialog(hwnd,NULL);
			DestroyWindow(hwnd);
			break;
		default:
		    break;
	}
	return 0;
}

//枚举进程
BOOL GetProcInfo()
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	//对系统进程拍快照
	HANDLE hps = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(hps == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL,"进程快照失败","错误",MB_OK);
		return FALSE;
	}
	//遍历进程
	int pnum = 0; //记录进程总数
	BOOL flag = Process32First(hps, &pe32);
	while(flag)
	{
		char pid[10];
		sprintf(pid,"%u",pe32.th32ProcessID);
		lvitemproc.iItem = pnum;
		lvitemproc.iSubItem = 0;
		lvitemproc.mask = LVIF_TEXT;
		lvitemproc.pszText = pid;
		SendMessage(hlistproc,LVM_INSERTITEM,pnum,(LPARAM)&lvitemproc);
		lvitemproc.iItem = pnum;
		lvitemproc.iSubItem = 1;
		lvitemproc.mask = LVIF_TEXT;
		lvitemproc.pszText = pe32.szExeFile;
	    SendMessage(hlist,LVM_SETITEMTEXT,pnum,(LPARAM)&lvitemproc);
		flag = Process32Next(hps, &pe32);
		pnum++;
	}
	return TRUE;
}

//删除指定进程
BOOL DelProc()
{
	int index = ListView_GetSelectionMark(hlistproc);
	char pid[10];
	ListView_GetItemText(hlistproc,index,0,pid,sizeof(pid));
	int numid = atoi(pid);
	HANDLE hphandle = OpenProcess(PROCESS_ALL_ACCESS,FALSE,(DWORD)numid);
	if(hphandle)
	{
		BOOL ret = TerminateProcess(hphandle,NULL);
		if(ret)
		{
			CloseHandle(hphandle);
			ListView_DeleteItem(hlistproc,index);
		}
	}
	else
	{
		MessageBox(NULL,"进程删除失败","错误",MB_OK);
		return FALSE;
	}
	return TRUE;	
}
