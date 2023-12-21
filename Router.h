#pragma once
#include "pcap.h"
#include<ctime>
#pragma warning(disable:4996)
char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
pcap_if_t* alldevs;	//指向设备链表首部的指针
pcap_t* chowang;//选择打开的网卡
BYTE mymac[6];//网卡设备的mac地址
BYTE desmac[6];
int arp_num = 0;//arp表项个数
BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };//广播地址
//路由表的初始数据项
char MyIP[2][INET_ADDRSTRLEN]; //本机IP
char Mymask[2][INET_ADDRSTRLEN]; //本机掩码
#pragma pack(1)//以1byte方式对齐
typedef struct FrameHeader_t //帧首部
{
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;
typedef struct ARPFrame_t //ARP报文首部
{
	FrameHeader_t FrameHeader;//帧首部
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址
	WORD Operation;//操作
	BYTE SendMAC[6];//发送方MAC
	DWORD SendIP;//发送方IP
	BYTE RecvMAC[6];//接收方MAC
	DWORD RecvIP;//接收方IP
}ARPFrame_t;
typedef struct IPHeader_t //IP首部
{
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;//生命周期
	BYTE Protocol;
	WORD Checksum;//校验和
	ULONG SrcIP;//源IP
	ULONG DstIP;//目的IP
}IPHeader_t;
typedef struct Data_t //帧首部和IP首部的数据包
{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}Data_t;
typedef struct SendPacket_t //缓冲区发送的数据包结构
{
	BYTE PktData[2000];// 数据缓存
	ULONG TargetIP; // 目的IP地址
	bool flag = 1; // 是否有效，如果已经被转发或者超时，则置0
	clock_t t; // 判断是否超时，超时则删除
} SendPacket_t;
//#pragma pack()//恢复4bytes对齐
SendPacket_t Buffer[50];//缓冲区
int bufsize = 0; //缓冲区大小
void print_MAC(byte* MAC)//打印MAC地址
{
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}
void print_IP(unsigned long u)//打印IP地址
{
	in_addr addr;
	memcpy(&addr, &u, sizeof(u));
	printf("%s  ", inet_ntoa(addr));
}
void print_IPRecord(Data_t* data)//打印IP数据包
{
	printf("帧首部-源MAC地址：");
	print_MAC(data->FrameHeader.SrcMAC);
	printf("帧首部-目的MAC地址：");
	print_MAC(data->FrameHeader.DesMAC);
	printf("IP首部-源IP地址：");
	print_IP(data->IPHeader.SrcIP);
	printf("\nIP首部-目的IP地址");
	print_IP(data->IPHeader.DstIP);
	printf("\n");
}
void print_ARPRecord(ARPFrame_t* data)//打印ARP数据包
{
	printf("帧首部-源MAC地址：");
	print_MAC(data->FrameHeader.SrcMAC);
	printf("帧首部-目的MAC地址：");
	print_MAC(data->FrameHeader.DesMAC);
	printf("arp内容-源IP地址：");
	print_IP(data->SendIP);
	printf("\narp内容-目的IP地址：");
	print_IP(data->RecvIP);
	printf("\n");
}
class RouteItem //路由表表项
{
public:
	DWORD mask;//掩码
	DWORD net;//目的网络
	DWORD nextip;//下一跳
	int index;//索引
	int type;//0为直接连接，1为用户添加
	RouteItem* nextitem;//采用链表形式存储
	RouteItem()
	{
		memset(this, 0, sizeof(*this));//初始化为全0
	}
	//打印表项内容，打印出掩码、目的网络和下一跳IP、类型（是否是直接投递）
	void print()
	{
		printf("第%d个：", index);
		printf("掩码：");
		print_IP(mask);
		printf("\t目标网络：");
		print_IP(net);
		printf("\n       下一跳：");
		print_IP(nextip);
		printf("\t类型：");
		if (type == 0) printf("direct\n");
		else printf("add\n");
	}
};
class RouteTable //路由表
{
public:
	RouteItem* head, * tail;//支持最多添加50转发表
	int num;//条数
	RouteTable()//初始化，添加直接连接的网络
	{
		head = new RouteItem;
		head->nextitem = tail;
		num = 0;
		for (int i = 0; i < 2; i++)
		{
			RouteItem* temp = new RouteItem;
			temp->net = (inet_addr(MyIP[i])) & (inet_addr(Mymask[i]));//本机网卡的ip和掩码进行按位与即为所在网络
			temp->mask = inet_addr(Mymask[i]);
			temp->type = 0;//0表示直接投递的网络，不可删除
			this->add(temp);//添加表项
		}
	};
	void add(RouteItem* a)//添加 直接投递在最前，最长匹配原则前缀长的在前面
	{
		RouteItem* pointer;//用于查找插入位置的指针
		if (a->type == 0)//默认路由 初始化时添加直接投递
		{
			a->nextitem = head->nextitem;
			head->nextitem = a;
			a->type = 0;
			printf("已插入0\n");
		}
		else//type==1，非直接投递
		{
			for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)//遍历路由表
				if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask) break;//掩码大于pointer指针指向的掩码，小于下一项的掩码，匹配
			if (pointer->nextitem == NULL)//插入
			{
				a->nextitem = pointer->nextitem;
				pointer->nextitem = a;
				a->type = 1;
				printf("已插入");
			}
			else
			{
				a->nextitem = pointer->nextitem;
				pointer->nextitem = a;
			}
		}
		RouteItem* p = head->nextitem;
		for (int i = 0; p != tail; p = p->nextitem, i++)//重排序号
		{
			p->index = i;
		}
		num++;//表项数+1
	}
	void remove(int index)//删除 type=0不能删除
	{
		for (RouteItem* t = head; t->nextitem != tail; t = t->nextitem)
		{
			if (t->nextitem->index == index)
			{
				if (t->nextitem->type == 0)
				{
					printf("默认路由不可删除！\n");
					return;
				}
				else
				{
					t->nextitem = t->nextitem->nextitem;
					printf("已删除！\n");
					return;
				}
			}
		}
		printf("未查找到该表项！\n");
	}
	void print()//打印 遍历表项调用表项的print函数
	{
		for (RouteItem* t = head->nextitem; t != tail; t = t->nextitem)
		{
			t->print();
		}
		printf("\n");
	}
	DWORD find(DWORD ip) //查找 最长匹配原则,返回下一跳的ip
	{
		DWORD result = -1;
		for (RouteItem* t = head->nextitem; t != tail; t = t->nextitem)
		{
			result = ip & t->mask;
			if (result == t->net)
			{
				if (t->type != 0)
				{
					print_IP(t->nextip);
					return t->nextip;//转发
				}
				else
				{
					print_IP(ip);
					return ip;//直接投递
				}
			}
			t = t->nextitem;
		}
		printf("没有找到对应的路由表项!\n");
		return result;
	}
};
class ARPTable
{
public:
	DWORD IP;//IP
	BYTE mac[6];//MAC
	static void add(DWORD ip, BYTE mac[6])//添加
	{
		arp_table[arp_num].IP = ip;
		for (int i = 0; i < 6; i++)
		{
			arp_table[arp_num].mac[i] = mac[i];
		}
		arp_num++;
	}
	static int find(DWORD ip, BYTE mac[6])//查找
	{
		for (int i = 0; i < arp_num; i++)
		{
			if (ip == arp_table[i].IP)
			{
				for (int j = 0; j < 6; j++)
				{
					mac[j] = arp_table[i].mac[j];
				}
				return 1;
			}
		}
		return 0;
	}
}arp_table[50];
