#include <stdio.h>
#include "pcap.h"
#include <string>
#include <ctime>
#include"Router.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma warning(disable:4996)
//多线程
HANDLE hThread;
DWORD dwThreadId;
//获取设备列表及选择设备
int pa()//输出设备信息
{
	pcap_if_t* a; //遍历设备的指针
	pcap_addr_t* p; //地址指针
	int i = 0;
	for (a = alldevs; a; a = a->next)//输出设备名和描述信息
	{
		++i;
		printf("第%d个：%s", i, a->name);
		if (a->description) printf("(%s)\n", a->description);
		else printf("无详细信息\n");
		for (p = a->addresses; p != NULL; p = p->next)
		{
			if (p->addr->sa_family == AF_INET)
			{
				char* ipStr = inet_ntoa(((struct sockaddr_in*)p->addr)->sin_addr);
				printf("IP地址：%s\n", ipStr);
				char* maskStr = inet_ntoa(((struct sockaddr_in*)p->netmask)->sin_addr);
				printf("网络掩码：%s\n", maskStr);
				char* broadStr = inet_ntoa(((struct sockaddr_in*)p->broadaddr)->sin_addr);
				printf("广播地址：%s\n", broadStr);
			}
		}
		printf("\n");
	}
	if (i == 0)//设备数量为0
	{
		printf("\n未找到设备\n");
		return 0;
	}
	return i;
}
void getMAC()//获取本机MAC地址
{
	//初始化ARP数据包
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//设置为广播地址
		ARPFrame.FrameHeader.SrcMAC[i] = 0x00;//随便设置
		ARPFrame.SendMAC[i] = 0x00;//随便设置
		ARPFrame.RecvMAC[i] = 0x0;//设置为0
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806); //帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);   //硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);   //协议类型为IP
	ARPFrame.HLen = 6;                       //硬件地址长度为6
	ARPFrame.PLen = 4;                       //协议类型长度为4
	ARPFrame.Operation = htons(0x0001);   //操作为ARP请求	
	ARPFrame.SendIP = inet_addr("10.10.10.10");
	ARPFrame.RecvIP = inet_addr(MyIP[0]);
	//捕获数据包
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	struct pcap_pkthdr* header = new pcap_pkthdr;
	int k;
	pcap_sendpacket(chowang, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	while ((k = pcap_next_ex(chowang, &pkt_header, &pkt_data)) >= 0)
	{
		if (k == 0)continue;//捕获超时，未能获取数据包
		else if (*(unsigned short*)(pkt_data + 12) == htons(0x0806) && *(unsigned short*)(pkt_data + 20) == htons(0x0002) && *(unsigned long*)(pkt_data + 28) == ARPFrame.RecvIP) //帧类型为ARP（htons(0x0806)）操作类型为ARP响应（htons(0x0002)）
		{
			//用mac数组记录本机的MAC地址
			for (int i = 0; i < 6; i++)
			{
				mymac[i] = *(unsigned char*)(pkt_data + 22 + i);
			}
			printf("本机MAC地址为：");
			print_MAC(mymac);
			printf("\n");
			break;
		}
	}
	//输出错误信息
	if (k < 0)
	{
		printf("捕获数据包时出现错误\n");
		pcap_freealldevs(alldevs);
		return;
	}
	printf("---------------------------------------------------------------------\n");
}
void get_MAC(DWORD ip, BYTE mac[])//获取目的主机MAC地址
{
	//初始化ARP数据包--------------------------------------------------
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//设置为广播地址
		ARPFrame.FrameHeader.SrcMAC[i] = mymac[i];//设置为本机MAC地址
		ARPFrame.SendMAC[i] = mymac[i];//设置为本机MAC地址
		ARPFrame.RecvMAC[i] = 0x0;//设置为0
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806); //帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);   //硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);   //协议类型为IP
	ARPFrame.HLen = 6;                       //硬件地址长度为6
	ARPFrame.PLen = 4;                       //协议类型长度为4
	ARPFrame.Operation = htons(0x0001);   //操作为ARP请求	
	ARPFrame.SendIP = inet_addr(MyIP[0]);//设置发送方ip地址
	ARPFrame.RecvIP = ip;
	//发送数据包
	pcap_sendpacket(chowang, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
}
bool compare(BYTE a[], BYTE b[])//比较两数组是否相同
{
	for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false;
	return true;
}
void Set_Checksum(Data_t* temp)//设置校验和
{
	temp->IPHeader.Checksum = 0;
	unsigned long sum = 0;
	WORD* buffer = (WORD*)&temp->IPHeader;//每16位为一组
	int size = sizeof(IPHeader_t);
	while (size > 1)
	{
		sum += *buffer++;
		// 16位相加
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		// 最后可能有单独8位
		sum += *(unsigned char*)buffer;
	}
	// 将高16位进位加至低16位
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	temp->IPHeader.Checksum = ~sum;// 取反
}
bool Check_Checksum(Data_t* temp)//检验校验和
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//包含原有校验和一起进行相加
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//源码+反码->全1
		return 1;//校验和正确
	return 0;
}
void resend(Data_t data, BYTE dmac[])//转发
{
	//拷贝数据包
	Data_t* temp = (Data_t*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//源MAC为本机MAC
	memcpy(temp->FrameHeader.DesMAC, dmac, 6);//目的MAC为下一跳MAC
	temp->IPHeader.TTL -= 1;//TTL-1
	if (temp->IPHeader.TTL < 0)return;//丢弃
	Set_Checksum(temp);//重新设置校验和
	printf("\n----------------------------------转发----------------------------------\n");
	int res = pcap_sendpacket(chowang, (const u_char*)temp, 74);//发送数据报
	if (res == 0) print_IPRecord(temp);
}
DWORD WINAPI recv(LPVOID lparam)//线程函数
{
	ARPTable arptable;
	RouteTable rtable = *(RouteTable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)//等待接收消息
		{
			int res = pcap_next_ex(chowang, &pkt_header, &pkt_data);
			if (res) break;//接收到消息
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (ntohs(header->FrameType) == 0x806)//数据包是ARP格式
		{
			ARPFrame_t* data = (ARPFrame_t*)pkt_data;//格式化收到的包为帧首部+ARP首部类
			printf("\n----------------------------------收到arp数据报----------------------------------\n");
			print_ARPRecord(data);
			//收到ARP响应包
			if (data->Operation == ntohs(0x0002)) {
				BYTE tmp_mac[6];
				//该映射关系已经存到路由表中，不做处理
				if (arptable.find(data->SendIP, tmp_mac)) {}
				//不在路由表中，插入
				else arptable.add(data->SendIP, data->SendMAC);
				//遍历缓冲区，看是否有可以转发的包
				for (int i = 0; i < bufsize; i++)
				{
					if (Buffer[i].flag == 0)continue;
					if (clock() - Buffer[i].t >= 6000) {//超时
						Buffer[i].flag = 0;
						continue;
					}
					if (Buffer[i].TargetIP == data->SendIP)
					{
						Data_t* data_send = (Data_t*)Buffer[i].PktData;
						Data_t temp = *data_send;
						resend(temp, data->SendMAC);
						Buffer[i].flag = 0;
					}
				}
			}
		}
		if (compare(header->DesMAC, mymac) && ntohs(header->FrameType) == 0x800)//目的mac是自己的mac且数据包是IP格式
		{
			Data_t* data = (Data_t*)pkt_data; //格式化收到的包
			if (!Check_Checksum(data))//如果校验和不正确，则直接丢弃不进行处理
			{
				printf("校验和出错\n");
				continue;
			}
			printf("\n----------------------------------收到ip数据报----------------------------------\n");
			print_IPRecord(data);
			if (data->IPHeader.DstIP == inet_addr(MyIP[0]) || data->IPHeader.DstIP == inet_addr(MyIP[1]))
			{
				printf("发送给自己的数据包 直接交由电脑处理\n");
				continue;
			}
			DWORD dstip = data->IPHeader.DstIP; //目的IP地址
			DWORD dstip_next = rtable.find(dstip);//查找下一跳IP地址
			if (dstip_next == -1)
			{
				printf("路由表里没有！\n");
				continue;//如果没有则直接丢弃或直接递交至上层
			}
			else
			{
				printf("arp!!!!!!!!!!!!!!!!");
				Data_t* temp_ = (Data_t*)pkt_data;
				Data_t temp = *temp_;
				BYTE mac[6];
				//直接投递
				print_IP(dstip_next);
				print_IP(dstip);
				if (dstip_next == dstip)
				{
					printf("直接投递");
					//如果ARP表中没有所需内容，则需要获取ARP
					if (!arptable.find(dstip, mac))
					{
						int flag_tool = 0;
						for (int i = 0; i < bufsize; i++)
						 {
							if (Buffer[i].flag == 0) //如果缓冲区中有已经被转发的
							{
								flag_tool = 1;
								memcpy(Buffer[i].PktData, pkt_data, pkt_header->len);
								Buffer[i].flag = 1;
								Buffer[i].t = clock();
								Buffer[i].TargetIP = dstip;
								get_MAC(dstip, mac);
								break;
							}
						}
						if (flag_tool == 0 && bufsize < 50) //缓冲区上限50
						{
							memcpy(Buffer[bufsize].PktData, pkt_data, pkt_header->len);
							Buffer[bufsize].flag = 1;
							Buffer[bufsize].t = clock();
							Buffer[bufsize].TargetIP = dstip;
							bufsize++;
							get_MAC(dstip, mac);
						}
					}
					else
					{
						resend(temp, mac);//转发
						printf("转发");
					}
				}
				else //不是直接投递
				{
					if (!arptable.find(dstip_next, mac))
					{
						int flag_tool = 0;
						for (int i = 0; i < bufsize; i++)
						{
							if (Buffer[i].flag == 0)
							{
								flag_tool = 1;
								memcpy(Buffer[i].PktData, pkt_data, pkt_header->len);
								Buffer[i].flag = 1;
								Buffer[i].t = clock();
								Buffer[i].TargetIP = dstip_next;
								get_MAC(dstip_next, mac);
								break;
							}
						}
						if (flag_tool == 0 && bufsize < 50)
						{
							memcpy(Buffer[bufsize].PktData, pkt_data, pkt_header->len);
							Buffer[bufsize].flag = 1;
							Buffer[bufsize].t = clock();
							Buffer[bufsize].TargetIP = dstip_next;
							bufsize++;
							get_MAC(dstip_next, mac);
						}
					}
					else 
					{
						printf("转发！！！！！！！！");
						resend(temp, mac);
					}
				}
			}
		}
	}
}
int main()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("%s", "获取设备错误! \n");
	}
	int sum = pa();//获取设备列表
	printf("---------------------------------------------------------------------\n");
	pcap_if_t* d = alldevs;
	pcap_addr_t* a;
	int j;
	printf("选择要打开的网卡：");
	scanf("%d", &j);
	for (int i = 0; i < j - 1; i++) d = d->next;
	int t = 0;
	for (a = d->addresses; a != NULL; a = a->next) 
	{
		if (a->addr->sa_family == AF_INET) 
		{
			//存储对应IP地址与MAC地址
			strcpy(MyIP[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			strcpy(Mymask[t++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
		}
	}
	chowang = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (chowang == NULL)
	{
		printf("打开网卡错误！\n");
	}
	pcap_freealldevs(alldevs);
	printf("本机的IP地址和子网掩码为：\n");
	for (int i = 0; i < 2; i++) 
	{
		printf("%s\t", MyIP[i]);
		printf("%s\n", Mymask[i]);
	}
	getMAC();//获取本机MAC地址
	struct bpf_program fcode;
	//通过绑定过滤器，设置只捕获IP和ARP数据报
	if (pcap_compile(chowang, &fcode, "ip or arp", 1, bpf_u_int32(Mymask[0])) < 0)//编辑过滤字符串
	{
		fprintf(stderr, "\n设置过滤器失败！\n");
		system("pause");
		return 0;
	}
	if (pcap_setfilter(chowang, &fcode) < 0)//绑定过滤器
	{
		fprintf(stderr, "\n绑定过滤器失败！\n");
		system("pause");
		return 0;
	}
	RouteTable rtable; //路由表初始化
	rtable.print();
	hThread = CreateThread(NULL, NULL, recv, LPVOID(&rtable), 0, &dwThreadId);
	while (1)
	{
		printf("请选择要进行的操作：1：添加路由表项   2：删除路由表项   3：查看路由表信息\n");
		int cho;
		printf("请输入操作序号：");
		scanf("%d", &cho);
		if (cho == 1)
		{
			RouteItem* a = new RouteItem;
			a->type = 1;//用户添加
			char buf[INET_ADDRSTRLEN];
			printf("请分别输入掩码、目的网络和下一跳IP地址:");
			scanf("%s", &buf);
			a->mask = inet_addr(buf);
			scanf("%s", &buf);
			a->net = inet_addr(buf);
			scanf("%s", &buf);
			a->nextip = inet_addr(buf);
			rtable.add(a);

		}
		else if (cho == 2)
		{
			printf("请输入删除的序号：");
			int index;
			scanf("%d", &index);
			rtable.remove(index);
		}
		else if (cho == 3)
		{
			rtable.print();
			printf("\n");
		}
		else
		{
			printf("----------------------------所选序号不对----------------------------\n");
		}
	}
	return 0;
}
