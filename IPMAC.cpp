#include <iostream>
#include "pcap.h"
#include <WinSock2.h>
#include<iomanip>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)
#pragma pack(1)
#define BYTE unsigned char
typedef struct Frame_Header//帧首部
{
    BYTE DesMAC[6];
    BYTE SrcMAC[6];
    WORD FrameType;
}Frame_Header;
typedef struct ARP_Frame//ARP数据包
{
    Frame_Header FrameHeader;
    WORD HardwareType; //硬件类型
    WORD ProtocolType; //协议类型
    BYTE HLen; //硬件长度
    BYTE PLen; //协议长度
    WORD op; //操作类型
    BYTE SrcMAC[6]; //源MAC地址
    DWORD SrcIP; //源IP地址
    BYTE DesMAC[6]; //目的MAC地址
    DWORD DesIP; //目的IP地址
}ARP_Frame;
#pragma pack()
ARP_Frame DesARP;
ARP_Frame SrcARP;
void* getAdd(struct sockaddr* sa)//获取sockaddr地址参数
{
    if (sa->sa_family == AF_INET)return &(((struct sockaddr_in*)sa)->sin_addr);
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
int pa(pcap_if_t* alldevs)//输出设备信息
{
    pcap_if_t* a; //遍历设备的指针
    pcap_addr_t* p; //地址指针
    int i = 0;
    for (a = alldevs; a; a = a->next)//输出设备名和描述信息
    {
        ++i;
        cout << "第" << i << "个：" << a->name;
        if (a->description)cout << "(" << a->description << ")" << endl;
        else cout << "无详细信息" << endl;
        for (p = a->addresses; p != NULL; p = p->next) 
        {
            if (p->addr->sa_family == AF_INET) 
            {
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, getAdd((struct sockaddr*)p->addr), str, sizeof(str));
                cout << "IP地址：" << str << endl;
                inet_ntop(AF_INET, getAdd((struct sockaddr*)p->netmask), str, sizeof(str));
                cout << "网络掩码：" << str << endl;
                inet_ntop(AF_INET, getAdd((struct sockaddr*)p->broadaddr), str, sizeof(str));
                cout << "广播地址：" << str << endl;
            }
        }
        cout << endl;
    }
    if (i == 0)//设备数量为0
    {
        cout << endl << "未找到设备" << endl;
        return 0;
    }
    return i;
}
void Arp(const u_char* pkt_data)//打印捕获到的ARP数据包的主要内容
{
    struct ARP_Frame* ARP;
    ARP = (struct ARP_Frame*)(pkt_data);
    cout << "操作类型：" << ntohs(ARP->op) << endl;
    cout << "源MAC地址：";
    for (int i = 0; i < 5; i++)
        cout << setw(2) << setfill('0') << hex << uppercase << (int)ARP->FrameHeader.SrcMAC[i] << "-";
    cout << setw(2) << setfill('0') << hex << uppercase << (int)ARP->FrameHeader.SrcMAC[5] << endl;
    cout << "源IP地址：";
    in_addr addr;
    memcpy(&addr, &ARP->SrcIP, 4);
    cout << inet_ntoa(addr) << endl; //inet_ntoa函数将IPv4或IPv6Internet网络地址转换为Internet标准格式的字符串
    cout << "目的MAC地址：";
    for (int i = 0; i < 5; i++)
        cout << setw(2) << setfill('0') << hex << uppercase << (int)ARP->FrameHeader.DesMAC[i] << "-";
    cout << setw(2) << setfill('0') << hex << uppercase << (int)ARP->FrameHeader.DesMAC[5] << endl;
    cout << "目的IP地址：";
    memcpy(&addr, &ARP->DesIP, 4);
    cout << inet_ntoa(addr) << endl << endl;; //inet_ntoa函数将IPv4或IPv6Internet网络地址转换为Internet标准格式的字符串
}
int main() 
{
    pcap_if_t* alldevs; //设备列表
    char err[PCAP_ERRBUF_SIZE]; //错误信息缓冲区
    if (pcap_findalldevs(&alldevs, err) == -1)//获取网络接口列表
    {
        cout << stderr << "pcap_findalldevs错误" << err << endl;
        return 0;
    }
    cout << endl << "-------------------------------设备-------------------------------" << endl;
    int sum = pa(alldevs);//输出设备对应的信息以及保存总设备数
    cout << endl << "-----------------------选择发送数据包的网卡-----------------------" << endl;
    //选择设备及打开网卡
    pcap_if_t* d; //遍历用的指针
    d = alldevs;
    int n;
    cout << "选择发送数据包的网卡：";
    cin >> n;
    for (int i = 0; i < n - 1; i++) d = d->next;//指针d指向目标网卡
    pcap_addr_t* a; //地址指针
    char src_ip[INET_ADDRSTRLEN]; //存放IP的数组
    for (a = d->addresses; a != NULL; a = a->next)
        if (a->addr->sa_family == AF_INET)
            inet_ntop(AF_INET, getAdd((struct sockaddr*)a->addr), src_ip, sizeof(src_ip));
    cout << "ip: " << src_ip << endl;
    //打开选择的设备的网卡
    pcap_t* targeted = pcap_open(d->name, 500, PCAP_OPENFLAG_PROMISCUOUS, 500, NULL, err);
    if (targeted == NULL)//输出错误信息
    {
        cout << "pcap_open错误" << err << endl;
        pcap_freealldevs(alldevs);
        return 0;
    }
    cout << endl << "-----------------------获取目的主机MAC地址-----------------------" << endl;
    unsigned char src_mac[48] = { 0x14,0x5a,0xfc,0x37,0x1a,0xf3 }, des_mac[48];
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    int k;
    for (int i = 0; i < 6; i++)//获取目的主机的MAC地址
    {
        DesARP.FrameHeader.DesMAC[i] = 0xff; //广播地址
        DesARP.FrameHeader.SrcMAC[i] = src_mac[i]; //本机MAC地址
        DesARP.DesMAC[i] = 0x00; //设置为0 
        DesARP.SrcMAC[i] = src_mac[i]; //本机MAC地址
    }
    DesARP.FrameHeader.FrameType = htons(0x0806);
    DesARP.HardwareType = htons(0x0001);
    DesARP.ProtocolType = htons(0x0800);
    DesARP.HLen = 6;
    DesARP.PLen = 4;
    DesARP.op = htons(0x0001);
    DesARP.SrcIP = inet_addr(src_ip);
    cout << "请输入目的主机IP地址：";
    char des_ip[INET_ADDRSTRLEN];
    cin >> des_ip;
    cout << endl;
    DesARP.DesIP = inet_addr(des_ip);
    while ((k = pcap_next_ex(targeted, &pkt_header, &pkt_data)) >= 0)
    {
        //发送构造好的数据包
        pcap_sendpacket(targeted, (u_char*)&DesARP, sizeof(ARP_Frame));
        if (k == 0)continue;
        //通过报文内容比对判断是否是要发打印的ARP数据包内容
        else if (*(unsigned short*)(pkt_data + 12) == htons(0x0806) && *(unsigned short*)(pkt_data + 20) == htons(0x0002) && *(unsigned long*)(pkt_data + 28) == DesARP.DesIP) //帧类型为ARP（htons(0x0806)）&& 操作类型为ARP响应（htons(0x0002)）
        {
            Arp(pkt_data); //调用函数打印数据包
            for (int i = 0; i < 6; i++)//用mac数组记录MAC地址
                des_mac[i] = *(unsigned char*)(pkt_data + 22 + i);
            cout << "获取MAC地址成功，MAC地址为：";
            for (int i = 0; i < 5; i++)
                cout << setw(2) << setfill('0') << hex << uppercase << (int)des_mac[i] << "-";
            cout << setw(2) << setfill('0') << hex << uppercase << (int)des_mac[5] << endl;
            break;
        }
    }
    if (k < 0)//输出错误信息
    {
        cout << "pcap_next_ex获取报文错误" << endl;
        pcap_freealldevs(alldevs);
        return 0;
    }
    pcap_freealldevs(alldevs);//释放设备，结束
    return 0;
}