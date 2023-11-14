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
typedef struct Frame_Header//֡�ײ�
{
    BYTE DesMAC[6];
    BYTE SrcMAC[6];
    WORD FrameType;
}Frame_Header;
typedef struct ARP_Frame//ARP���ݰ�
{
    Frame_Header FrameHeader;
    WORD HardwareType; //Ӳ������
    WORD ProtocolType; //Э������
    BYTE HLen; //Ӳ������
    BYTE PLen; //Э�鳤��
    WORD op; //��������
    BYTE SrcMAC[6]; //ԴMAC��ַ
    DWORD SrcIP; //ԴIP��ַ
    BYTE DesMAC[6]; //Ŀ��MAC��ַ
    DWORD DesIP; //Ŀ��IP��ַ
}ARP_Frame;
#pragma pack()
ARP_Frame DesARP;
ARP_Frame SrcARP;
void* getAdd(struct sockaddr* sa)//��ȡsockaddr��ַ����
{
    if (sa->sa_family == AF_INET)return &(((struct sockaddr_in*)sa)->sin_addr);
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
int pa(pcap_if_t* alldevs)//����豸��Ϣ
{
    pcap_if_t* a; //�����豸��ָ��
    pcap_addr_t* p; //��ַָ��
    int i = 0;
    for (a = alldevs; a; a = a->next)//����豸����������Ϣ
    {
        ++i;
        cout << "��" << i << "����" << a->name;
        if (a->description)cout << "(" << a->description << ")" << endl;
        else cout << "����ϸ��Ϣ" << endl;
        for (p = a->addresses; p != NULL; p = p->next) 
        {
            if (p->addr->sa_family == AF_INET) 
            {
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, getAdd((struct sockaddr*)p->addr), str, sizeof(str));
                cout << "IP��ַ��" << str << endl;
                inet_ntop(AF_INET, getAdd((struct sockaddr*)p->netmask), str, sizeof(str));
                cout << "�������룺" << str << endl;
                inet_ntop(AF_INET, getAdd((struct sockaddr*)p->broadaddr), str, sizeof(str));
                cout << "�㲥��ַ��" << str << endl;
            }
        }
        cout << endl;
    }
    if (i == 0)//�豸����Ϊ0
    {
        cout << endl << "δ�ҵ��豸" << endl;
        return 0;
    }
    return i;
}
void Arp(const u_char* pkt_data)//��ӡ���񵽵�ARP���ݰ�����Ҫ����
{
    struct ARP_Frame* ARP;
    ARP = (struct ARP_Frame*)(pkt_data);
    cout << "�������ͣ�" << ntohs(ARP->op) << endl;
    cout << "ԴMAC��ַ��";
    for (int i = 0; i < 5; i++)
        cout << setw(2) << setfill('0') << hex << uppercase << (int)ARP->FrameHeader.SrcMAC[i] << "-";
    cout << setw(2) << setfill('0') << hex << uppercase << (int)ARP->FrameHeader.SrcMAC[5] << endl;
    cout << "ԴIP��ַ��";
    in_addr addr;
    memcpy(&addr, &ARP->SrcIP, 4);
    cout << inet_ntoa(addr) << endl; //inet_ntoa������IPv4��IPv6Internet�����ַת��ΪInternet��׼��ʽ���ַ���
    cout << "Ŀ��MAC��ַ��";
    for (int i = 0; i < 5; i++)
        cout << setw(2) << setfill('0') << hex << uppercase << (int)ARP->FrameHeader.DesMAC[i] << "-";
    cout << setw(2) << setfill('0') << hex << uppercase << (int)ARP->FrameHeader.DesMAC[5] << endl;
    cout << "Ŀ��IP��ַ��";
    memcpy(&addr, &ARP->DesIP, 4);
    cout << inet_ntoa(addr) << endl << endl;; //inet_ntoa������IPv4��IPv6Internet�����ַת��ΪInternet��׼��ʽ���ַ���
}
int main() 
{
    pcap_if_t* alldevs; //�豸�б�
    char err[PCAP_ERRBUF_SIZE]; //������Ϣ������
    if (pcap_findalldevs(&alldevs, err) == -1)//��ȡ����ӿ��б�
    {
        cout << stderr << "pcap_findalldevs����" << err << endl;
        return 0;
    }
    cout << endl << "-------------------------------�豸-------------------------------" << endl;
    int sum = pa(alldevs);//����豸��Ӧ����Ϣ�Լ��������豸��
    cout << endl << "-----------------------ѡ�������ݰ�������-----------------------" << endl;
    //ѡ���豸��������
    pcap_if_t* d; //�����õ�ָ��
    d = alldevs;
    int n;
    cout << "ѡ�������ݰ���������";
    cin >> n;
    for (int i = 0; i < n - 1; i++) d = d->next;//ָ��dָ��Ŀ������
    pcap_addr_t* a; //��ַָ��
    char src_ip[INET_ADDRSTRLEN]; //���IP������
    for (a = d->addresses; a != NULL; a = a->next)
        if (a->addr->sa_family == AF_INET)
            inet_ntop(AF_INET, getAdd((struct sockaddr*)a->addr), src_ip, sizeof(src_ip));
    cout << "ip: " << src_ip << endl;
    //��ѡ����豸������
    pcap_t* targeted = pcap_open(d->name, 500, PCAP_OPENFLAG_PROMISCUOUS, 500, NULL, err);
    if (targeted == NULL)//���������Ϣ
    {
        cout << "pcap_open����" << err << endl;
        pcap_freealldevs(alldevs);
        return 0;
    }
    cout << endl << "-----------------------��ȡĿ������MAC��ַ-----------------------" << endl;
    unsigned char src_mac[48] = { 0x14,0x5a,0xfc,0x37,0x1a,0xf3 }, des_mac[48];
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    int k;
    for (int i = 0; i < 6; i++)//��ȡĿ��������MAC��ַ
    {
        DesARP.FrameHeader.DesMAC[i] = 0xff; //�㲥��ַ
        DesARP.FrameHeader.SrcMAC[i] = src_mac[i]; //����MAC��ַ
        DesARP.DesMAC[i] = 0x00; //����Ϊ0 
        DesARP.SrcMAC[i] = src_mac[i]; //����MAC��ַ
    }
    DesARP.FrameHeader.FrameType = htons(0x0806);
    DesARP.HardwareType = htons(0x0001);
    DesARP.ProtocolType = htons(0x0800);
    DesARP.HLen = 6;
    DesARP.PLen = 4;
    DesARP.op = htons(0x0001);
    DesARP.SrcIP = inet_addr(src_ip);
    cout << "������Ŀ������IP��ַ��";
    char des_ip[INET_ADDRSTRLEN];
    cin >> des_ip;
    cout << endl;
    DesARP.DesIP = inet_addr(des_ip);
    while ((k = pcap_next_ex(targeted, &pkt_header, &pkt_data)) >= 0)
    {
        //���͹���õ����ݰ�
        pcap_sendpacket(targeted, (u_char*)&DesARP, sizeof(ARP_Frame));
        if (k == 0)continue;
        //ͨ���������ݱȶ��ж��Ƿ���Ҫ����ӡ��ARP���ݰ�����
        else if (*(unsigned short*)(pkt_data + 12) == htons(0x0806) && *(unsigned short*)(pkt_data + 20) == htons(0x0002) && *(unsigned long*)(pkt_data + 28) == DesARP.DesIP) //֡����ΪARP��htons(0x0806)��&& ��������ΪARP��Ӧ��htons(0x0002)��
        {
            Arp(pkt_data); //���ú�����ӡ���ݰ�
            for (int i = 0; i < 6; i++)//��mac�����¼MAC��ַ
                des_mac[i] = *(unsigned char*)(pkt_data + 22 + i);
            cout << "��ȡMAC��ַ�ɹ���MAC��ַΪ��";
            for (int i = 0; i < 5; i++)
                cout << setw(2) << setfill('0') << hex << uppercase << (int)des_mac[i] << "-";
            cout << setw(2) << setfill('0') << hex << uppercase << (int)des_mac[5] << endl;
            break;
        }
    }
    if (k < 0)//���������Ϣ
    {
        cout << "pcap_next_ex��ȡ���Ĵ���" << endl;
        pcap_freealldevs(alldevs);
        return 0;
    }
    pcap_freealldevs(alldevs);//�ͷ��豸������
    return 0;
}