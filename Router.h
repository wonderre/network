#pragma once
#include "pcap.h"
#include<ctime>
#pragma warning(disable:4996)
char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
pcap_if_t* alldevs;	//ָ���豸�����ײ���ָ��
pcap_t* chowang;//ѡ��򿪵�����
BYTE mymac[6];//�����豸��mac��ַ
BYTE desmac[6];
int arp_num = 0;//arp�������
BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };//�㲥��ַ
//·�ɱ�ĳ�ʼ������
char MyIP[2][INET_ADDRSTRLEN]; //����IP
char Mymask[2][INET_ADDRSTRLEN]; //��������
#pragma pack(1)//��1byte��ʽ����
typedef struct FrameHeader_t //֡�ײ�
{
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;
typedef struct ARPFrame_t //ARP�����ײ�
{
	FrameHeader_t FrameHeader;//֡�ײ�
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э������
	BYTE HLen;//Ӳ����ַ����
	BYTE PLen;//Э���ַ
	WORD Operation;//����
	BYTE SendMAC[6];//���ͷ�MAC
	DWORD SendIP;//���ͷ�IP
	BYTE RecvMAC[6];//���շ�MAC
	DWORD RecvIP;//���շ�IP
}ARPFrame_t;
typedef struct IPHeader_t //IP�ײ�
{
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;//��������
	BYTE Protocol;
	WORD Checksum;//У���
	ULONG SrcIP;//ԴIP
	ULONG DstIP;//Ŀ��IP
}IPHeader_t;
typedef struct Data_t //֡�ײ���IP�ײ������ݰ�
{
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}Data_t;
typedef struct SendPacket_t //���������͵����ݰ��ṹ
{
	BYTE PktData[2000];// ���ݻ���
	ULONG TargetIP; // Ŀ��IP��ַ
	bool flag = 1; // �Ƿ���Ч������Ѿ���ת�����߳�ʱ������0
	clock_t t; // �ж��Ƿ�ʱ����ʱ��ɾ��
} SendPacket_t;
//#pragma pack()//�ָ�4bytes����
SendPacket_t Buffer[50];//������
int bufsize = 0; //��������С
void print_MAC(byte* MAC)//��ӡMAC��ַ
{
	for (int i = 0; i < 5; i++)
		printf("%02X-", MAC[i]);
	printf("%02X\n", MAC[5]);
}
void print_IP(unsigned long u)//��ӡIP��ַ
{
	in_addr addr;
	memcpy(&addr, &u, sizeof(u));
	printf("%s  ", inet_ntoa(addr));
}
void print_IPRecord(Data_t* data)//��ӡIP���ݰ�
{
	printf("֡�ײ�-ԴMAC��ַ��");
	print_MAC(data->FrameHeader.SrcMAC);
	printf("֡�ײ�-Ŀ��MAC��ַ��");
	print_MAC(data->FrameHeader.DesMAC);
	printf("IP�ײ�-ԴIP��ַ��");
	print_IP(data->IPHeader.SrcIP);
	printf("\nIP�ײ�-Ŀ��IP��ַ");
	print_IP(data->IPHeader.DstIP);
	printf("\n");
}
void print_ARPRecord(ARPFrame_t* data)//��ӡARP���ݰ�
{
	printf("֡�ײ�-ԴMAC��ַ��");
	print_MAC(data->FrameHeader.SrcMAC);
	printf("֡�ײ�-Ŀ��MAC��ַ��");
	print_MAC(data->FrameHeader.DesMAC);
	printf("arp����-ԴIP��ַ��");
	print_IP(data->SendIP);
	printf("\narp����-Ŀ��IP��ַ��");
	print_IP(data->RecvIP);
	printf("\n");
}
class RouteItem //·�ɱ����
{
public:
	DWORD mask;//����
	DWORD net;//Ŀ������
	DWORD nextip;//��һ��
	int index;//����
	int type;//0Ϊֱ�����ӣ�1Ϊ�û����
	RouteItem* nextitem;//����������ʽ�洢
	RouteItem()
	{
		memset(this, 0, sizeof(*this));//��ʼ��Ϊȫ0
	}
	//��ӡ�������ݣ���ӡ�����롢Ŀ���������һ��IP�����ͣ��Ƿ���ֱ��Ͷ�ݣ�
	void print()
	{
		printf("��%d����", index);
		printf("���룺");
		print_IP(mask);
		printf("\tĿ�����磺");
		print_IP(net);
		printf("\n       ��һ����");
		print_IP(nextip);
		printf("\t���ͣ�");
		if (type == 0) printf("direct\n");
		else printf("add\n");
	}
};
class RouteTable //·�ɱ�
{
public:
	RouteItem* head, * tail;//֧��������50ת����
	int num;//����
	RouteTable()//��ʼ�������ֱ�����ӵ�����
	{
		head = new RouteItem;
		head->nextitem = tail;
		num = 0;
		for (int i = 0; i < 2; i++)
		{
			RouteItem* temp = new RouteItem;
			temp->net = (inet_addr(MyIP[i])) & (inet_addr(Mymask[i]));//����������ip��������а�λ�뼴Ϊ��������
			temp->mask = inet_addr(Mymask[i]);
			temp->type = 0;//0��ʾֱ��Ͷ�ݵ����磬����ɾ��
			this->add(temp);//��ӱ���
		}
	};
	void add(RouteItem* a)//��� ֱ��Ͷ������ǰ���ƥ��ԭ��ǰ׺������ǰ��
	{
		RouteItem* pointer;//���ڲ��Ҳ���λ�õ�ָ��
		if (a->type == 0)//Ĭ��·�� ��ʼ��ʱ���ֱ��Ͷ��
		{
			a->nextitem = head->nextitem;
			head->nextitem = a;
			a->type = 0;
			printf("�Ѳ���0\n");
		}
		else//type==1����ֱ��Ͷ��
		{
			for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)//����·�ɱ�
				if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask) break;//�������pointerָ��ָ������룬С����һ������룬ƥ��
			if (pointer->nextitem == NULL)//����
			{
				a->nextitem = pointer->nextitem;
				pointer->nextitem = a;
				a->type = 1;
				printf("�Ѳ���");
			}
			else
			{
				a->nextitem = pointer->nextitem;
				pointer->nextitem = a;
			}
		}
		RouteItem* p = head->nextitem;
		for (int i = 0; p != tail; p = p->nextitem, i++)//�������
		{
			p->index = i;
		}
		num++;//������+1
	}
	void remove(int index)//ɾ�� type=0����ɾ��
	{
		for (RouteItem* t = head; t->nextitem != tail; t = t->nextitem)
		{
			if (t->nextitem->index == index)
			{
				if (t->nextitem->type == 0)
				{
					printf("Ĭ��·�ɲ���ɾ����\n");
					return;
				}
				else
				{
					t->nextitem = t->nextitem->nextitem;
					printf("��ɾ����\n");
					return;
				}
			}
		}
		printf("δ���ҵ��ñ��\n");
	}
	void print()//��ӡ ����������ñ����print����
	{
		for (RouteItem* t = head->nextitem; t != tail; t = t->nextitem)
		{
			t->print();
		}
		printf("\n");
	}
	DWORD find(DWORD ip) //���� �ƥ��ԭ��,������һ����ip
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
					return t->nextip;//ת��
				}
				else
				{
					print_IP(ip);
					return ip;//ֱ��Ͷ��
				}
			}
			t = t->nextitem;
		}
		printf("û���ҵ���Ӧ��·�ɱ���!\n");
		return result;
	}
};
class ARPTable
{
public:
	DWORD IP;//IP
	BYTE mac[6];//MAC
	static void add(DWORD ip, BYTE mac[6])//���
	{
		arp_table[arp_num].IP = ip;
		for (int i = 0; i < 6; i++)
		{
			arp_table[arp_num].mac[i] = mac[i];
		}
		arp_num++;
	}
	static int find(DWORD ip, BYTE mac[6])//����
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
