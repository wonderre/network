#include <stdio.h>
#include "pcap.h"
#include <string>
#include <ctime>
#include"Router.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma warning(disable:4996)
//���߳�
HANDLE hThread;
DWORD dwThreadId;
//��ȡ�豸�б�ѡ���豸
int pa()//����豸��Ϣ
{
	pcap_if_t* a; //�����豸��ָ��
	pcap_addr_t* p; //��ַָ��
	int i = 0;
	for (a = alldevs; a; a = a->next)//����豸����������Ϣ
	{
		++i;
		printf("��%d����%s", i, a->name);
		if (a->description) printf("(%s)\n", a->description);
		else printf("����ϸ��Ϣ\n");
		for (p = a->addresses; p != NULL; p = p->next)
		{
			if (p->addr->sa_family == AF_INET)
			{
				char* ipStr = inet_ntoa(((struct sockaddr_in*)p->addr)->sin_addr);
				printf("IP��ַ��%s\n", ipStr);
				char* maskStr = inet_ntoa(((struct sockaddr_in*)p->netmask)->sin_addr);
				printf("�������룺%s\n", maskStr);
				char* broadStr = inet_ntoa(((struct sockaddr_in*)p->broadaddr)->sin_addr);
				printf("�㲥��ַ��%s\n", broadStr);
			}
		}
		printf("\n");
	}
	if (i == 0)//�豸����Ϊ0
	{
		printf("\nδ�ҵ��豸\n");
		return 0;
	}
	return i;
}
void getMAC()//��ȡ����MAC��ַ
{
	//��ʼ��ARP���ݰ�
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//����Ϊ�㲥��ַ
		ARPFrame.FrameHeader.SrcMAC[i] = 0x00;//�������
		ARPFrame.SendMAC[i] = 0x00;//�������
		ARPFrame.RecvMAC[i] = 0x0;//����Ϊ0
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806); //֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);   //Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);   //Э������ΪIP
	ARPFrame.HLen = 6;                       //Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;                       //Э�����ͳ���Ϊ4
	ARPFrame.Operation = htons(0x0001);   //����ΪARP����	
	ARPFrame.SendIP = inet_addr("10.10.10.10");
	ARPFrame.RecvIP = inet_addr(MyIP[0]);
	//�������ݰ�
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	struct pcap_pkthdr* header = new pcap_pkthdr;
	int k;
	pcap_sendpacket(chowang, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	while ((k = pcap_next_ex(chowang, &pkt_header, &pkt_data)) >= 0)
	{
		if (k == 0)continue;//����ʱ��δ�ܻ�ȡ���ݰ�
		else if (*(unsigned short*)(pkt_data + 12) == htons(0x0806) && *(unsigned short*)(pkt_data + 20) == htons(0x0002) && *(unsigned long*)(pkt_data + 28) == ARPFrame.RecvIP) //֡����ΪARP��htons(0x0806)����������ΪARP��Ӧ��htons(0x0002)��
		{
			//��mac�����¼������MAC��ַ
			for (int i = 0; i < 6; i++)
			{
				mymac[i] = *(unsigned char*)(pkt_data + 22 + i);
			}
			printf("����MAC��ַΪ��");
			print_MAC(mymac);
			printf("\n");
			break;
		}
	}
	//���������Ϣ
	if (k < 0)
	{
		printf("�������ݰ�ʱ���ִ���\n");
		pcap_freealldevs(alldevs);
		return;
	}
	printf("---------------------------------------------------------------------\n");
}
void get_MAC(DWORD ip, BYTE mac[])//��ȡĿ������MAC��ַ
{
	//��ʼ��ARP���ݰ�--------------------------------------------------
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//����Ϊ�㲥��ַ
		ARPFrame.FrameHeader.SrcMAC[i] = mymac[i];//����Ϊ����MAC��ַ
		ARPFrame.SendMAC[i] = mymac[i];//����Ϊ����MAC��ַ
		ARPFrame.RecvMAC[i] = 0x0;//����Ϊ0
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806); //֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);   //Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);   //Э������ΪIP
	ARPFrame.HLen = 6;                       //Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;                       //Э�����ͳ���Ϊ4
	ARPFrame.Operation = htons(0x0001);   //����ΪARP����	
	ARPFrame.SendIP = inet_addr(MyIP[0]);//���÷��ͷ�ip��ַ
	ARPFrame.RecvIP = ip;
	//�������ݰ�
	pcap_sendpacket(chowang, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
}
bool compare(BYTE a[], BYTE b[])//�Ƚ��������Ƿ���ͬ
{
	for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false;
	return true;
}
void Set_Checksum(Data_t* temp)//����У���
{
	temp->IPHeader.Checksum = 0;
	unsigned long sum = 0;
	WORD* buffer = (WORD*)&temp->IPHeader;//ÿ16λΪһ��
	int size = sizeof(IPHeader_t);
	while (size > 1)
	{
		sum += *buffer++;
		// 16λ���
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		// �������е���8λ
		sum += *(unsigned char*)buffer;
	}
	// ����16λ��λ������16λ
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	temp->IPHeader.Checksum = ~sum;// ȡ��
}
bool Check_Checksum(Data_t* temp)//����У���
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//����ԭ��У���һ��������
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)//Դ��+����->ȫ1
		return 1;//У�����ȷ
	return 0;
}
void resend(Data_t data, BYTE dmac[])//ת��
{
	//�������ݰ�
	Data_t* temp = (Data_t*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//ԴMACΪ����MAC
	memcpy(temp->FrameHeader.DesMAC, dmac, 6);//Ŀ��MACΪ��һ��MAC
	temp->IPHeader.TTL -= 1;//TTL-1
	if (temp->IPHeader.TTL < 0)return;//����
	Set_Checksum(temp);//��������У���
	printf("\n----------------------------------ת��----------------------------------\n");
	int res = pcap_sendpacket(chowang, (const u_char*)temp, 74);//�������ݱ�
	if (res == 0) print_IPRecord(temp);
}
DWORD WINAPI recv(LPVOID lparam)//�̺߳���
{
	ARPTable arptable;
	RouteTable rtable = *(RouteTable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)//�ȴ�������Ϣ
		{
			int res = pcap_next_ex(chowang, &pkt_header, &pkt_data);
			if (res) break;//���յ���Ϣ
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (ntohs(header->FrameType) == 0x806)//���ݰ���ARP��ʽ
		{
			ARPFrame_t* data = (ARPFrame_t*)pkt_data;//��ʽ���յ��İ�Ϊ֡�ײ�+ARP�ײ���
			printf("\n----------------------------------�յ�arp���ݱ�----------------------------------\n");
			print_ARPRecord(data);
			//�յ�ARP��Ӧ��
			if (data->Operation == ntohs(0x0002)) {
				BYTE tmp_mac[6];
				//��ӳ���ϵ�Ѿ��浽·�ɱ��У���������
				if (arptable.find(data->SendIP, tmp_mac)) {}
				//����·�ɱ��У�����
				else arptable.add(data->SendIP, data->SendMAC);
				//���������������Ƿ��п���ת���İ�
				for (int i = 0; i < bufsize; i++)
				{
					if (Buffer[i].flag == 0)continue;
					if (clock() - Buffer[i].t >= 6000) {//��ʱ
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
		if (compare(header->DesMAC, mymac) && ntohs(header->FrameType) == 0x800)//Ŀ��mac���Լ���mac�����ݰ���IP��ʽ
		{
			Data_t* data = (Data_t*)pkt_data; //��ʽ���յ��İ�
			if (!Check_Checksum(data))//���У��Ͳ���ȷ����ֱ�Ӷ��������д���
			{
				printf("У��ͳ���\n");
				continue;
			}
			printf("\n----------------------------------�յ�ip���ݱ�----------------------------------\n");
			print_IPRecord(data);
			if (data->IPHeader.DstIP == inet_addr(MyIP[0]) || data->IPHeader.DstIP == inet_addr(MyIP[1]))
			{
				printf("���͸��Լ������ݰ� ֱ�ӽ��ɵ��Դ���\n");
				continue;
			}
			DWORD dstip = data->IPHeader.DstIP; //Ŀ��IP��ַ
			DWORD dstip_next = rtable.find(dstip);//������һ��IP��ַ
			if (dstip_next == -1)
			{
				printf("·�ɱ���û�У�\n");
				continue;//���û����ֱ�Ӷ�����ֱ�ӵݽ����ϲ�
			}
			else
			{
				printf("arp!!!!!!!!!!!!!!!!");
				Data_t* temp_ = (Data_t*)pkt_data;
				Data_t temp = *temp_;
				BYTE mac[6];
				//ֱ��Ͷ��
				print_IP(dstip_next);
				print_IP(dstip);
				if (dstip_next == dstip)
				{
					printf("ֱ��Ͷ��");
					//���ARP����û���������ݣ�����Ҫ��ȡARP
					if (!arptable.find(dstip, mac))
					{
						int flag_tool = 0;
						for (int i = 0; i < bufsize; i++)
						 {
							if (Buffer[i].flag == 0) //��������������Ѿ���ת����
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
						if (flag_tool == 0 && bufsize < 50) //����������50
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
						resend(temp, mac);//ת��
						printf("ת��");
					}
				}
				else //����ֱ��Ͷ��
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
						printf("ת������������������");
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
		printf("%s", "��ȡ�豸����! \n");
	}
	int sum = pa();//��ȡ�豸�б�
	printf("---------------------------------------------------------------------\n");
	pcap_if_t* d = alldevs;
	pcap_addr_t* a;
	int j;
	printf("ѡ��Ҫ�򿪵�������");
	scanf("%d", &j);
	for (int i = 0; i < j - 1; i++) d = d->next;
	int t = 0;
	for (a = d->addresses; a != NULL; a = a->next) 
	{
		if (a->addr->sa_family == AF_INET) 
		{
			//�洢��ӦIP��ַ��MAC��ַ
			strcpy(MyIP[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			strcpy(Mymask[t++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
		}
	}
	chowang = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (chowang == NULL)
	{
		printf("����������\n");
	}
	pcap_freealldevs(alldevs);
	printf("������IP��ַ����������Ϊ��\n");
	for (int i = 0; i < 2; i++) 
	{
		printf("%s\t", MyIP[i]);
		printf("%s\n", Mymask[i]);
	}
	getMAC();//��ȡ����MAC��ַ
	struct bpf_program fcode;
	//ͨ���󶨹�����������ֻ����IP��ARP���ݱ�
	if (pcap_compile(chowang, &fcode, "ip or arp", 1, bpf_u_int32(Mymask[0])) < 0)//�༭�����ַ���
	{
		fprintf(stderr, "\n���ù�����ʧ�ܣ�\n");
		system("pause");
		return 0;
	}
	if (pcap_setfilter(chowang, &fcode) < 0)//�󶨹�����
	{
		fprintf(stderr, "\n�󶨹�����ʧ�ܣ�\n");
		system("pause");
		return 0;
	}
	RouteTable rtable; //·�ɱ��ʼ��
	rtable.print();
	hThread = CreateThread(NULL, NULL, recv, LPVOID(&rtable), 0, &dwThreadId);
	while (1)
	{
		printf("��ѡ��Ҫ���еĲ�����1�����·�ɱ���   2��ɾ��·�ɱ���   3���鿴·�ɱ���Ϣ\n");
		int cho;
		printf("�����������ţ�");
		scanf("%d", &cho);
		if (cho == 1)
		{
			RouteItem* a = new RouteItem;
			a->type = 1;//�û����
			char buf[INET_ADDRSTRLEN];
			printf("��ֱ��������롢Ŀ���������һ��IP��ַ:");
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
			printf("������ɾ������ţ�");
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
			printf("----------------------------��ѡ��Ų���----------------------------\n");
		}
	}
	return 0;
}
