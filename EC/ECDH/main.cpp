#define _CRT_SECURE_NO_WARNINGS
#include<iostream>
#include"XECDH.h"
using namespace std;
int main()
{
	XECDH server;
	XECDH client;
	unsigned char spub[1024] = { 0 };
	unsigned char cpub[1024] = { 0 };
	unsigned char serversharedkey[1024] = { 0 };
	unsigned char clintsharedkey[1024] = { 0 };
	//server����һ����Կ��
	server.CreateKey();
	//server����Կ��תΪ8��������
	int seroctlen = server.GetPubKey(spub);
	//server ���Լ��Ĺ�Կ���͸���clinet
	client.CreateKey();
	int clioctlen = client.GetPubKey(cpub);
	server.SharedKey(serversharedkey, cpub, clioctlen);
	client.SharedKey(clintsharedkey, spub, seroctlen);
	cout << "server���ɵĹ�����Կ��" << serversharedkey << endl;
	cout << "client���ɵĹ�����Կ��" << clintsharedkey << endl;
	return 0;
}