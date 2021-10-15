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
	//server生成一个密钥对
	server.CreateKey();
	//server将密钥对转为8进制数据
	int seroctlen = server.GetPubKey(spub);
	//server 将自己的公钥发送给了clinet
	client.CreateKey();
	int clioctlen = client.GetPubKey(cpub);
	server.SharedKey(serversharedkey, cpub, clioctlen);
	client.SharedKey(clintsharedkey, spub, seroctlen);
	cout << "server生成的共享密钥：" << serversharedkey << endl;
	cout << "client生成的共享密钥：" << clintsharedkey << endl;
	return 0;
}