#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<openssl/evp.h>
#include<openssl/ec.h>
#include<openssl/err.h>
#include<iostream>
using namespace std;
class XECDH
{
public:
	XECDH();
	//������Բ������Կ��
	bool CreateKey();
	//////////////��pkeyתΪ�˽����ַ���/////////////////////
	/////@pubkey ������������Ű˽��ƹ�Կ�ַ���
	int GetPubKey(unsigned char *pubkey);
	////////////���˽��ƹ�Կ����תΪEVP_PKEY*
	////@pubkey �˽�������
	////@pubkey_size ����
	////@return evp_pkey*���͵Ĺ�Կ
	EVP_PKEY* OctTokey(const  unsigned char *pubkey, int pubkey_size);
	///////////////////���ɹ�����Կ////////////////////////////
	/////@out����������������Կ
	/////@ppkey �Է���Կ���˽����ַ���
	/////@key_size �ַ�������
	/////@return ������Կ�ĳ���
	int SharedKey(unsigned char *out, const unsigned char *ppkey, int key_size);

private:
	//ѡ�����Բ����
	int nid;
	//��Կ�Դ��
	EVP_PKEY*pkey = nullptr;
};

