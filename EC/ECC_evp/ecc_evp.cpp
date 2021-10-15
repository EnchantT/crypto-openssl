#include<openssl/ec.h>
#include<openssl/evp.h>
#include<iostream>
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
using namespace std;
//////////////////////////////������Կ����///////////////////////////////
EVP_PKEY* genkey()
{
	EC_KEY*eckey=EC_KEY_new();
	//��ӡopenssl��������֧�ֵ���Բ����
	/*int len = EC_get_builtin_curves(NULL, 0);
	EC_builtin_curve *curves = (EC_builtin_curve*)malloc(sizeof(EC_builtin_curve)*len);
	EC_get_builtin_curves(curves, len);
	for (int i = 0; i < len; i++)
	{
		cout << "nid:" << curves[i].nid << " " << curves[i].comment << endl;
	}
	delete[] curves;*/
	//ѡ��ĳһ����Բ���ߣ���ʵ����ѡ������G,a,b,p�Ȳ�����
	//��Щ�������洢��EC_GROUP*������
	//secp256k1��֧�ּӽ��ܵ���֧��ǩ������Կ����
	EC_GROUP*group=EC_GROUP_new_by_curve_name(NID_sm2); //����SM2֧�ּӽ���
	if (!group)
	{
		cout << "group is null" << endl;
		return nullptr;
	}
	//������Կ����������Կ
	EC_KEY_set_group(eckey, group);
	int ret=EC_KEY_generate_key(eckey);
	if (ret != 1)
	{
		cout << "generate key failed!" << endl;
		EC_KEY_free(eckey);
		return nullptr;
	}
	
	//�����Կ
	ret=EC_KEY_check_key(eckey);
	if (ret != 1)
	{
		cout << "key error!" << endl;
	}
	auto pkey= EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(pkey, eckey);
	EC_KEY_free(eckey);
	return pkey;
}
int main()
{
	////////////////////////////////����׼��////////////////////////////////////////////
	unsigned char data[] = "aaaaahi how are you i am fine and you?haha my name is tangxiao!";
	unsigned char out[1024] = { 0 };
	unsigned char out2[1024] = { 0 };
	int data_size = sizeof(data);
	cout << "data_size:" << data_size << endl;
	////////////////////////////������Կ��������Կ�����pkey��///////////////////////
	auto pkey=genkey();
	//����evp_pkey�ӽ���������
	auto ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
	{
		cout << "evp_pkey_ctx_new error!" << endl;
	}
	//���ܳ�ʼ��
	int ret=EVP_PKEY_encrypt_init(ctx);
	if (ret != 1)
	{
		cout << "evp_pkey_init error!" << endl;
	}
	else
	{
		cout << "evp_pkey_encrypto_init success!" << endl;
	}
	size_t outlen = sizeof(out);
	/////���ܺ���
	////@ctx ������
	////@out ���
	////@outlen ������ݵĴ�С
	////@data ����
	////@data_size �������ݵĴ�С
	EVP_PKEY_encrypt(ctx, out, &outlen, data, data_size);
	cout << "cipherfile:" << out << endl;
	cout << "outlen=" << outlen << endl;
	cout << "--------------------------------------" << endl;
	//���ܳ�ʼ��
	EVP_PKEY_decrypt_init(ctx);
	size_t out2len = sizeof(out2);
	//////���ܺ���
	////@ctx ������
	////@out2 ���(����)
	////@out2len ������ݴ�С
	////@out ����(����)
	////@outlen �������ݵĴ�С
	EVP_PKEY_decrypt(ctx, out2, &out2len, out, outlen);
	cout << "plaintxt:" << out2 << endl;
	cout << "out2len=" << out2len << endl;
	return 0;
}