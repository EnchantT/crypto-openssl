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
	//生成椭圆曲线密钥对
	bool CreateKey();
	//////////////将pkey转为八进制字符串/////////////////////
	/////@pubkey 传出参数，存放八进制公钥字符串
	int GetPubKey(unsigned char *pubkey);
	////////////将八进制公钥数据转为EVP_PKEY*
	////@pubkey 八进制数据
	////@pubkey_size 长度
	////@return evp_pkey*类型的公钥
	EVP_PKEY* OctTokey(const  unsigned char *pubkey, int pubkey_size);
	///////////////////生成共享密钥////////////////////////////
	/////@out传出参数，共享密钥
	/////@ppkey 对方公钥，八进制字符串
	/////@key_size 字符串长度
	/////@return 共享密钥的长度
	int SharedKey(unsigned char *out, const unsigned char *ppkey, int key_size);

private:
	//选择的椭圆曲线
	int nid;
	//密钥对存放
	EVP_PKEY*pkey = nullptr;
};

