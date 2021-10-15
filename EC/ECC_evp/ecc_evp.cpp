#include<openssl/ec.h>
#include<openssl/evp.h>
#include<iostream>
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
using namespace std;
//////////////////////////////生成密钥函数///////////////////////////////
EVP_PKEY* genkey()
{
	EC_KEY*eckey=EC_KEY_new();
	//打印openssl库中所有支持的椭圆曲线
	/*int len = EC_get_builtin_curves(NULL, 0);
	EC_builtin_curve *curves = (EC_builtin_curve*)malloc(sizeof(EC_builtin_curve)*len);
	EC_get_builtin_curves(curves, len);
	for (int i = 0; i < len; i++)
	{
		cout << "nid:" << curves[i].nid << " " << curves[i].comment << endl;
	}
	delete[] curves;*/
	//选择某一条椭圆曲线，其实就是选择它的G,a,b,p等参数，
	//这些参数都存储在EC_GROUP*对象中
	//secp256k1不支持加解密但是支持签名和密钥交换
	EC_GROUP*group=EC_GROUP_new_by_curve_name(NID_sm2); //国密SM2支持加解密
	if (!group)
	{
		cout << "group is null" << endl;
		return nullptr;
	}
	//设置密钥参数生成密钥
	EC_KEY_set_group(eckey, group);
	int ret=EC_KEY_generate_key(eckey);
	if (ret != 1)
	{
		cout << "generate key failed!" << endl;
		EC_KEY_free(eckey);
		return nullptr;
	}
	
	//检查密钥
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
	////////////////////////////////数据准备////////////////////////////////////////////
	unsigned char data[] = "aaaaahi how are you i am fine and you?haha my name is tangxiao!";
	unsigned char out[1024] = { 0 };
	unsigned char out2[1024] = { 0 };
	int data_size = sizeof(data);
	cout << "data_size:" << data_size << endl;
	////////////////////////////生成密钥，并将密钥存放在pkey中///////////////////////
	auto pkey=genkey();
	//创建evp_pkey加解密上下文
	auto ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
	{
		cout << "evp_pkey_ctx_new error!" << endl;
	}
	//加密初始化
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
	/////加密函数
	////@ctx 上下文
	////@out 输出
	////@outlen 输出数据的大小
	////@data 输入
	////@data_size 输入数据的大小
	EVP_PKEY_encrypt(ctx, out, &outlen, data, data_size);
	cout << "cipherfile:" << out << endl;
	cout << "outlen=" << outlen << endl;
	cout << "--------------------------------------" << endl;
	//解密初始化
	EVP_PKEY_decrypt_init(ctx);
	size_t out2len = sizeof(out2);
	//////解密函数
	////@ctx 上下文
	////@out2 输出(明文)
	////@out2len 输出数据大小
	////@out 输入(密文)
	////@outlen 输入数据的大小
	EVP_PKEY_decrypt(ctx, out2, &out2len, out, outlen);
	cout << "plaintxt:" << out2 << endl;
	cout << "out2len=" << out2len << endl;
	return 0;
}