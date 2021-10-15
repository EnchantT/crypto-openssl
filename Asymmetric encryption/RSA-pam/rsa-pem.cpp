#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include<openssl/rsa.h>
#include<openssl/evp.h>
#include<openssl/err.h>
#include<openssl/pem.h>
#ifdef _WIN32
#include<openssl/applink.c>
#endif
using namespace std;
///////////////////////////////////////////////
///////创建pem格式密钥对///////////////////////
EVP_PKEY*GenerKey()
{
	
	//1、创建RSA公钥加密上下文,参数1为算法类型
	EVP_PKEY_CTX *ctx= EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	//2、初始化密钥对生成上下文
	int ret=EVP_PKEY_keygen_init(ctx);
	if (!ret)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	//设置参数，RSA的密钥位数1024位
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) <= 0)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	//4、密钥生成
	EVP_PKEY *pkey=NULL;
	//内部有malloc申请的空间，密钥放在了peky中
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	//将公钥写入文件
	FILE *fp1 = fopen("./public.pem", "w");
	PEM_write_RSAPublicKey(fp1, EVP_PKEY_get0_RSA(pkey));
	//将私钥写入文件
	FILE *fp2 = fopen("./private.pem", "w");
	//以明文方式存储
	PEM_write_RSAPrivateKey(fp2, EVP_PKEY_get0_RSA(pkey),
		NULL,//加密的上下文
		NULL,//key
		0,//密钥长度
		NULL,//回调
		NULL //回调参数
		);
	fclose(fp1);
	fclose(fp2);
	return pkey;
}
/////////////////////////////////////////////////////////////////////
/////加密函数
/////@in 输入
/////@in_len 输入数据的长度
/////@out 输出数据
/////@return 输出数据的长度
int Encrypto(const unsigned char *in, int in_len, unsigned char *out)
{
	//1、读取公钥
	FILE *fp = fopen("./public.pem", "r");
	RSA *r = NULL;
	if (NULL == fp)
	{
		fclose(fp);
		return -1;
	}
	//把文件中公钥写入到RSA结构体中
	PEM_read_RSAPublicKey(fp, &r, NULL, NULL);
	fclose(fp);
	if (!r)
	{
		ERR_print_errors_fp(stderr);

		return -1;
	}
	//2、
	//密钥长度
	int key_size = RSA_size(r);
	//2通过EVP_PKEY生成EVP_PKEY_CTX上下文
	EVP_PKEY *pkey = EVP_PKEY_new();
	//设置为RSA的密钥
	EVP_PKEY_set1_RSA(pkey, r);
	auto ctx = EVP_PKEY_CTX_new(pkey, NULL);

	//3加密初始化
	EVP_PKEY_encrypt_init(ctx);
	//数据块大小，输入的明文长度比RSA密钥短至少11个字节
	//　输入明文长度：keysize- 11;
　//　加密后的密文长度为：keysize;
	int block_size = key_size - RSA_PKCS1_PADDING_SIZE;
	int out_size = 0;
	int i;
	//4加密
	for (i = 0; i < in_len; i += block_size)
	{
		size_t out_len = key_size;
		size_t ensize = block_size;
		if (in_len - i < block_size)
			ensize = in_len - i;
		int ret=EVP_PKEY_encrypt(ctx, out+out_size, &out_len, in+i, ensize);
		if (ret <= 0)
		{
			ERR_print_errors_fp(stderr);
			break;
		}
		out_size += out_len;
	}
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	RSA_free(r);
	return out_size;
}
/////////////////////////////////////////////////////////////////////
/////解密函数
/////@in 输入(密文)
/////@in_len 输入数据的长度
/////@out 输出数据（明文）
/////@return 输出数据的长度
int Decrypto(const unsigned char *in, int in_len, unsigned char *out)
{
	//打开pem文件获取私钥
	FILE *fp = fopen("./private.pem", "r");
	if (!fp)
	{
		fclose(fp);
		return -1;
	}
	RSA *r = NULL;
	//拿私钥，私钥存放在r中
	PEM_read_RSAPrivateKey(fp, &r, NULL, NULL);
	if (!r)
	{
		fclose(fp);
		RSA_free(r);
	}
	int key_size = RSA_size(r);
	//生成PKEY并创建上下文
	EVP_PKEY*pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, r);
	auto ctx = EVP_PKEY_CTX_new(pkey,NULL);
	//释放资源
	EVP_PKEY_free(pkey);
	RSA_free(r);
	fclose(fp);

	//解密
	int out_size = 0;
	//解密初始化
	EVP_PKEY_decrypt_init(ctx);
	//块大小和密钥大小一致
	int block_size = key_size;
	for (int i = 0; i < in_len; i += block_size)
	{
		size_t outlen = key_size;//设置输出空间大小；
		if (EVP_PKEY_decrypt(ctx, out+out_size, &outlen, in + i, block_size) <= 0)
		{
			ERR_print_errors_fp(stderr);
			return -1;
		}
		out_size += outlen;

	}
	EVP_PKEY_CTX_free(ctx);
	return out_size;
	
}
/////////////////////////////////////////////////////////////////////
/////签名函数
/////@data 待签名的数据
/////@in_len 数据长度
/////@sigh 签名
/////@return 输出签名的长度
int EVP_Sign(unsigned char *data, int in_size, unsigned char*sign)
{
	//打开pem文件获取私钥
	FILE *fp = fopen("./private.pem", "r");
	if (!fp)
	{
		fclose(fp);
		return -1;
	}
	RSA *r = NULL;
	//拿私钥
	PEM_read_RSAPrivateKey(fp, &r, NULL, NULL);
	if (!r)
	{
		fclose(fp);
		RSA_free(r);
	}
	int key_size = RSA_size(r);
	//生成PKEY并创建上下文
	EVP_PKEY*pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, r);
	auto ctx = EVP_PKEY_CTX_new(pkey, NULL);
	EVP_PKEY_free(pkey);
	RSA_free(r);
	fclose(fp);
 
	//生成hash值的上下文
	auto hctx=EVP_MD_CTX_new();
	EVP_SignInit(hctx, EVP_sha512());
	//生成hash
	EVP_SignUpdate(hctx, data, in_size);
	//取出hash并用私钥进行加密
	unsigned int sigh_size = in_size;
	EVP_SignFinal(hctx, sign, &sigh_size, pkey);
	//释放资源
	EVP_MD_CTX_free(hctx);
	return sigh_size;
}
/////////////////////////////////////////////////////////////////////
/////验签函数
/////@data 原始数据
/////@in_len 原始数据长度
/////@sigh 签名
/////@sigh_size 签名长度
/////@return 数据是否被篡改
bool verify(unsigned char*data,int in_size,unsigned char *sign,int sign_size)
{
	//1、读取公钥
	FILE *fp = fopen("./public.pem", "r");
	RSA *r = NULL;
	if (NULL == fp)
	{
		fclose(fp);
		return -1;
	}
	//把文件中公钥写入到RSA结构体中
	PEM_read_RSAPublicKey(fp, &r, NULL, NULL);
	fclose(fp);
	if (!r)
	{
		ERR_print_errors_fp(stderr);

		return -1;
	}
	//2、
	//密钥长度
	int key_size = RSA_size(r);
	//2通过EVP_PKEY生成EVP_PKEY_CTX上下文
	EVP_PKEY *pkey = EVP_PKEY_new();
	//设置为RSA的密钥
	EVP_PKEY_set1_RSA(pkey, r);
	RSA_free(r);
	auto ctx = EVP_PKEY_CTX_new(pkey, NULL);

	
	auto hctx= EVP_MD_CTX_new();
	EVP_VerifyInit(hctx, EVP_sha512());
	//生成新的散列值
	EVP_VerifyUpdate(hctx, data, in_size);

	//公钥解密签名，对比新的散列值
	int ret = EVP_VerifyFinal(hctx,//上下文中存放的是新的散列值 
		sign, 
		sign_size,
		pkey);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	if (ret==1)
		return true;
	else
	{
		return false;
	}
}
//测试签名和验签
void test01()
{
	unsigned char data[] = "how are you?hello world!i am fine and you";
	unsigned char sigh[512] = { 0 };
	
	int data_size = sizeof(data);
	int sighsize = EVP_Sign(data, data_size, sigh);
	cout << "sigh:" << sigh << endl;
	int res=verify(data, data_size, sigh, sighsize);
	if (res)
	{
		cout << "验证成功！" << endl;
	}
	else
	{
		cout << "验证失败！" << endl;
	}
}

int main()
{
	//////////////////////////////数据准备//////////////////////////////
	unsigned char data[] = "how are you?hello world!i am fine and you";
	unsigned char out[512] = { 0 };
	unsigned char out2[512] = { 0 };
	int data_size = sizeof(data);
	////////////////////////////生成密钥并写入文件中////////////////////
	auto pkey = GenerKey();
	EVP_PKEY_free(pkey);
	//////////////////////////////加密//////////////////////////////
	int outsize = Encrypto(data, data_size, out);
	cout << "密文长度：" << outsize << endl;
	cout << "密文：" << out << endl;
	//////////////////////////////解密//////////////////////////////
	int out2size = Decrypto(out, outsize, out2);
	cout << "解密后的数据：" << out2<<endl;
	/////////////////////////////签名和验证签名///////////////////////////
	test01();
	return 0;
}

