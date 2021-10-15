#include "XECDH.h"

XECDH::XECDH()
{
	nid = NID_secp256k1;
}

bool XECDH::CreateKey()
{
	//������Բ���ߵĲ�����������,�������ɶ�Ӧ�Ĳ���
	EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	//��Բ���߲����ĳ�ʼ��
	int re = EVP_PKEY_paramgen_init(ctx);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	//ѡ����Բ����
	re=EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	//������Բ���߲����洢��params
	EVP_PKEY*param = nullptr;
	re=EVP_PKEY_paramgen(ctx, &param);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);
	//������Կ��
	//����EC����������Կ�Դ���������
	EVP_PKEY_CTX* kctx=EVP_PKEY_CTX_new(param,NULL);
	if (!kctx)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	//������Կ�Եĳ�ʼ��
	re=EVP_PKEY_keygen_init(kctx);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(kctx);
		return false;
	}
	//������Կ��������Կ�����pkey��
	re=EVP_PKEY_keygen(kctx, &pkey);
	EVP_PKEY_CTX_free(kctx);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	cout << "generkey success!" << endl;

	return true;
}

int XECDH::GetPubKey(unsigned char * pubkey)
{
	if (!pkey)
		return 0;
	//��pkey���õ�ԭʼ�ӿ����͵���Կ
	EC_KEY* key=EVP_PKEY_get0_EC_KEY(pkey);
	//�õ���Կ������һ����
	const EC_POINT* pub = EC_KEY_get0_public_key(key);
	//�������ת����8����,�����pubkey��
	int re=EC_POINT_point2oct(EC_KEY_get0_group(key), pub, POINT_CONVERSION_HYBRID, pubkey, 1024, 0);
	return re;
}

EVP_PKEY * XECDH::OctTokey(const unsigned char * pubkey, int pubkey_size)
{
	//�õ���ǰ��Բ���߲�����������G��abp
	auto key = EVP_PKEY_get0_EC_KEY(pkey);
	auto group = EC_KEY_get0_group(key);
	//pubkey-->EC_POINT
	EC_POINT*p = EC_POINT_new(group);//��Կ
	EC_POINT_oct2point(group, p, pubkey, pubkey_size, 0);//���Է��Ĺ�Կ�Ѿ��洢��P��
	//��Բ���ߵĵͼ���ԭʼ�ӿ�ec_key,��Բ���ߵĹ�˽Կ�Ͳ��������������ṹ��
	EC_KEY*ec_key = EC_KEY_new();
	//��������䵽ec_key��
	EC_KEY_set_group(ec_key, group);//ѡ��ͬ������Բ����
	EC_KEY_set_public_key(ec_key, p);//����ԿҲ��䵽ec_key��
	EC_POINT_free(p);
	//��ԭʼ�ӿ�תΪ�߼��ӿ�evp_pkey
	EVP_PKEY *ppkey = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(ppkey, ec_key);
	EC_KEY_free(ec_key);
	return ppkey;
}

int XECDH::SharedKey(unsigned char * out, const unsigned char * ppkey, int key_size)
{
	//����һ����Կ����������
	auto ctx = EVP_PKEY_CTX_new(pkey,0);
	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		return 0;
	}
	//��ʼ����Կ����
	int er=EVP_PKEY_derive_init(ctx);
	if (er != 1)
	{
		EVP_PKEY_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		return 0;
	}
	//�趨�Է���Կ               
	int re=EVP_PKEY_derive_set_peer(ctx, OctTokey(ppkey, key_size));
	if (re != 1)
	{
		EVP_PKEY_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		return 0;
	}
	//��ʼ����
	size_t outsize = 1024;
	re=EVP_PKEY_derive(ctx, out, &outsize);
	if (re != 1)
	{
		EVP_PKEY_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		return 0;
	}
	EVP_PKEY_CTX_free(ctx);

	return outsize;
}
