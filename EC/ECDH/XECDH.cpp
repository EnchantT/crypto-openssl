#include "XECDH.h"

XECDH::XECDH()
{
	nid = NID_secp256k1;
}

bool XECDH::CreateKey()
{
	//生成椭圆曲线的参数的上下文,用来生成对应的参数
	EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	//椭圆曲线参数的初始化
	int re = EVP_PKEY_paramgen_init(ctx);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	//选择椭圆曲线
	re=EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	//生成椭圆曲线参数存储到params
	EVP_PKEY*param = nullptr;
	re=EVP_PKEY_paramgen(ctx, &param);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);
	//生成密钥对
	//根据EC参数生成密钥对创建上下文
	EVP_PKEY_CTX* kctx=EVP_PKEY_CTX_new(param,NULL);
	if (!kctx)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	//生成密钥对的初始化
	re=EVP_PKEY_keygen_init(kctx);
	if (re != 1)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(kctx);
		return false;
	}
	//生成密钥，并将密钥存放在pkey中
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
	//从pkey中拿到原始接口类型的密钥
	EC_KEY* key=EVP_PKEY_get0_EC_KEY(pkey);
	//拿到公钥，这是一个点
	const EC_POINT* pub = EC_KEY_get0_public_key(key);
	//将这个点转换成8进制,存放在pubkey中
	int re=EC_POINT_point2oct(EC_KEY_get0_group(key), pub, POINT_CONVERSION_HYBRID, pubkey, 1024, 0);
	return re;
}

EVP_PKEY * XECDH::OctTokey(const unsigned char * pubkey, int pubkey_size)
{
	//拿到当前椭圆曲线参数，里面有G，abp
	auto key = EVP_PKEY_get0_EC_KEY(pkey);
	auto group = EC_KEY_get0_group(key);
	//pubkey-->EC_POINT
	EC_POINT*p = EC_POINT_new(group);//公钥
	EC_POINT_oct2point(group, p, pubkey, pubkey_size, 0);//将对方的公钥已经存储在P中
	//椭圆曲线的低级、原始接口ec_key,椭圆曲线的公私钥和参数都存放在这个结构中
	EC_KEY*ec_key = EC_KEY_new();
	//将参数填充到ec_key中
	EC_KEY_set_group(ec_key, group);//选择同样的椭圆曲线
	EC_KEY_set_public_key(ec_key, p);//将公钥也填充到ec_key中
	EC_POINT_free(p);
	//将原始接口转为高级接口evp_pkey
	EVP_PKEY *ppkey = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(ppkey, ec_key);
	EC_KEY_free(ec_key);
	return ppkey;
}

int XECDH::SharedKey(unsigned char * out, const unsigned char * ppkey, int key_size)
{
	//生成一个密钥交换上下文
	auto ctx = EVP_PKEY_CTX_new(pkey,0);
	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		return 0;
	}
	//初始化密钥交换
	int er=EVP_PKEY_derive_init(ctx);
	if (er != 1)
	{
		EVP_PKEY_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		return 0;
	}
	//设定对方公钥               
	int re=EVP_PKEY_derive_set_peer(ctx, OctTokey(ppkey, key_size));
	if (re != 1)
	{
		EVP_PKEY_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		return 0;
	}
	//开始计算
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
