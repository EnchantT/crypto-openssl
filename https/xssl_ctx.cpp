#include "xssl_ctx.h"
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
using namespace std;

//��֤֤��Ļص�
static int SSLVerifyCB(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    if (preverify_ok == 0)
    {
        cout << "SSL cert validate failed!" << endl;
    }
    else
    {
        cout << "SSL cert validate success!" << endl;
    }
    //��������һ����֤��������֤֤���е������Ƿ���ȷ
    return preverify_ok;
}

//�ͷ���Դ
void XSSLCtx::Close()
{
    if (ssl_ctx_)
    {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = 0;
    }
}
//////////////////////////////////////////////////////////////////////
/// ��֤�Է�֤��
void XSSLCtx::SetVerify(const char *ca_crt)
{
    if (!ca_crt|| !ssl_ctx_)return;
    //������֤�Է�֤��
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, SSLVerifyCB);
    SSL_CTX_load_verify_locations(ssl_ctx_, ca_crt, 0);
}

/////////////////////////////////////////////////////////////////////
/// ��ʼ��SSL�ͻ���
/// @para ca_file ��֤�����֤��
bool  XSSLCtx::InitClient(const char *ca_file )
{
    ssl_ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx_)
    {
        cerr << "SSL_CTX_new TLS_client_method failed!" << endl;
        return false;
    }

    //�Է�����֤����֤
    SetVerify(ca_file);
    return true;
}

bool XSSLCtx::InitServer(const char*crt_file, const char *key_file, const char *ca_file )
{
    //���������� ssl ctx������
    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx_)
    {
        cerr << "SSL_CTX_new TLS_server_method failed!" << endl;
        return false;
    }

    //����֤�飬˽Կ������֤
    int re = SSL_CTX_use_certificate_file(ssl_ctx_, crt_file, SSL_FILETYPE_PEM);
    if (re <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    cout << "Load certificate success!" << endl;
    re = SSL_CTX_use_PrivateKey_file(ssl_ctx_, key_file, SSL_FILETYPE_PEM);
    if (re <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    cout << "Load PrivateKey success!" << endl;

    re = SSL_CTX_check_private_key(ssl_ctx_);
    if (re <= 0)
    {
        cout << "private key does not match the certificate!" << endl;
        return false;
    }
    cout << "check_private_key success!" << endl;

    //�Կͻ���֤����֤
    SetVerify(ca_file);
    return true;
}

XSSL XSSLCtx::NewXSSL(int socket)
{
    XSSL xssl;
    if (socket <= 0 || !ssl_ctx_)
    {
        cout << "socket <=0 ����ssl_ctx == 0" << endl;
        return xssl;
    }
        
    auto ssl = SSL_new(ssl_ctx_);
    if (!ssl)
    {
        cerr << "SSL_new failed!" << endl;
        return xssl;
    }
    SSL_set_fd(ssl, socket);
    xssl.set_ssl(ssl);
    return xssl;
}
 
XSSLCtx::XSSLCtx()
{
    OpenSSL_add_ssl_algorithms();
    /*Ϊ��ӡ������Ϣ��׼��*/
    SSL_load_error_strings();
}


XSSLCtx::~XSSLCtx()
{
}
