#pragma once
#include "xssl.h"

class XSSLCtx
{
public:

    /////////////////////////////////////////////////////////////////////
    /// ��ʼ��SSL�����
    /// @crt_file �����֤���ļ�
    /// @key_file �����˽Կ�ļ�
    /// @ca_file ��֤�ͻ���֤�飨��ѡ��
    /// @return ��ʼ���Ƿ�ɹ�
    virtual bool InitServer(const char*crt_file, const char *key_file, const char *ca_file = 0);

    /////////////////////////////////////////////////////////////////////
    /// ��ʼ��SSL�ͻ���
    /// @para ca_file ��֤�����֤��
    virtual bool InitClient(const char *ca_file = 0);

    /////////////////////////////////////////////////////////////////////
    /// ����SSLͨ�Ŷ���socket��ssl_st��Դ�ɵ������ͷ�
    /// ����ʧ�ܷ���ͨ��XSSL::IsEmpty()�ж�
    XSSL NewXSSL(int socket);

    //�ͷ���Դ
    void Close();

    XSSLCtx();

    ~XSSLCtx();
private:
    struct ssl_ctx_st *ssl_ctx_ = 0;
    //////////////////////////////////////////////////////////////////////
    /// ��֤�Է�֤��
    void SetVerify(const char *ca_crt);
};

