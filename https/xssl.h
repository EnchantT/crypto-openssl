class XSSL
{
public:
    XSSL();
    ~XSSL();

    //�ն���
    bool IsEmpty() { return ssl_ == 0; }

    //����˽���ssl����
    bool Accept();

    //�ͻ��˴���ssl����
    bool Connect();

    //��ӡͨ��ʹ�õ��㷨
    void PrintCipher();

    //��ӡ�Է�֤����Ϣ
    void PrintCert();

    int Write(const void *data, int data_size);

    int Read(void *buf, int buf_size);

    void set_ssl(struct ssl_st *ssl) { this->ssl_ = ssl; }

    //�ͷ�SSL
    void Close();

private:
    struct ssl_st *ssl_ = 0;
};

