#include<iostream>
#include<openssl/bio.h>
#include<openssl/rand.h>
#include<openssl/evp.h>
#include<openssl/buffer.h>
using namespace std;
/*
���뺯��
@para in ����
@para len �������ݵĳ���
@para out ���
@return ������ݵĳ���
*/
int Base64Encode(const unsigned char *in,int len, char *out)
{
	//�ڴ�Դ,����ڴ�Դ�л�ȡ����
	 auto mem_bio=BIO_new(BIO_s_mem());
	 if (!mem_bio)
	 {
		 return -1;
	 }
	 //base64 ������
	 auto b64_f= BIO_new(BIO_f_base64());
	 if (!b64_f)
	 {
		 BIO_free(mem_bio);//������Ŀռ��ͷ�
		 return -1;
	 }
	 //�γ�bio����  b64_f--->mem_bio 
	 //����������д���ݣ����б��룬Ȼ����ڴ�Դ�ж�����
	 BIO_push(b64_f, mem_bio);
	 //����64�ֽڲ����У�Ĭ�Ͻ�β�л��з�
	 BIO_set_flags(b64_f, BIO_FLAGS_BASE64_NO_NL);
	 //д�뵽base64���������룬��mem�ж�ȡ
	 int ret= BIO_write(b64_f, in, len);
	 if (!ret)
	 {
		 //�����������b64_f������������
		 BIO_free_all(b64_f);
		 return -1;
	 }
	 //ˢ����Ϻ������ɣ���meme�л�ȡ���
	 BIO_flush(b64_f);
	 BUF_MEM *p_data = NULL;
	 int out_size = 0;
	 BIO_get_mem_ptr(b64_f, &p_data);
	 //ȡ������
	 if (p_data != NULL)
	 {
		 memcpy(out, p_data->data, p_data->length);
		 out_size = p_data->length;
	 }
	 //�������пռ�
	 BIO_free_all(b64_f);
	 return out_size;
}
/*
���뺯��
@para in ����
@para len �������ݵĳ���
@para out ���
@return ������ݵĳ���
*/
int Base64Decode(const unsigned char *in, int len, char *out)
{
	//�������Ĵ���һ���ڴ�Դ
	auto mem_bio= BIO_new_mem_buf(in, len);
	//����base64������
	auto b64_f=BIO_new(BIO_f_base64());
	if (!b64_f)
	{
		BIO_free(mem_bio);
		return -1;
	}
	//�γ�bio����
	BIO_push(b64_f, mem_bio);
	BIO_set_flags(b64_f, BIO_FLAGS_BASE64_NO_NL);
	//��ȡ

	BIO_read(b64_f, out, len);
	BIO_free_all(b64_f);
	return 0;
}
int main()
{	
	unsigned char data[] = "hello,how are you!";
	int data_size = sizeof(data);
	unsigned char out[1024] = { 0 };
	unsigned char out2[1024] = { 0 };
	int out_size = Base64Encode(data, data_size, (char *)out);
	out[out_size] = '\0';
	cout << "base64���룺"<<out << endl;
	Base64Decode(out, out_size, (char *)out2);
	cout << "���������ݣ�"<<out2 << endl;
	return 0;
}