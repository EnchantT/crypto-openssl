#include<iostream>
#include<openssl/bio.h>
#include<openssl/rand.h>
#include<openssl/evp.h>
#include<openssl/buffer.h>
using namespace std;
/*
编码函数
@para in 输入
@para len 输入数据的长度
@para out 输出
@return 输出数据的长度
*/
int Base64Encode(const unsigned char *in,int len, char *out)
{
	//内存源,会从内存源中获取数据
	 auto mem_bio=BIO_new(BIO_s_mem());
	 if (!mem_bio)
	 {
		 return -1;
	 }
	 //base64 过滤器
	 auto b64_f= BIO_new(BIO_f_base64());
	 if (!b64_f)
	 {
		 BIO_free(mem_bio);//把上面的空间释放
		 return -1;
	 }
	 //形成bio链表  b64_f--->mem_bio 
	 //往过滤器中写数据，进行编码，然后从内存源中读数据
	 BIO_push(b64_f, mem_bio);
	 //超过64字节不换行，默认结尾有换行符
	 BIO_set_flags(b64_f, BIO_FLAGS_BASE64_NO_NL);
	 //写入到base64过滤器编码，从mem中读取
	 int ret= BIO_write(b64_f, in, len);
	 if (!ret)
	 {
		 //清空整个链表，b64_f代表整个链表
		 BIO_free_all(b64_f);
		 return -1;
	 }
	 //刷新完毕后计算完成，从meme中获取结果
	 BIO_flush(b64_f);
	 BUF_MEM *p_data = NULL;
	 int out_size = 0;
	 BIO_get_mem_ptr(b64_f, &p_data);
	 //取出数据
	 if (p_data != NULL)
	 {
		 memcpy(out, p_data->data, p_data->length);
		 out_size = p_data->length;
	 }
	 //清理所有空间
	 BIO_free_all(b64_f);
	 return out_size;
}
/*
解码函数
@para in 输入
@para len 输入数据的长度
@para out 输出
@return 输出数据的长度
*/
int Base64Decode(const unsigned char *in, int len, char *out)
{
	//利用密文创建一个内存源
	auto mem_bio= BIO_new_mem_buf(in, len);
	//创建base64过滤器
	auto b64_f=BIO_new(BIO_f_base64());
	if (!b64_f)
	{
		BIO_free(mem_bio);
		return -1;
	}
	//形成bio链表
	BIO_push(b64_f, mem_bio);
	BIO_set_flags(b64_f, BIO_FLAGS_BASE64_NO_NL);
	//读取

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
	cout << "base64编码："<<out << endl;
	Base64Decode(out, out_size, (char *)out2);
	cout << "解码后的数据："<<out2 << endl;
	return 0;
}