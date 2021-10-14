#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fstream>
#include <ctime>
// _CRT_SECURE_NO_WARNINGS
#include <openssl/applink.c>
#include "xsec.h"
#include"base64.h"
using namespace std;
////////////////////////////////////////////////////////////////////
/////@para type 加密的类型
/////@para passwd 密钥
/////@in_filename 输入文件名
/////@out_filename 输出文件名
/////@is_enc 是否加密
/////@return 成功or失败
bool XSecEncryptFile(XSecType type, string passwd, string in_filename, string out_filename, bool is_enc)
{
    ifstream ifs(in_filename, ios::binary); //二进制打开输入文件
    if (!ifs)return false;
    ofstream ofs(out_filename, ios::binary);//二进制大小输出文件
    if (!ofs)
    {
        ifs.close();
        return false;
    }
    XSec sec;
    sec.Init(type, "1234567812345678", is_enc);

    unsigned char buf[1024] = { 0 };
    unsigned char out[1024] = { 0 };
    int out_len = 0;
    //1 读文件=》2 加解密文件=》3写入文件
    while (!ifs.eof())
    {
        //1 读文件
        ifs.read((char*)buf, sizeof(buf));
        int count = ifs.gcount();
        if (count <= 0)break;
        bool is_end = false;
        if (ifs.eof()) //文件结尾
            is_end = true;
        out_len = sec.Encrypt(buf, count, out, is_end);
        if (out_len <= 0)
            break;
        ofs.write((char*)out, out_len);
    }
    sec.Close();
    ifs.close();
    ofs.close();
    return true;
}

int main(int argc, char* argv[])
{

    //加密文件
	XSecEncryptFile(XAES128_CBC,"1234567891234567", "./plaint.txt","./cipher.txt",true);
	XSecEncryptFile(XAES128_CBC, "1234567891234567", "./cipher.txt", "./plaint2.txt", false);
}