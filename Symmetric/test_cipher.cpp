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
/////@para type ���ܵ�����
/////@para passwd ��Կ
/////@in_filename �����ļ���
/////@out_filename ����ļ���
/////@is_enc �Ƿ����
/////@return �ɹ�orʧ��
bool XSecEncryptFile(XSecType type, string passwd, string in_filename, string out_filename, bool is_enc)
{
    ifstream ifs(in_filename, ios::binary); //�����ƴ������ļ�
    if (!ifs)return false;
    ofstream ofs(out_filename, ios::binary);//�����ƴ�С����ļ�
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
    //1 ���ļ�=��2 �ӽ����ļ�=��3д���ļ�
    while (!ifs.eof())
    {
        //1 ���ļ�
        ifs.read((char*)buf, sizeof(buf));
        int count = ifs.gcount();
        if (count <= 0)break;
        bool is_end = false;
        if (ifs.eof()) //�ļ���β
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

    //�����ļ�
	XSecEncryptFile(XAES128_CBC,"1234567891234567", "./plaint.txt","./cipher.txt",true);
	XSecEncryptFile(XAES128_CBC, "1234567891234567", "./cipher.txt", "./plaint2.txt", false);
}