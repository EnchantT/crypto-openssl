#pragma comment(lib, "Ws2_32.lib")
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <string>
#include <string.h>
#include <stdlib.h>
#include "xssl_ctx.h"
#include <sstream>
#include <thread>
using namespace std;
int main(int argc, char *argv[])
{
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    int port = 443; //https
    XSSLCtx ctx;
    if (!ctx.InitServer("server.crt", "server.key"))
    {
        cout << "ctx.InitServer(\"server.crt\", \"server.key\") failed！" << endl;
        getchar();
        return -1;
    }
    cout << "ctx.InitServer(\"server.crt\", \"server.key\") success！" << endl;

    ///服务端通信
    int accept_sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa_server;
    memset(&sa_server, 0, sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port = htons(port);
    int re = ::bind(accept_sock, (sockaddr*)&sa_server, sizeof(sa_server));
    if (re != 0)
    {
        cerr << " bind port:" << port << " failed!" << endl;
        getchar();
    }
    listen(accept_sock, 10);
    cout << "start listen port " << port << endl;

    for (;;)
    {
        int client_socket = accept(accept_sock, 0, 0);
        if (client_socket <= 0)
            break;
        cout << "accept socket" << endl;
        auto xssl = ctx.NewXSSL(client_socket);
        if (xssl.IsEmpty())
        {
            cout << "xssl.IsEmpty" << endl;
            continue;
        }
        if (!xssl.Accept())
        {
            xssl.Close();
            continue;
        }
        string data = "Server Write";
        //https://127.0.0.1
        for (int i = 0;; i++)
        {
            char buf[10240] = { 0 };
            int len = xssl.Read(buf, sizeof(buf) - 1);
            if (len > 0)
                cout << buf << endl;
     
            //解析GET 得到访问的资源

            //HTTP 响应 状态行、消息报头、响应正文
            string html = "<h1>Test Https(openssl3.0)</h1>";  //响应正文
            stringstream ss;
            ss << "HTTP/1.1 200 OK\r\n";//状态行
            ss << "Server: Xhttps\r\n"; //消息报头
            ss << "Content-Type: text/html\r\n";
            ss << "Content-Length: " << html.size();
            ss << "\r\n\r\n";
            ss << html;
            len = xssl.Write(ss.str().c_str(), ss.str().size());
            if (len <= 0)
                break;
            this_thread::sleep_for(1ms);
        }
        xssl.Close();
    }
    ctx.Close();
    return 0;
}
