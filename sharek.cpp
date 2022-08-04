#include <iostream>
#include <string>
#include <sstream>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>

#include <cstdio>
#include <cstdlib>

#include "./include/ssha256.h"
#include "./include/AES256CBC.h"
#include "./include/log.h"

#define BUFFER_LEN 16

// https://rsdn.org/article/unix/sockets.xml

void clearBUFFER(unsigned char* buffer);
std::string bytes2str(const unsigned char* bytes, unsigned len);
void transmitter(const char *pathToFile, const char *password, int port, const char* ip);
void receiver(const char *pathToFile, const char *password, int port);

union Long64
{
   unsigned long l;
   unsigned char c[8];
};

/*
sharek out {ip} {port} {password} {filename}
  0     1    2     3        4         5
sharek in {port} {password} {filename}
  0     1    2       3           4
*/
int main(int argc, char *argv[])
{
    std::string ifSynErr("Expected: \"> sharek out {ip} {port} {password} {filename}\" or \"> sharek in {port} {password} {filename}\"");
    clog("Wake up");
    std::string buffS("");
    for(int li = 0; li < argc; ++li)
        buffS += std::string("\"") + std::string(argv[li]) + std::string("\" ");
    clog("Get args (" + std::to_string(argc) + std::string(" pieces): ") + buffS);
    if(!(argc == 6 || argc == 5))
        {std::cout << "Syntax error! " << ifSynErr << std::endl; return -1;}

    if(strcmp(argv[1], "out") == 0)
    {
        if(argc != 6)
            {std::cout << "Syntax error! " << ifSynErr << std::endl; return -1;}
        clog("I will be transmitter. ");

        transmitter(argv[5], argv[4], atoi(argv[3]), argv[2]);
    }
    else if(strcmp(argv[1], "in") == 0)
    {
        if(argc != 5)
            {std::cout << "Syntax error! " << ifSynErr << std::endl; return -1;}
        clog("I will be receiver. ");
        receiver(argv[4], argv[3], atoi(argv[2]));
    }
    else
    {
        std::cout << "Syntax error! " << ifSynErr << std::endl;
        return -1;
    }
    return 0;
}

void transmitter(const char *pathToFile, const char *password, int port, const char* ip)
{
    int sock;
    struct sockaddr_in addr;
    AES256CBC aes;
    unsigned char buff[BUFFER_LEN];
    unsigned char buff_en[BUFFER_LEN];

    clog("Creating socket... ");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        perror("socket");
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    // addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    clog(std::string("Connecting to: ") + std::string(inet_ntoa(addr.sin_addr)) + std::string(":") + std::to_string(htons(addr.sin_port)) + "... ");
    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        exit(2);
    }

    clog(std::string("Openning file (rb): \"") + std::string(pathToFile) + std::string("\"... "));
    /*
    Информационное сообщение. Первые 8 байт - это размер файла
    Следующие 4 байта - это keycheck
    */
    union Long64 file_size;
	FILE *fptr;
	fptr = fopen(pathToFile, "rb");
	if(fptr == NULL)
	{
		printf("Cannot open file");
		return;
	}

    clog("Checking file size... ");

	fseek(fptr, 0L, SEEK_END);
	long sz = ftell(fptr);
	fseek(fptr, 0L, SEEK_SET);

    clog("File size: " + std::to_string(sz) + std::string(" bytes. "));

    clog("Forming info block: file size and keycheck... ");

    file_size.l = sz;
    clearBUFFER(buff);
    for(unsigned li = 0; li < 8; ++li)
        buff[li] = file_size.c[li];
    buff[9] = 133; buff[10] = 50; buff[11] = 51; buff[12] = 7;

    clog(std::string("Info block formed: ") + bytes2str(buff, BUFFER_LEN));

    clog("Generating key and iv...");
    unsigned char key[32];
    unsigned char iv_buff[32];
    calc_256hash(password, strlen(password), key);
    std::string iv_buff_s = std::string(password) + bytes2str(key, 32);
    calc_256hash(iv_buff_s.c_str(), iv_buff_s.length(), iv_buff);
    unsigned char iv[16];
    for(unsigned li = 0; li < 16; ++li)
        iv[li] = iv_buff[li];
    
    aes.EncryptCBC(buff, buff_en, BUFFER_LEN, key, iv);
    send(sock, buff_en, BUFFER_LEN, 0);

    clog("Transmitting... ");
    const unsigned beforePercentOut_begin = sz/(100*16*2);
    unsigned beforePercentOut = beforePercentOut_begin;
    unsigned left = 0;
    std::cout << "Transmitted: " << left << "%" << std::flush;

	long c = sz;
	long cur_block_size;
	while(c > 0)
	{
		cur_block_size = c>BUFFER_LEN?BUFFER_LEN:c;
		if(c > BUFFER_LEN)
            c-=BUFFER_LEN;
        else
        {
            clearBUFFER(buff);
            c = 0;
        }
		//c-=BS; c=(c>0?c:0);
		
		fread(buff, sizeof(unsigned char), cur_block_size, fptr);
        aes.EncryptCBC(buff, buff_en, BUFFER_LEN, key, iv);
        send(sock, buff_en, BUFFER_LEN, 0);

        --beforePercentOut;
        if(beforePercentOut == 0)
        {
            beforePercentOut = beforePercentOut_begin;
            std::cout << (left<10?"\b\b":(left<100?"\b\b\b":"\b\b\b\b"));
            left = 100 - unsigned((float)c/(float)sz*100);
            std::cout << left << "%"<< std::flush;
        }
	}
    std::cout << (left<10?"\b\b":(left<100?"\b\b\b":"\b\b\b\b")) << "100%. " << std::endl;

    fclose(fptr);

    clog("File transmitted and closed. ");

    clog("Checking file hash... ");
    clog("Calculating file hash... ");

    clog("Transmitting file hash... ");
    unsigned char filehash[32];
    calc_file_hash(pathToFile, filehash);
    for(unsigned li = 0; li < 16; ++li)
        buff[li] = filehash[li];
    aes.EncryptCBC(buff, buff_en, BUFFER_LEN, key, iv);
    send(sock, buff_en, BUFFER_LEN, 0);

    for(unsigned li = 0; li < 16; ++li)
        buff[li] = filehash[16 + li];
    aes.EncryptCBC(buff, buff_en, BUFFER_LEN, key, iv);
    send(sock, buff_en, BUFFER_LEN, 0);

    clog("Clossing socket. ");
    close(sock);
    clog("========== Done! ==========");
}

void receiver(const char *pathToFile, const char *password, int port)
{
    AES256CBC aes;
    unsigned char buff[BUFFER_LEN];
    unsigned char buff_en[BUFFER_LEN];
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    clog("Creating socket... ");
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    clog(std::string("Binding socket: PORT=") + std::to_string(port) + "... ");
    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    clog("Start listen... ");
    if (listen(server_fd, 1) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, 
                (struct sockaddr*)&address,
                (socklen_t*)&addrlen)) < 0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    clog(std::string("New connection: ") + std::string(inet_ntoa(address.sin_addr)) + std::string(":") + std::to_string(htons(address.sin_port)));

    clog("Generating key and iv...");

    unsigned char key[32];
    unsigned char iv_buff[32];
    calc_256hash(password, strlen(password), key);
    std::string iv_buff_s = std::string(password) + bytes2str(key, 32);
    calc_256hash(iv_buff_s.c_str(), iv_buff_s.length(), iv_buff);
    unsigned char iv[16];
    for(unsigned li = 0; li < 16; ++li)
        iv[li] = iv_buff[li];

    clog("Getting info block: file size and keycheck... ");
    clearBUFFER(buff_en);
    read(new_socket, buff_en, BUFFER_LEN);
    aes.DecryptCBC(buff_en, buff, BUFFER_LEN, key, iv);

    clog(std::string("Info block received: ") + bytes2str(buff, BUFFER_LEN));

    if(!(buff[9] == 133 && buff[10] == 50 && buff[11] == 51 && buff[12] == 7))
    {
        std::cout << "Key does not match. " << std::endl;
        clog("keycheck failed. Key does not match. ");
        return;
    }
    union Long64 file_size;
    for(unsigned li = 0; li < 8; ++li)
        file_size.c[li] = buff[li];
    long sz = file_size.l;
clog(std::string("Size of file will be: ") + std::to_string(sz) + std::string(" bytes. "));

    clog("Openning file (wb): \"" + std::string(pathToFile) + std::string("\"... "));
	FILE *fptr;
	fptr = fopen(pathToFile, "wb");
	if(fptr == NULL)
	{
		printf("Cannot open file");
		return;
	}

    clog("Receiving...");
    const unsigned beforePercentOut_begin = sz/(100*16*2);
    unsigned beforePercentOut = beforePercentOut_begin;
    unsigned left = 0;
    std::cout << "Received: " << left << "%" << std::flush;

	long c = sz;
	long cur_block_size;
	while(c > 0)
	{
		cur_block_size = c>BUFFER_LEN?BUFFER_LEN:c;
		if(c > BUFFER_LEN)
            c-=BUFFER_LEN;
        else
        {
            clearBUFFER(buff);
            c = 0;
        }
		//c-=BS; c=(c>0?c:0);
        read(new_socket, buff_en, BUFFER_LEN);
        aes.DecryptCBC(buff_en, buff, BUFFER_LEN, key, iv);
		
		fwrite(buff, sizeof(unsigned char), cur_block_size, fptr);

        --beforePercentOut;
        if(beforePercentOut == 0)
        {
            beforePercentOut = beforePercentOut_begin;
            std::cout << (left<10?"\b\b":(left<100?"\b\b\b":"\b\b\b\b"));
            left = 100 - unsigned((float)c/(float)sz*100);
            std::cout << left << "%"<< std::flush;
        }
	}
    std::cout << (left<10?"\b\b":(left<100?"\b\b\b":"\b\b\b\b")) << "100%. " << std::endl;
    
    fclose(fptr);
    
    clog("File recieved and closed. ");

    clog("Checking file hash... ");
    clog("Calculating file hash... ");

    unsigned char filehash[32];
    unsigned char filehash_received[32];
    calc_file_hash(pathToFile, filehash);

    clog("Receiving file hash... ");
    read(new_socket, buff_en, BUFFER_LEN);
    aes.DecryptCBC(buff_en, buff, BUFFER_LEN, key, iv);
    for(unsigned li = 0; li < 16; ++li)
        filehash_received[li] = buff[li];
    
    read(new_socket, buff_en, BUFFER_LEN);
    aes.DecryptCBC(buff_en, buff, BUFFER_LEN, key, iv);
    for(unsigned li = 0; li < 16; ++li)
        filehash_received[16 + li] = buff[li];
    
    bool if_eq = true;
    for(unsigned li = 0; li < 32; ++li)
        if(filehash[li] != filehash_received[li])
            if_eq = false;
    
    clog("Comparing file hashes...");
    clog(std::string("Calculated hash: ") + bytes2str(filehash, 32));
    clog(std::string("Received hash:   ") + bytes2str(filehash_received, 32));

    if(if_eq == true)
        clog("Hash of file matches! ");
    else
        clog("\n==============================\n\n!!!!! Hash of file does not match !!!!!\n\n==============================\n");

    clog("Clossing socket. ");
    close(new_socket);
    shutdown(server_fd, SHUT_RDWR);
    clog("========== Done! ==========");
}

std::string bytes2str(const unsigned char* bytes, unsigned len)
{
    std::stringstream ss;

    for(unsigned i = 0; i < len; ++i)
        if(i == 0)
            ss << (int)bytes[i];
        else
            ss << "_" << (int)bytes[i];
    return ss.str();
}

void clearBUFFER(unsigned char* buffer)
{
    for(unsigned i = 0; i < BUFFER_LEN; ++i)
        buffer[i] = 0;
}