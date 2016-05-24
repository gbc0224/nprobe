#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <crsocket.h>
int init_socket(const char* ip_dest,int port_dest){
	int s,num;
	char sendbuf[BUFSIZE];

	struct sockaddr_in server_addr;
	s = socket(AF_INET,SOCK_STREAM,0);
	if(s<0){
		printf("socket error\n");
		return -1;
	}

	bzero(&server_addr,sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(ip_dest);
	server_addr.sin_port = htons(port_dest);
	//建立链接
	int resconn;
	resconn = connect(s,(struct sockaddr*) &server_addr,sizeof(struct sockaddr));
	if(resconn == -1){
		printf("connect error\n");
		return -1;
	}
	return s;
}