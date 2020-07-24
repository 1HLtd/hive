#include "memstats.h"

#define BUFFER_SIZE 321
#define BUFFER_READ 320
#define MAX_PATH 24
#define PARAM 21

/* Debugging :) next time include <stdlib.h>
long long convert(char *x) {
	long long res = 0;
	while (*x) {
		if (*x == ' ')
			break;
		res = 10L*res + *x-'0';
		x++;
	}   
	return res;
}
*/

long long get_part(char *buf, int received, int param) {
	int spaces = 0;
	int i = 0;
	char *point = NULL;

	for (i=0; i<=received;i++) {
		if (buf[i] == ' ' || buf[i] == '\0') {			// found a space
			spaces++;
			buf[i] = '\0';
			if (spaces == param)
				point = &buf[i+1];
		}
		if (spaces == param+1) 
			break;
	}
/* if we haven't reached the next space it probably means tha we 
   haven't read the whole stat file so we should return err */
	if (spaces != param+1) 
		return -2;
/* Debugging :) next time include <stdlib.h>
	printf("|%lld|\n", atoll(point));
	printf("|%lld|\n", strtoll(point, (char **) NULL, 10));
	printf("|%lld|\n", convert(point));
*/
	return atoll(point);
}

int get_memusage(int *pid, long long *mem) {
	int fd = 0;
	int received = 0;
	char path[MAX_PATH];
	char buf[BUFFER_SIZE];

	sprintf(path,"/proc/%d/stat", *pid);
	fd = open(path, O_RDONLY);
	if ( fd == -1 )
		return 1;
	
	received = read(fd,buf,BUFFER_READ);
	if (received == -1)
		return 2;

	buf[received] = '\0';
	*mem += get_part(buf, received, 22);
	close(fd);
	return 0;
}

/*
int save_mem_io(
	uid_t *uid,
	long long *mem,
	int *memcount,
	long *read_chars,
	long *write_chars,
	long *read_bytes,
	long *write_bytes) {
	// socket connection vars
	int sockfd, srvlen;
	struct sockaddr_un srvaddr;
	char msg_buffer[80];
	sprintf(msg_buffer, "%d %lld %ld %ld %ld %ld\n", *uid, *mem / *memcount, *read_chars, *write_chars, *read_bytes, *write_bytes);

	// connect to the socket and send the collected stats
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("stats socket");
		return 1;
	}
	srvaddr.sun_family = AF_UNIX;
	strcpy(srvaddr.sun_path, MEMSOCK_PATH);
	srvlen = strlen(srvaddr.sun_path) + sizeof(srvaddr.sun_family);
	if (connect(sockfd, (struct sockaddr *) &srvaddr, srvlen) == 0) {
		write(sockfd, &msg_buffer, strlen(msg_buffer));
		close(sockfd);
	}
	return 0;
}
int save_memusage(int *uid, long long *mem, int *memcount) {
	// socket connection vars
	int sockfd, srvlen;
	struct sockaddr_un srvaddr;
	char msg_buffer[80];
	sprintf(msg_buffer, "%d %lld\n", *uid, *mem / *memcount);

	// connect to the socket and send the collected stats
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("stats socket");
		return 1;
	}
	srvaddr.sun_family = AF_UNIX;
	strcpy(srvaddr.sun_path, MEMSOCK_PATH);
	srvlen = strlen(srvaddr.sun_path) + sizeof(srvaddr.sun_family);
	if (connect(sockfd, (struct sockaddr *) &srvaddr, srvlen) == 0) {
		write(sockfd, &msg_buffer, strlen(msg_buffer));
		close(sockfd);
	}
	return 0;
}

int main(int argc, char *argv[]) {
	int pid = 0;
	int count = 0;
	long long mem = 0;
	struct timespec sleeper;
	sleeper.tv_sec = 0;
	sleeper.tv_nsec = 500000000;

	if (argc <= 1) {
		printf("Usage: %s pid\n", argv[0]);
		return 1;
	}
	pid = atoi(argv[1]);

	while(get_memusage(&pid, &mem)==0) {
		nanosleep(&sleeper, NULL);
		count++;
	}
	printf("Count: %d\nTotal rss:\t%lld\nAverage rss:\t%lld\n", count, mem, mem/count);
	return 0;
}

*/
