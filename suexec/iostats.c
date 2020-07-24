#include "iostats.h"

long get_io_part(char *buf, int received, int line) {
	int lines = 0;
	int i = 0;
	char *point = NULL;
	// get the line that I need
	for (i=0; i<=received;i++) {
		if (buf[i] == '\n') 	// found a newline
			buf[i] = '\0';		// replace it with NULL terminator in case we use this line
		if (buf[i] == '\0') 
			lines++;
		if (lines == line)
			if (buf[i] == ' ') {
				point = &buf[i+1];
			}
		if (lines == line+1)
			break;
	}
/* if we haven't reached the next space it probably means tha we 
   haven't read the whole stat file so we should return err */
	if (lines != line+1) 
		return -2;

	return atol(point);
}

int get_io_usage(pid_t *pid, long *read_chars, long *write_chars, long *read_bytes, long *write_bytes) {
	int fd = 0;
	int received = 0;
	char path[IOMAX_PATH];
	char buf[IOBUFFER_SIZE];

	sprintf(path,"/proc/%d/io", *pid);
	fd = open(path, O_RDONLY);
	if ( fd == -1 )
		return 1;
	
	received = read(fd,buf,IOBUFFER_READ);
	if (received == -1)
		return 2;
	buf[received] = '\0';
	*read_chars = get_io_part(buf, received, 0);
//	printf("Read chars: %ld\n", *read_chars);
	*write_chars = get_io_part(buf, received, 1);
//	printf("Write chars: %ld\n", *write_chars);
	*read_bytes = get_io_part(buf, received, 5);
//	printf("Read bytes: %ld\n", *read_bytes);
	*write_bytes = get_io_part(buf, received, 6);
//	printf("Write bytes: %ld\n", *write_bytes);
	close(fd);
	return 0;
}
/*
int save_io_usage(int *uid, long long *mem) {
	// socket connection vars
	int sockfd, srvlen;
	struct sockaddr_un srvaddr;
	char msg_buffer[80];
	sprintf(msg_buffer, "%d %lld\n", *uid, *mem);

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
	long reads = 0;
	long writes = 0;
	struct timespec sleeper;
	sleeper.tv_sec = 0;
	sleeper.tv_nsec = 500000000;

	if (argc <= 1) {
		printf("Usage: %s pid\n", argv[0]);
		return 1;
	}
	pid = atoi(argv[1]);

	while(get_io_usage(&pid, &reads, &writes)==0) {
		nanosleep(&sleeper, NULL);
	}
	printf("Total reads:\t%ld\t writes:\t%ld\n", reads, writes);
	return 0;
}
*/
