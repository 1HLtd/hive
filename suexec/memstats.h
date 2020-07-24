#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>

#define BUFFER_SIZE 321
#define BUFFER_READ 320
#define MAX_PATH 24
#define PARAM 21
#define MEMSOCK_PATH "/tmp/memstats.sock"

long long get_part(char *buf, int received, int param);
int get_memusage(int *pid, long long *mem);
// This function is commented since it was only used during development and testing
//int save_mem_io(uid_t *uid, long long *mem, int *memcount, long *read_chars, long *write_chars, long *read_bytes, long *write_bytes);
