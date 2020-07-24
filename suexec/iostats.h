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

#define IOBUFFER_SIZE 321
#define IOBUFFER_READ 320
#define IOMAX_PATH 24
#define MEMSOCK_PATH "/tmp/memstats.sock"

long get_io_part(char *buf, int received, int line);
int get_io_usage(int *pid, long *read_chars, long *write_chars, long *read_bytes, long *write_bytes);
