#include "time.h"

void resuse_start (resp) RESUSE *resp; {
#if HAVE_WAIT3
	gettimeofday (&resp->start, (struct timezone *) 0);
#else
	long value;
	struct tms tms;

	value = times (&tms);
	resp->start.tv_sec = value / HZ;
	resp->start.tv_usec = value % HZ * (1000000 / HZ);
#endif
}

void resuse_end (pid_t pid, RESUSE *resp) {
	int status;
#if HAVE_WAIT3
	pid_t caught;

	/* Ignore signals, but don't ignore the children.  When wait3
	   returns the child process, set the time the command finished. */
	while ((caught = wait3 (&status, 0, &resp->ru)) != pid)
		if (caught == -1)
			return;

	gettimeofday (&resp->elapsed, (struct timezone *) 0);
#else  /* !HAVE_WAIT3 */
	long value;
	struct tms tms;

	pid = wait (&status);
	if (pid == -1)
		return;

	value = times (&tms);

	memset (&resp->ru, 0, sizeof (struct rusage));

	resp->ru.ru_utime.tv_sec = tms.tms_cutime / HZ;
	resp->ru.ru_stime.tv_sec = tms.tms_cstime / HZ;

#if HAVE_SYS_RUSAGE_H
	resp->ru.ru_utime.tv_nsec = tms.tms_cutime % HZ * (1000000000 / HZ);
	resp->ru.ru_stime.tv_nsec = tms.tms_cstime % HZ * (1000000000 / HZ);
#else
	resp->ru.ru_utime.tv_usec = tms.tms_cutime % HZ * (1000000 / HZ);
	resp->ru.ru_stime.tv_usec = tms.tms_cstime % HZ * (1000000 / HZ);
#endif /* HAVE_SYS_RUSAGE_H */

	resp->elapsed.tv_sec = value / HZ;
	resp->elapsed.tv_usec = value % HZ * (1000000 / HZ);
#endif  /* HAVE_WAIT3 */

	resp->elapsed.tv_sec -= resp->start.tv_sec;
	if (resp->elapsed.tv_usec < resp->start.tv_usec) {
	/* Manually carry a one from the seconds field.  */
		resp->elapsed.tv_usec += 1000000;
		--resp->elapsed.tv_sec;
	}
	resp->elapsed.tv_usec -= resp->start.tv_usec;
	resp->waitstatus = status;
}


/* summarize: Report on the system use of a command.

   Copy the FMT argument to FP except that `%' sequences
   have special meaning, and `\n' and `\t' are translated into
   newline and tab, respectively, and `\\' is translated into `\'.

   The character following a `%' can be:
   (* means the tcsh time builtin also recognizes it)
*  P == percent of CPU this job got (total cpu time / elapsed time)
*  E == elapsed real (wall clock) time in [hour:]min:sec
*  S == system (kernel) time (seconds) (ru_stime)
*  U == user time (seconds) (ru_utime)
   e == elapsed real time in seconds

   Various memory usages are found by converting from page-seconds
   to kbytes by multiplying by the page size, dividing by 1024,
   and dividing by elapsed real time.

   RESP is resource information on the command.  
*/

unsigned long ptok (unsigned long pages) {
	static unsigned long ps = 0;
	unsigned long tmp;
	static long size = LONG_MAX;

	/* Initialization.  */
	if (ps == 0)
		ps = (long) getpagesize ();

	/* Conversion.  */
	if (pages > (LONG_MAX / ps)) {	/* Could overflow.  */
		tmp = pages / 1024;			/* Smaller first, */
		size = tmp * ps;			/* then larger.  */
	} else {						/* Could underflow.  */
		tmp = pages * ps;			/* Larger first, */
		size = tmp / 1024;			/* then smaller.  */
	}
	return size;
}

int save_stats(char *msg) {
    // socket connection vars
    int sockfd, srvlen;
    struct sockaddr_un srvaddr;
    // connect to the socket and send the collected stats
    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("stats socket");
        return 1;
    }
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, SOCK_PATH);
    srvlen = strlen(srvaddr.sun_path) + sizeof(srvaddr.sun_family);
    if (connect(sockfd, (struct sockaddr *) &srvaddr, srvlen) == 0) {
        write(sockfd, msg, strlen(msg));
        close(sockfd);
    }
    return 0;
}

void summarize (
	RESUSE *resp,
	uid_t *uid,
	long long mem,
	long *read_chars,
	long *write_chars,
	long *read_bytes,
	long *write_bytes
) {
    char msg_buffer[80];
    char *msg = msg_buffer;
    sprintf(msg, "1 %d %d.%d %d.%d %d.%d %lld %ld %ld %ld %ld",
        *uid,
        (int)resp->elapsed.tv_sec,
        (int)(resp->elapsed.tv_usec / 10000),
        (int)resp->ru.ru_utime.tv_sec,
        (int)(resp->ru.ru_utime.TV_MSEC / 10),
        (int)resp->ru.ru_stime.tv_sec,
        (int)(resp->ru.ru_stime.TV_MSEC / 10),
		mem,
		*read_chars,
		*write_chars,
		*read_bytes,
		*write_bytes
    );
    save_stats(msg);
}

