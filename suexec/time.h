#ifndef _SUEXEC_TIMES_H
#define _SUEXEC_TIMES_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/times.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "log.h"

#define SOCK_PATH "/chroot/run/cpustats_socket"

#define PARAMS(x) x
#define PTR void *

// These are used for the time mesurments
#ifndef WIFSTOPPED
#define WIFSTOPPED(w) (((w) & 0xff) == 0x7f)
#endif

#ifndef WIFSIGNALED
#define WIFSIGNALED(w) (((w) & 0xff) != 0x7f && ((w) & 0xff) != 0)
#endif

#ifndef WIFEXITED
#define WIFEXITED(w) (((w) & 0xff) == 0)
#endif

#ifndef WSTOPSIG
#define WSTOPSIG(w) (((w) >> 8) & 0xff)
#endif

#ifndef WTERMSIG
#define WTERMSIG(w) ((w) & 0x7f)
#endif

#ifndef WEXITSTATUS
#define WEXITSTATUS(w) (((w) >> 8) & 0xff)
#endif

#ifndef TICKS_PER_SEC
#define TICKS_PER_SEC 100
#endif

/* The number of milliseconds in one `tick' used by the `rusage' structure.  */
#define MSEC_PER_TICK (1000 / TICKS_PER_SEC)

/* Return the number of clock ticks that occur in M milliseconds.  */
#define MSEC_TO_TICKS(m) ((m) / MSEC_PER_TICK)

#if !defined(HZ) && defined(CLOCKS_PER_SEC)
#define HZ CLOCKS_PER_SEC
#endif
#if !defined(HZ) && defined(CLK_TCK)
#define HZ CLK_TCK
#endif
#ifndef HZ
#define HZ 60
#endif

#define TV_MSEC tv_usec / 1000
#define UL unsigned long


/* Information on the resources used by a child process.  */
typedef struct {
  int waitstatus;
  struct rusage ru;
  struct timeval start, elapsed; /* Wallclock time of process.  */
} RESUSE;

unsigned long ptok (unsigned long pages);
void resuse_start PARAMS ((RESUSE *resp));
void resuse_end	  PARAMS ((pid_t pid, RESUSE *resp));
void summarize 	 	     (
	RESUSE *resp,
    uid_t *uid,
    long long mem,
    long *read_chars,
    long *write_chars,
    long *read_bytes,
    long *write_bytes);


#endif /* _SUEXEC_TIMES_H */
