#ifndef _SUEXEC_RLIMIT_H
#define _SUEXEC_RLIMIT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>
#include <sys/resource.h>

struct userlimits {
	char *username;	/* Username */
	rlim_t memlimit;	/* Maximum allowed memory */
	rlim_t cputime;	/* Maximum CPU time*/
	rlim_t nproc;	/* Number of processes */
	rlim_t fsize;	/* Maximum allowed size of the biggest file that can be opened */
	rlim_t ofile;	/* Maximum opened files */
};

extern struct userlimits *getliment (void);
extern struct userlimits *fgetliment (FILE *__stream);

struct userlimits * fgetliment (FILE *fp);

char *buffer;
size_t buflen;
struct userlimits ul;

/* Since these are static, they don't need to be defined here
static char * parse_line (char *s, char **p);
static struct userlimits * getentry (char *s);
*/

#endif /* _SUEXEC_RLIMIT_H */
