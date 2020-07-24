#include "rlimit_config.h"

static char * parse_line (char *s, char **p) {
	if (*s) {
		char *sep = strchr (s, ':');
		if (sep) {
			*sep++ = '\0';
			*p = sep;
		} else
			*p = s + strlen (s);
    } else
    	*p = s;
	return s;
}

static struct userlimits * getentry (char *s) {
	char *p;
	ul.username = parse_line (s, &p);
	s = p;
	ul.memlimit = strtoul(parse_line (s, &p), NULL, 10);
	s = p;
	ul.cputime = strtoul(parse_line (s, &p), NULL, 10);
	s = p;
	ul.nproc = strtoul(parse_line (s, &p), NULL, 10);
	s = p;
	ul.fsize = strtoul(parse_line (s, &p), NULL, 10);
	s = p;
	ul.ofile = strtoul(parse_line (s, &p), NULL, 10);
	return &ul;
}

struct userlimits * fgetliment (FILE *fp) {
	size_t pos = 0;
	int done = 0;
	struct userlimits *ul = NULL;
	
	/* Allocate buffer if not yet available.  */
	/* This buffer will be never free().  */
	if (buffer == NULL) {
		buflen = 1024;
		buffer = malloc (buflen);
		if (buffer == NULL)
			return NULL;
	}

	do {
		if (fgets (buffer + pos, buflen, fp) != NULL) {
			/* Need a full line.  */
			if (buffer[strlen (buffer) - 1] == '\n') {
				/* reset marker position.  */
				pos = 0;
				/* Nuke trailing newline.  */
				buffer[strlen (buffer) - 1] = '\0';
	
				/* Skip comments.  */
				if (buffer[0] != '#') {
					done = 1;
					ul = getentry (buffer);
				}
			} else {
				/* Line is too long reallocate the buffer.  */
				char *tmp;
				pos = strlen (buffer);
				buflen *= 2;
				tmp = realloc (buffer, buflen);
				if (tmp)
					buffer = tmp;
				else
					done = 1;
			}
		} else
			done = 1;
	} while (!done);

	return ul;
}
