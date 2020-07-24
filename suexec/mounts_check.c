#include "mounts_check.h"

int check_mount (char *userdir, char *homedir) {
	FILE* fp;               /* Declare file pointer variable */
	char *tok;				/* Separate strings of the line(tokens) */
	char buf[1024];			/* Buffer for reading the file */
	int found_home = 0;
	int found_user = 0;
//    struct passwd *pw;		/* password entry holder     */
	int cmp_len = strlen(userdir + CMP_START);
	
	/*
	 * If file doesn't exist or filetype isn't allowed exit and
	 * error message & return (2) control to the OS
	 */
	if ((fp = fopen("/proc/mounts","rt")) == NULL) {
		fprintf(stderr,"Error opening file: /proc/mounts\n");
		return -1;
	}

	/* Read into the buffer contents within the file stream */
	while(fgets(buf, 1024, fp) != NULL) {
		/* Here we take the second column of the input. */
		if (strtok(buf, " ") && (tok = strtok(NULL, " "))) {
#ifdef DEBUGMOUNTS
			log_err("Mountpoint %s partial check for %s (length %d)\n", tok, userdir + CMP_START, cmp_len);
#endif
			if (strncmp(tok + CMP_START, userdir + CMP_START, cmp_len) == 0) {
#ifdef DEBUGMOUNTS
				if (!found_user)
					log_err("Mountpoint %s is checked for userdir %s\n", tok, userdir);
#endif
				if (!found_user && strcmp(tok, userdir) == 0) {
					if ( found_home ) {
						fclose(fp);
						return 0;
					}
					found_user=1;
					continue;
				}
				// Check if the home folder is mounted
#ifdef DEBUGMOUNTS
				if (!found_home)
					log_err("Mountpoint %s is checked for homedir %s\n", tok, homedir);
#endif
				if (!found_home && strcmp(tok, homedir) == 0 ) {
					if ( found_user ) {
						fclose(fp);
						return 0;
					}
					found_home=1;
				}
			}
		}
	} /* Continue until EOF is encoutered */
// If the code above continues to work, we should remove the next lines and remove the usage of mount_status
// in suexec.c. This will surely simplify the code.
 	fclose(fp);
	if ( found_user == 0 && found_home == 0 )
		return(5);
	if ( found_user )
		return(7);
	else
		return(6);

	// Return the right value depending on did we found it.

}
