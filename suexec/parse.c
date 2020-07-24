/****************************************************************/
/*Program: PARSE.C                                              */
/*Author:  HackMan                                              */
/*Comment: Program to read in a sentence of words within a file */
/*         and parse them into seperate lines of words.         */
/****************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
// #define DEBUG
struct ret {
	int user;
	int home;
};

#include "mounts_check.h"
int main(int argc, char *argv[]) {                    /* Program entry point */
	char username[12];
	int ret = -1;

	if (argc == 2) {
		sprintf(username, "%s", argv[1]);
		if (strlen(username) > 10) {
			printf("Error: username too long!");
			return 1;
		}
		printf("Checking mount for user: %s\n", username);
	} else {
		printf("Error: no username supplied!\nUsage: ./parse username\n");
		return 2;
	}
	ret = check_mount(username);
	if (ret == 0)
		printf("%s's mounts are ok!\n", username);
	else {
		if (ret == 5) {
			printf("Error: unable to find user and home mounts for user %s\n", username);
			return 1;
		}
		if (ret == 6) {
			printf("Error: unable to find user mount for user %s\n", username);
			return 1;
		}
		if (ret == 7) {
			printf("Error: unable to find home mount for user %s\n", username);
			return 1;
		}
	}

	return 0; /* Executed without errors */
} /* End main */
