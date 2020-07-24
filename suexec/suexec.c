/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 * suexec.c -- "Wrapper" support program for suEXEC behaviour for Apache
 *
 ***********************************************************************
 *
 * NOTE! : DO NOT edit this code!!!  Unless you know what you are doing,
 *         editing this code might open up your system in unexpected
 *         ways to would-be crackers.  Every precaution has been taken
 *         to make this code as safe as possible; alter it at your own
 *         risk.
 *
 ***********************************************************************
 *
 *
 * Error messages in the suexec logfile are prefixed with severity values
 * similar to those used by the main server:
 *
 *  Sev     Meaning
 * emerg:  Failure of some basic system function
 * alert:  Bug in the way Apache is communicating with suexec
 * crit:   Basic information is missing, invalid, or incorrect
 * error:  Script permission/configuration error
 * warn:
 * notice: Some issue of which the sysadmin/webmaster ought to be aware
 * info:   Normal activity message
 * debug:  Self-explanatory
 *
 ***********************************************************************
 * Developed by Marian Marinov a.k.a. HackMan <mm@yuhu.biz>
 * Last update: 03.Jul.2008
 ***********************************************************************
 * CHANGELOG
 *
 * 03.Jul.2008 Marian
 *  Updated the check_mount function. Added better validation.
 *
 ***********************************************************************
 */
// suexec VERSION
#define SUEXEC_VERSION "19.0"
#include "suexec.h"
#include "log.h"

// resource limits functions & types
#ifdef INCLUDELIMITS
#include "rlimit_config.h"
#endif

// times functions & declarations
#ifdef INCLUDESTATS
#include "time.h"
#endif

#include "mounts_check.h"

#ifdef MEMIOSTATS
	#include "memstats.h"
	#include "iostats.h"
#endif

/* THE TEST COMMAND:
 * the PHPHANDLER is needed only for PHP scripts
 * we must go to openfest's home folder
 * execute the suexec and provide username, groupname and locaton of the file
 * the username must be with ~ infront in order to tell the suexec that it is using userdir
 *
 * su - nobody -c 'export PHPHANDLER="/usr/local/php52/bin/php"; cd ~openfest; /usr/local/apache/bin/suexec \~openfest users cgi-bin/test.php'; echo $?
 *
 * su - nobody -c 'export PHPHANDLER="/usr/local/php52/bin/php"; /usr/local/apache/bin/suexec \~openfest users cgi-bin/test.php'; echo $?
 */


extern char **environ;
static FILE *log = NULL;
static int chroot_enabled = 1;
static int limits_disabled = 0;
static int stats_disabled = 0;
static int relaxed_perms = 0;
pid_t childpid;			/* variables to store the child's pid */

char *safe_env_lst[] = {
    /* variable name starts with */
    "HTTP_",
#ifdef MOD_SSL
    "HTTPS=",
    "HTTPS_",
    "SSL_",
#endif

    /* variable name is */
    "AUTH_TYPE=",
    "CONTENT_LENGTH=",
    "CONTENT_TYPE=",
    "DATE_GMT=",
    "DATE_LOCAL=",
    "DOCUMENT_NAME=",
    "DOCUMENT_PATH_INFO=",
    "DOCUMENT_ROOT=",
    "DOCUMENT_URI=",
    "FILEPATH_INFO=",
    "GATEWAY_INTERFACE=",
    "LAST_MODIFIED=",
    "PATH_INFO=",
    "PATH_TRANSLATED=",
    "QUERY_STRING=",
    "QUERY_STRING_UNESCAPED=",
    "REMOTE_ADDR=",
    "REMOTE_HOST=",
    "REMOTE_IDENT=",
    "REMOTE_PORT=",
    "REMOTE_USER=",
    "REDIRECT_QUERY_STRING=",
    "REDIRECT_STATUS=",
    "REDIRECT_URL=",
    "REQUEST_METHOD=",
    "REQUEST_URI=",
    "SCRIPT_FILENAME=",
    "SCRIPT_NAME=",
    "SCRIPT_URI=",
    "SCRIPT_URL=",
    "SERVER_ADMIN=",
    "SERVER_NAME=",
    "SERVER_ADDR=",
    "SERVER_PORT=",
    "SERVER_PROTOCOL=",
    "SERVER_SOFTWARE=",
    "UNIQUE_ID=",
    "USER_NAME=",
    "TZ=",
    "FPUID=",
    "FPGID=",
    "FPFD=",
    "FPEXEDIR=",
    "HTTPS=",
	"PHPHANDLER=",
	"PHPRC=",
	"PHP_AUTH_USER=",
	"APPLICATION_ENV=",
    NULL
};


static void err_output(const char *fmt, va_list ap) {
#ifdef LOG_EXEC
    time_t timevar;
    struct tm *lt;

    if (!log)
		if ((log = fopen(LOG_EXEC, "a")) == NULL) {
			fprintf(stderr, "crit: failed to open log file\n");
			perror("fopen");
			exit(100);
		}

    if (time(&timevar) == (time_t) -1)
		exit(141);
    if ((lt = localtime(&timevar)) == NULL)
		exit(142);

    fprintf(log, "[%d-%.2d-%.2d %.2d:%.2d:%.2d]: ",
	    lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
	    lt->tm_hour, lt->tm_min, lt->tm_sec);

    vfprintf(log, fmt, ap);
    fflush(log);
#endif /* LOG_EXEC */
    return;
}

void log_err(const char *fmt,...) {
#ifdef LOG_EXEC
    va_list ap;
    va_start(ap, fmt);
    err_output(fmt, ap);
    va_end(ap);
#endif /* LOG_EXEC */
    return;
}

static void clean_env(void) {
    char pathbuf[512];
    char **cleanenv;
    char **ep;
    int cidx = 0;
    int idx;

    /* While cleaning the environment, the environment should be clean.
     * (e.g. malloc() may get the name of a file for writing debugging info.
     * Bad news if MALLOC_DEBUG_FILE is set to /etc/passwd.  Sprintf() may be
     * susceptible to bad locale settings....)
     * (from PR 2790)
     */
    char **envp = environ;
    char *empty_ptr = NULL;

    environ = &empty_ptr; /* VERY safe environment */

    if ((cleanenv = (char **) calloc(AP_ENVBUF, sizeof(char *))) == NULL) {
        log_err("emerg: failed to malloc memory for environment\n");
		exit(101);
    }

    sprintf(pathbuf, "PATH=%s", SAFE_PATH);
    cleanenv[cidx] = strdup(pathbuf);
    cidx++;

#ifdef DEBUGENV
 	printf("Content-type: text/plain\n\n");
#endif
    for (ep = envp; *ep && cidx < AP_ENVBUF-1; ep++) {
#ifdef DEBUGENV
 		printf("ENV: %s\n", *ep);
#endif
		if (!strncmp(*ep, "DisableChroot", 13))
			chroot_enabled=0;
		if (!strncmp(*ep, "DisableLimits", 13))
			limits_disabled=1;
		if (!strncmp(*ep, "DisableStats", 12))
			stats_disabled=1;
		if (!strncmp(*ep, "RelaxPerms", 10))
			relaxed_perms=1;
        for (idx = 0; safe_env_lst[idx]; idx++)
            if (!strncmp(*ep, safe_env_lst[idx], strlen(safe_env_lst[idx]))) {
				cleanenv[cidx] = *ep;
				cidx++;
                break;
            }
	}
    cleanenv[cidx] = NULL;
    environ = cleanenv;
}

#ifdef APACHE2
/*
 * Validates if the given string is a valid UID/GID
 * (contains only digits)
 */
int validate_id(char *id) {
	static char * safe_chars = "1234567890";
	int i = 0;
	char *ch = id;

	while (i++ < 9 && *ch) {
		if (!strchr(safe_chars, *ch))
			return 0;
		ch++;
	}
	if (i > 9)
		return 0;
	return 1;
}
#else
/*
 * Validates if the given string is a valid user/group name
 * (contains only digits, leters _ and -)
 */
int validate_name(char *name) {
	static char * safe_chars = "1234567890-_";
	int i = 0;
	char *ch = name;

	while (i++ < 12 && *ch) {
		if (!strchr(safe_chars, *ch) && (*ch < 'a' || *ch > 'z'))
			return 0;
		ch++;
	}
	if (i > 12)
		return 0;
	return 1;
}

#endif /* APACHE2 */

static void handle_term(int sig) {
	sig = sig;
	if (childpid != 0) {
		kill(childpid,SIGTERM);
	} else {
		exit(1);
	}
}

int childwait = 1;
static void handle_chld(int sig) {
	sig = sig;
	childwait = 0;
}

int main(int argc, char *argv[]) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
    sa.sa_handler = handle_chld;
	sigaction(SIGCHLD, &sa, NULL);

#ifdef APACHE24
	sigset_t unbl;
	sigemptyset(&unbl);
	sigaddset(&unbl, SIGCHLD);
	sigprocmask(SIG_UNBLOCK, &unbl, NULL);
#endif

    uid_t uid;				/* user information				*/
    gid_t gid;				/* target group placeholder		*/
    gid_t httpgid = getgid();	/* http group				*/
    char *target_uname;		/* target user name				*/
    char *target_gname;		/* target group name			*/
    char *target_homedir;	/* target home directory		*/
    char *actual_uname;		/* actual user name				*/
    char *actual_gname;		/* actual group name			*/
//	char *prog;				/* name of this program			*/
    char *cmd;				/* command to be executed		*/
    char cwd[AP_MAXPATH];	/* current working directory	*/
    struct passwd *pw;		/* password entry holder		*/
    struct group *gr;		/* group entry holder			*/
    struct stat dir_info;	/* directory info holder		*/
    struct stat prg_info;	/* program info holder			*/
//#ifdef HAVECGIDIR
	int is_cgi_dir = 0;		/* is the cwd the CGIDIR		*/
//#endif
#ifdef INCLUDELIMITS
	struct rlimit rlim;		/* resource limits holder		*/
#endif
#ifdef INCLUDESTATS
	RESUSE tinfo;			/* resources structior for storing child's resource usage */
#endif
#ifdef MEMIOSTATS
	int memcount = 0;
	long long mem = 0;
	struct timespec sleeper;
	sleeper.tv_sec  = 0;
	sleeper.tv_nsec = 200000000;
	// 0.2 seconds
	long read_chars = 0;
	long write_chars = 0;
	long read_bytes = 0;
	long write_bytes = 0;
#endif
	int usephp;				/* do we use PHP handlers		*/
	char *phphandler;		/* path to the PHP executable	*/
	char *newargv[4];		/* container for the PHP executable */
	struct stat phpfinfo;	/* phphandler info holder		*/
#ifdef SUEXEC_CHROOT
	char chroot_path[AP_MAXPATH];
	char chroot_home[AP_MAXPATH];
	char chroot_hometmp[AP_MAXPATH];
	char chroot_tmp_mysql[AP_MAXPATH];
	char chroot_tmp_pgsql[AP_MAXPATH];
	char chroot_tmp[AP_MAXPATH];
	struct stat sb;
	char newHandler[100];
#endif
	int mount_status = -1;

#ifdef SUEXEC_CHROOT
	chroot_path[0] = '\0';
	chroot_home[0] = '\0';
	chroot_hometmp[0] = '\0';
	chroot_tmp_mysql[0] = '\0';
	chroot_tmp_pgsql[0] = '\0';
	chroot_tmp[0] = '\0';
    if (access(DISABLE_CHROOT, F_OK) == 0)
		chroot_enabled = 0;
#endif /* SUEXEC_CHROOT */

	/*
     * Start with a "clean" environment
     */
	clean_env();
//	prog = argv[0];

#ifdef PATH_TRANSLATED
	char current_path[250];
	char *script_name = NULL;
	size_t script_lenght = 0;
	script_name = getenv("SCRIPT_FILENAME");
	script_lenght = strlen(argv[3]);
	if (script_name != NULL)
		strncat(current_path, script_name, strlen(script_name) - script_lenght);

#endif /* PATH_TRANSLATED */

    /*
     * Check existence/validity of the UID of the user
     * running this program.  Error out if invalid.
     */
    uid = getuid();
    if ((pw = getpwuid(uid)) == NULL) {
		log_err("crit: invalid uid: (%ld)\n", uid);
		exit(103);
    }
    /*
     * See if this is a 'how were you compiled' request, and
     * comply if so.
     */
    if ((argc > 1) && (! strcmp(argv[1], "-V")) && ((uid == 0) || (! strcmp(HTTPD_USER, pw->pw_name)))) {
#ifdef LOG_EXEC
        fprintf(stderr, " -D LOG_EXEC=\"%s\"\n", LOG_EXEC);
#endif
#ifdef DOC_ROOT
        fprintf(stderr, " -D DOC_ROOT=\"%s\"\n", DOC_ROOT);
#endif
#ifdef SAFE_PATH
        fprintf(stderr, " -D SAFE_PATH=\"%s\"\n", SAFE_PATH);
#endif
#ifdef HTTPD_USER
        fprintf(stderr, " -D HTTPD_USER=\"%s\"\n", HTTPD_USER);
#endif
#ifdef UID_MIN
        fprintf(stderr, " -D UID_MIN=%d\n", UID_MIN);
#endif
#ifdef GID_MIN
        fprintf(stderr, " -D GID_MIN=%d\n", GID_MIN);
#endif
#ifdef SUEXEC_UMASK
        fprintf(stderr, " -D SUEXEC_UMASK=%03o\n", SUEXEC_UMASK);
#endif
#ifdef SUEXEC_CHROOT
        fprintf(stderr, " -D SUEXEC_CHROOT, CHROOT_DIR=%s, BASE_OS=%s, HOME_PATH=%s\n", CHROOT_DIR, BASE_OS, HOME_PATH);
		if (chroot_enabled == 0)
			fprintf(stderr, "!!! Chrooting disabled by %s or by DisabledChroot environtment variable!\n", DISABLE_CHROOT);
#endif
#ifdef TRUSTED_USERS_SCRIPTS
        fprintf(stderr, " -D SUEXEC_TRUSTED_USER=%d\n -D SUEXEC_TRUSTED_GROUP=%d\n", SUEXEC_TRUSTED_USER, SUEXEC_TRUSTED_GROUP);
#endif
#ifdef USERDIR_SUFFIX
        fprintf(stderr, " -D USERDIR_SUFFIX=\"%s\"\n", USERDIR_SUFFIX);
#endif
#ifdef PATH_TRANSLATED
        fprintf(stderr, " -D PATH_TRANSLATED\n");
#endif
#ifdef INCLUDELIMITS
        fprintf(stderr, " -D INCLUDELIMITS\n\tLIMITS_CONF=\"%s\"\n\tMAX_CPUTIME=%lu\n\tMAX_MEMLIMIT=%lu\n\tMAX_NUMPROC=%lu\n\tMAX_FSIZE=%lu\n\tMAX_OFILE=%lu\n",
			LIMITS_CONF, MAX_CPUTIME, MAX_MEMLIMIT, MAX_NUMPROC, MAX_FSIZE, MAX_OFILE);
		if (limits_disabled)
			fprintf(stderr, "!!! Limits disabled by DisabledLimits environment variable!\n");
#endif
#ifdef INCLUDESTATS
		fprintf(stderr, " -D INCLUDESTATS\n");
	#ifdef DEBUGSTATS
		fprintf(stderr, " -D DEBUGSTATS\n");
	#endif
	#ifdef MEMIOSTATS
		fprintf(stderr, " -D MEMIOSTATS\n");
	#endif
		if (stats_disabled)
			fprintf(stderr, "!!! Statistics disabled by DisabledStats environment variable!\n");
#endif
#ifdef HAVECGIDIR
		fprintf(stderr, " -D HAVECGIDIR\n");
#endif
#ifdef MAILMAN
		fprintf(stderr, " -D MAILMAN\n");
#endif
#ifdef STDEXEC
		fprintf(stderr, " -D STDEXEC\n");
#endif
#ifdef DEBUGMOUNTS
		fprintf(stderr, " -D DEBUGMOUNTS\n");
#endif
#ifdef DEBUG
		fprintf(stderr, " -D DEBUG\n");
#endif
#ifdef DEBUGENV
		fprintf(stderr, " -D DEBUGENV\n");
#endif
#ifdef APACHE2
        fprintf(stderr, " -D APACHE2\n");
#endif
		fprintf(stderr, " -D NO_LICENSING\n");
		fprintf(stderr, "VERSION: " SUEXEC_VERSION "\n");
		fprintf(stderr, "BUILD COMMIT: " BUILD_COMMIT "\n");
        exit(0);
    }

    /*
     * If there are a proper number of arguments, set
     * all of them to variables.  Otherwise, error out.
     */
    if (argc < 4) {
		log_err("alert: too few arguments\n");
		exit(104);
    }

    target_uname = argv[1];
    target_gname = argv[2];
    cmd = argv[3];

#ifdef DEBUG
	log_err("debug: su - nobody -c '%s \\%s %s %s'\n", argv[0], argv[1], argv[2], argv[3]);
	log_err("debug: uname: %s gname: %s cmd: %s\n", target_uname, target_gname, cmd);
#endif
    /*
     * Check to see if the user running this program
     * is the user allowed to do so as defined in
     * suexec.h.  If not the allowed user, error out.
     */
    if (strcmp(HTTPD_USER, pw->pw_name)) {
        log_err("alert: calling user mismatch (%s instead of %s)\n",
		pw->pw_name, HTTPD_USER);
		exit(105);
    }

    /*
     * Check for a leading '/' (absolute path) in the command to be executed,
     * or attempts to back up out of the current directory,
     * to protect against attacks.  If any are
     * found, error out.  Naughty naughty crackers.
     */
    if ((cmd[0] == '/') || (!strncmp(cmd, "../", 3)) || (strstr(cmd, "/../") != NULL)) {
        log_err("error: invalid command (%s)\n", cmd);
		exit(106);
    }

    /*
     * Check to see if this is a ~userdir request.  If
     * so, set the flag, and remove the '~' from the
     * target username.
     */
    if (!strncmp("~", target_uname, 1)) {
		target_uname++;
    }

#ifdef APACHE2
    /*
     * Error out if the target UID is invalid.
     */
	if (!validate_id(target_uname)) {
		log_err("crit: invalid target UID format: (%s)\n", target_uname);
		exit(107);
	}

	if ((pw = getpwuid(atoi(target_uname))) == NULL) {
		log_err("crit: invalid target UID: (%s)\n", target_uname);
		exit(108);
	}


    /*
     * Error out if the target GID is invalid.
     */
	if (!validate_id(target_gname)) {
		log_err("crit: invalid target GID format: (%s)\n", target_gname);
		exit(109);
	}
	if ((gr = getgrgid(atoi(target_gname))) == NULL) {
		log_err("crit: invalid target GID: (%s)\n", target_gname);
		exit(140);
	}

#else
    /*
     * Error out if the target username is invalid.
     */
	if (!validate_name(target_uname)) {
		log_err("crit: invalid target username format: (%s)\n", target_uname);
		exit(107);
	}

	if ((pw = getpwnam(target_uname)) == NULL) {
		log_err("crit: invalid target username: (%s)\n", target_uname);
		exit(108);
	}


    /*
     * Error out if the target group name is invalid.
     */
	if (!validate_name(target_gname)) {
		log_err("crit: invalid target group name format: (%s)\n", target_gname);
		exit(109);
	}
	if ((gr = getgrnam(target_gname)) == NULL) {
		log_err("crit: invalid target group name: (%s)\n", target_gname);
		exit(140);
	}
#endif

    /*
     * Save these for later since initgroups will hose the struct
     */
	uid = pw->pw_uid;
	actual_uname = strdup(pw->pw_name);

	gid = gr->gr_gid;
	actual_gname = strdup(gr->gr_name);

#ifndef SUEXEC_CHROOT
	target_homedir = strdup(pw->pw_dir);
#endif
	if ( strlen(actual_uname) > MAX_UNAME ) {
		log_err("emerg: username too long(more then %d chars)!\n", MAX_UNAME);
		exit(119);
	}
	if ( strlen(target_uname) > MAX_UNAME ) {
		log_err("emerg: username too long(more then %d chars)!\n", MAX_UNAME);
		exit(120);
	}

#ifdef SUEXEC_CHROOT
	if (chroot_enabled) {
		// create the chroot path:
		//		/var/suexec/%s
		strcat(chroot_path, CHROOT_DIR);
		strcat(chroot_path, actual_uname);
		// copy the chroot_path to generate home folder:
		//		/var/suexec/%s/home/%s
		strcat(chroot_home, CHROOT_DIR);
		strcat(chroot_home, actual_uname);
		/*
		 * We have not initialized target_homedir (because SUEXEC_CHROOT is defined) so we can initialize it here.
		 * Target homedir is the last part of the chroot_home string.
		 */
		target_homedir = chroot_home + sizeof(CHROOT_DIR) + strlen(actual_uname) - 1;
		strcat(chroot_tmp, chroot_home);
		strcat(chroot_tmp, "/tmp");
# if defined(PLESK) || defined(PLAIN)
		/*
		 * !!!!!!!
		 * Be careful with this pw (it can be used this way if and only
		 * if the last call to getpwnam/getpwid is for the target user.
		 */
		strcat(chroot_home, pw->pw_dir);
# else
		strcat(chroot_home, HOME_PATH);
		strcat(chroot_home, actual_uname);
# endif /* PLESK */
		strcat(chroot_hometmp, chroot_home);
		strcat(chroot_hometmp, "/tmp");
		strcat(chroot_tmp_mysql, chroot_hometmp);
		strcat(chroot_tmp_mysql, "/mysql.sock");
		strcat(chroot_tmp_pgsql, chroot_hometmp);
		strcat(chroot_tmp_pgsql, "/.s.PGSQL.5432");
	}
#endif /* SUEXEC_CHROOT */

		/* check if it's a php file */
		phphandler = getenv("PHPHANDLER");
		if (phphandler) {
		#ifdef SUEXEC_CHROOT
				/* Build PHP handler for later use */
				strcpy(newHandler, chroot_path);
				strncat(newHandler, phphandler, 32);
		#endif /* SUEXEC_CHROOT */
			usephp = 1;
		} else {
			usephp = 0;
		}


	/*
	 * Get the current working directory before the chroot.
	 * We will chdir to it after we chroot into chroot_path.
	 */
	if (getcwd(cwd, AP_MAXPATH) == NULL) {
		log_err("emerg: cannot get current working directory\n");
		exit(124);
	}


	if (phphandler)
#ifdef DEBUG
		log_err("info: (target/actual) uid: (%s/%s) gid: (%s/%s) cmd: %s/%s php: %s\n",
			target_uname, actual_uname,	target_gname, actual_gname,	cwd, cmd, phphandler);
#else
		log_err("info: [usr/grp]: %s/%s cmd: %s/%s php: %s\n",
			actual_uname, actual_gname, cwd, cmd, phphandler);
#endif
	else
#ifdef DEBUG
		log_err("info: (target/actual) uid: (%s/%s) gid: (%s/%s) cmd: %s\n",
			target_uname, actual_uname,	target_gname, actual_gname,	cwd, cmd);
#else
		log_err("info: [usr/grp]: %s/%s cmd: %s/%s\n", actual_uname, actual_gname, cwd, cmd);
#endif

	/*
	* Error out if attempt is made to execute as root or as
	* a UID less than UID_MIN.  Tsk tsk.
	*/

#if defined(PLESK) || defined(PLAIN)
	/*
	 * On some older versions of Plesk the apache UID is a lot less than our UID_MIN
	 * so we check if the UID is less than UID_MIN and the user is not HTTPD_USER.
	 */
	if ((uid == 0 || uid < UID_MIN) && strncmp(actual_uname, HTTPD_USER, sizeof(HTTPD_USER))) {
#else
	if (uid == 0 || uid < UID_MIN) {
#endif
		log_err("crit: cannot run as forbidden uid (%d/%s)\n", uid, cmd);
		exit(120);
	}

	/*
	* Error out if attempt is made to execute as root group
	* or as a GID less than GID_MIN.  Tsk tsk.
	*/
#if defined(PLESK) || defined(PLAIN)
	/*
	 * On some older versions of Plesk the apache GID is a lot less than our GID_MIN
	 * so we check if the GID is less than GID_MIN and he group is not HTTPD_USER.
	 */
	if ((gid == 0 || gid < GID_MIN) && strncmp(actual_gname, HTTPD_USER, sizeof(HTTPD_USER))) {
#else
	if (gid == 0 || gid < GID_MIN) {
#endif
		log_err("crit: cannot run as forbidden gid (%d/%s)\n", gid, cmd);
		exit(121);
	}

	/*
	* Stat the cwd and verify it is a directory, or error out.
	*/
	if (((lstat(cwd, &dir_info)) != 0) || !(S_ISDIR(dir_info.st_mode))) {
		log_err("error: cannot stat directory: (%s)\n", cwd);
		exit(128);
	}
#ifndef PLESK
	/*
	* Error out if cwd is writable by others.
	*/
#ifdef MAILMAN
	if ((strncmp(cwd, "/usr/local/cpanel/3rdparty/mailman/", 35)) != 0) {
#endif /* MAILMAN */
		if ((dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP)) {
			log_err("error: directory is writable by others: (%s)\n", cwd);
			exit(129);
		}
#ifdef MAILMAN
	} else {
		if ((dir_info.st_mode & S_IWOTH)) {
			log_err("error: directory is writable by others: (%s)\n", cwd);
			exit(129);
		}
	}
#endif /* MAILMAN */
#endif /* PLESK */
	/*
	 * Error out if we cannot stat the program or the file to which the link is pointing.
	 */
	if ((stat(cmd, &prg_info)) != 0) {
		log_err("error: cannot stat program: (%s)\n", cmd);
		exit(130);
	}
#ifndef PLESK
	/*
	 * Error out if the program is writable by others.
	 */
	if ((prg_info.st_mode & S_IWOTH) || (prg_info.st_mode & S_IWGRP)) {
		log_err("error: file is writable by others: (%s/%s)\n", cwd, cmd);
		exit(131);
	}
#endif /* PLESK */

	/*
	 * Error out if the target name/group is different from
	 * the name/group of the cwd or the program.
	 */
#ifdef MAILMAN
	if ((strncmp(cwd, "/usr/local/cpanel/3rdparty/mailman/", 35)) != 0) {
#endif /* MAILMAN */

#ifdef HAVECGIDIR
	if (!strstr(cwd, CGIDIR)) {
		if ((uid != dir_info.st_uid) || ((gid != dir_info.st_gid) && (dir_info.st_gid != httpgid)) ||
			(uid != prg_info.st_uid) || ((gid != prg_info.st_gid) && (prg_info.st_gid != httpgid))) {

	#ifdef TRUSTED_USERS_SCRIPTS
			if (SUEXEC_TRUSTED_USER != prg_info.st_uid ||
				SUEXEC_TRUSTED_GROUP != prg_info.st_gid) {
					log_err("error: targEt uid/gid (%ld/%ld) mismatch with directory (%ld/%ld) or "
							"program (%ld/%ld) or trusted user (%d/%d)\n", uid, gid,
							dir_info.st_uid, dir_info.st_gid,
							prg_info.st_uid, prg_info.st_gid,
							SUEXEC_TRUSTED_USER, SUEXEC_TRUSTED_GROUP);
					exit(133);
				}
	#else	/* TRUSTED_USERS_SCRIPTS */
			log_err("error: tarGet uid/gid (%ld/%ld) mismatch with directory (%ld/%ld) or program (%ld/%ld)\n",
				uid, gid, dir_info.st_uid, dir_info.st_gid,	prg_info.st_uid, prg_info.st_gid);
			exit(134);
	#endif	/* TRUSTED_USERS_SCRIPTS */
		}
	} else {
			/* Check if the owner of the CGI directory is the right one */
			if ((dir_info.st_uid != CGIDIRUID) || (dir_info.st_gid != CGIDIRGID)) {
				log_err("error: taRget uid/gid (%ld/%ld) mismatch with cgi-bin directory %s (%ld/%ld)\n",
					dir_info.st_uid, dir_info.st_gid, cwd, CGIDIRUID, CGIDIRGID);
				exit(135);
			}
			is_cgi_dir = 1;
	}
	/* If the if failed, we have entered the default CGI dir */
#else	/* HAVECGIDIR */
# ifdef PLESK
	/* We have finished using the gr pointer so we can reuse it here. */
	if ((gr = getgrnam(PLESK_GROUP)) == NULL) {
		log_err("error: Failed to get Plesk group!\n");
		exit(143);
	}
	if ((uid != dir_info.st_uid) || ((gid != dir_info.st_gid) && (dir_info.st_gid != httpgid) && (dir_info.st_gid != gr->gr_gid)) ||
		(uid != prg_info.st_uid) || ((gid != prg_info.st_gid) && (prg_info.st_gid != httpgid))) {
# else /* !PLESK */
	if ((uid != dir_info.st_uid) || ((gid != dir_info.st_gid) && (dir_info.st_gid != httpgid)) ||
		(uid != prg_info.st_uid) || ((gid != prg_info.st_gid) && (prg_info.st_gid != httpgid))) {
# endif /* PLESK */
	#ifdef TRUSTED_USERS_SCRIPTS
		if (SUEXEC_TRUSTED_USER != prg_info.st_uid ||
			SUEXEC_TRUSTED_GROUP != prg_info.st_gid) {
			log_err("error: tArget uid/gid (%ld/%ld) mismatch with directory (%ld/%ld) or "
				"program (%ld/%ld) or trusted user (%d/%d)\n", uid, gid,
				dir_info.st_uid, dir_info.st_gid,
				prg_info.st_uid, prg_info.st_gid,
				SUEXEC_TRUSTED_USER, SUEXEC_TRUSTED_GROUP);
			exit(136);
		}
	#else	/* TRUSTED_USERS_SCRIPTS */
		log_err("error: Target uid/gid (%ld/%ld) mismatch with directory (%ld/%ld) or program (%ld/%ld)\n",
			uid, gid, dir_info.st_uid, dir_info.st_gid,	prg_info.st_uid, prg_info.st_gid);
		exit(137);
	#endif	/* TRUSTED_USERS_SCRIPTS */
	}
#endif		/* HAVECGIDIR */

	/*
	 * Error out if the file is setuid or setgid.
	 */
	if ((prg_info.st_mode & S_ISUID) || (prg_info.st_mode & S_ISGID)) {
	#ifdef TRUSTED_USERS_SCRIPTS
		if (SUEXEC_TRUSTED_USER != prg_info.st_uid ||
			SUEXEC_TRUSTED_GROUP != prg_info.st_gid) {
			log_err("error: file is either setuid or setgid: (%s/%s)\n", cwd, cmd);
			exit(132);
		}
	#else	/* TRUSTED_USERS_SCRIPTS */
			log_err("error: file is either setuid or setgid: (%s/%s)\n", cwd, cmd);
			exit(132);
	#endif	/* TRUSTED_USERS_SCRIPTS */
	}
#ifdef MAILMAN
	}
#endif

#if (defined(PLESK) || defined(PLAIN)) && defined(TRUSTED_USERS_SCRIPTS)
	if (prg_info.st_uid == SUEXEC_TRUSTED_USER && prg_info.st_gid == SUEXEC_TRUSTED_GROUP) {
		chroot_enabled = 0;
		phphandler = DEFAULT_PHP_HANDLER;
	}
#endif

			/*
			* Error out if the program is not executable for the user.
			* Otherwise, she won't find any error in the logs except for
			* "[error] Premature end of script headers: ..."
			*
			* if this is a php script, skip the check for execute permissions
			*/
	if (!usephp)
		if (!(prg_info.st_mode & S_IXUSR)) {
			log_err("error: file has no execute permission: (%s/%s)\n", cwd, cmd);
			exit(138);
		}
#ifdef SUEXEC_UMASK
	/*
	* umask() uses inverse logic; bits are CLEAR for allowed access.
	*/
	if ((~SUEXEC_UMASK) & 0022)
		log_err("notice: SUEXEC_UMASK of %03o allows write permission to group and/or other\n", SUEXEC_UMASK);
	umask(SUEXEC_UMASK);
#endif /* SUEXEC_UMASK */

#ifdef DEBUG
	#ifdef PATH_TRANSLATED
	log_err("debug: SUEXEC VARS\n  PATH_TRANSLATED: %s\n  target_homedir: %s\n  chroot_path: %s\n  chroot_home: %s\n",
		current_path, target_homedir, chroot_path, chroot_home);
	#else
	log_err("debug: SUEXEC VARS\n  target_homedir: %s\n  chroot_path: %s\n  chroot_home: %s\n",
		target_homedir, chroot_path, chroot_home);
	#endif	/* PATH_TRANSLATED */
#endif		/* DEBUG */

#ifdef PATH_TRANSLATED
       if (current_path != NULL) {
           if (strncmp(current_path, target_homedir, strlen(target_homedir)) == 0) {
               char *new_path = current_path + strlen(target_homedir);
               int buf_size = strlen(new_path) + 20;
               char *buf = NULL;
               buf = malloc(buf_size);
               if (buf == NULL) {
                   log_err("crit: memory allocation failed (%i bytes)\n", buf_size);
                   exit(110);
               }
               snprintf(buf, buf_size, "PATH_TRANSLATED=%s", new_path);
               putenv(buf);
			} else {
				char *sanitised_current_path = NULL;
                char *p = NULL;

                /* sanitise what we got in PATH_TRANSLATED to avoid
                 * potential log curruption (suggested by Colm MacCarthaigh).
                 */
                p = sanitised_current_path = strdup(current_path);
                if (p == NULL) {
                    log_err("crit: failed to duplicate PATH_TRANSLATED");
                    exit(111);
                }
#ifdef DEBUG
				log_err("   SANITISED PATH: %s\n", sanitised_current_path);
#endif
                while(*p != '\0') {
                    if ((*p < 32)||(*p > 126)) *p = '_';
                    p++;
                }
#ifdef DEBUG
                log_err("debug: script not within home dir (script=%s, home=%s)\n", sanitised_current_path, target_homedir);
#endif
                exit(112);
            }
        }
#endif /* PATH_TRANSLATED */
/*
 * If defined PREMOUNT we stat the directory and only
 * if the dir is not existing, we create it and mount the base os.
 * If the dir is existing we asume that there is already mounted
 * baseos in it.
 */
#ifdef SUEXEC_CHROOT
	if (chroot_enabled) {
#ifdef HAVECGIDIR
		if (is_cgi_dir == 0)
#endif /* HAVECGIDIR */
			if (stat(chroot_path, &sb) != 0) {
				if (mkdir(chroot_path, 0711) == -1) {
					log_err("emerg: unable to create %s, error: %s\n", chroot_path, strerror(errno));
					exit(113);
				}
			}

		mount_status = check_mount(chroot_path, chroot_home);
		if (mount_status == -1) {
			log_err("emerg: unable to check the mounts of user %s", actual_uname);
			exit(114);
		}

		#ifdef DEBUGMOUNTS
		log_err("debug: mounting baseos(%s) to chroot(%s)\n", BASE_OS, chroot_path);
		#endif
#ifdef HAVECGIDIR
		if (is_cgi_dir == 0)
#endif /* HAVECGIDIR */
			if (mount_status == 5 || mount_status == 6)
				if (mount(BASE_OS, chroot_path, "ext3", MS_MGC_VAL | MS_BIND | MS_REC | MS_NOSUID, "" ) == -1) {
					log_err("emerg: mount error: Source: %s Destination: %s ERROR: %s\n", BASE_OS, chroot_path, strerror(errno));
					exit(115);
				}
#ifdef HAVECGIDIR
		if (is_cgi_dir == 0) {
#endif /* HAVECGIDIR */
			if (stat(chroot_home, &sb) != 0) {
				if (mkdir(chroot_home, 0711) == -1) {
					log_err("crit: unable to create %s, error: %s\n", chroot_home, strerror(errno));
					exit(116);
				}
			}
#ifdef HAVECGIDIR
		}
#endif

		#ifdef DEBUGMOUNTS
		log_err("debug: mounting target homedir(%s) in chroot(%s)\n", target_homedir, chroot_home);
		#endif

#ifdef HAVECGIDIR
		if (is_cgi_dir == 0) {
#endif /* HAVECGIDIR */
			if (mount_status == 5 || mount_status == 7) {
				if (mount(target_homedir, chroot_home, "ext3", MS_MGC_VAL | MS_BIND | MS_REC | MS_NOSUID | MS_NODEV, "" ) == -1) {
					log_err("crit: mount error: Source: %s Destination: %s ERROR: %s\n", target_homedir, chroot_home, strerror(errno));
					exit(117);
				}
				if (lstat(chroot_tmp, &sb) == -1) {
					// create /var/suexec/USER/tmp if it does not exist
					if (mkdir(chroot_tmp, 0711) == -1) {
						log_err("crit: unable to create %s, error: %s\n", chroot_tmp, strerror(errno));
						exit(127);
					}
				}
				// if /var/suexec/USER/tmp is not symlink, mount /var/suexec/USER/home/USER/tmp to /var/suexec/USER/tmp
				if (!S_ISLNK(sb.st_mode)) {
					if (lstat(chroot_hometmp, &sb) == -1) {
						if (mkdir(chroot_hometmp, 0711) == -1 || chown(chroot_hometmp, uid, gid) == -1) {
							log_err("crit: unable to create %s, error: %s\n", chroot_hometmp, strerror(errno));
							exit(128);
						}
					}
					if (mount(chroot_hometmp, chroot_tmp, "ext3", MS_MGC_VAL | MS_BIND | MS_REC | MS_NOSUID | MS_NODEV | MS_NOEXEC, "" ) == -1) {
						log_err("crit: mount error: Source: %s Destination: %s ERROR: %s\n", chroot_hometmp, chroot_tmp, strerror(errno));
						exit(129);
					}
					symlink("/chroot/tmp/mysql.sock", chroot_tmp_mysql);
					symlink("/chroot/tmp/.s.PGSQL.5432", chroot_tmp_pgsql);
				}
			} else {
				symlink("/chroot/tmp/mysql.sock", chroot_tmp_mysql);
				symlink("/chroot/tmp/.s.PGSQL.5432", chroot_tmp_pgsql);
			}
		}
	} // chroot_enabled
#endif /* SUEXEC_CHROOT */


/* Check for PHP handlers. */
	if (usephp) {
	#ifdef SUEXEC_CHROOT
			if (chroot_enabled) {
				if ((lstat(newHandler, &phpfinfo)) == -1) {
					log_err("crit: unable to stat php handler %s: %s\n", newHandler, strerror(errno));
					exit(102);
				}
			} else {
				if ((lstat(phphandler, &phpfinfo)) == -1) {
					log_err("crit: unable to stat php handler %s: %s\n", phphandler, strerror(errno));
					exit(102);
				}
				phphandler = DEFAULT_PHP_HANDLER;
			}
	#else /* !SUEXEC_CHROOT */
		if ((lstat(phphandler, &phpfinfo)) == -1) {
			log_err("crit: unable to stat php handler %s: %s\n", phphandler, strerror(errno));
			exit(102);
		}
	#endif /* SUEXEC_CHROOT */
	}


	/*
     * Fork the process
     *
	 */
#ifdef INCLUDESTATS
	resuse_start(&tinfo);
#endif
    /* only 1 int variable is needed because each process would have its
       own instance of the variable
       here, 2 int variables are used for clarity */

    /* now create new process */
    childpid = fork();

    if (childpid >= 0) { /* fork succeeded */
        if (childpid == 0) { /* fork() returns 0 to the child process */

#ifdef MAILMAN
			if ((strncmp(cwd, "/usr/local/cpanel/3rdparty/mailman/", 35)) == 0) {
	#ifdef NEED_HASHBANG_EMUL
				{
					extern char **environ;
					ap_execve(cmd, &argv[3], environ);
				}
	#else
				execv(cmd, &argv[3]);
	#endif	/* NEED_HASHBANG_EMUL */
				exit(0);
			}
#endif	/* MAILMAN */

#ifdef INCLUDELIMITS
			if (limits_disabled == 0) {
				/*
				 * This looks like the perfect place to paste the limits
				 * for our clients, just before we execute the script
				 */
				FILE *fp = fopen(LIMITS_CONF, "r");
				int found_user_limits = 1;
				struct userlimits *rlimit;	// real limits
				struct userlimits saved_limits;

				if (fp) {
					while ((rlimit = fgetliment (fp))) {
						// check for different default limits(00)
						if ( !strncmp(rlimit->username, "00", 3) ) {
							memcpy(&saved_limits, rlimit, sizeof(struct userlimits));
							found_user_limits=0;
						}
						// or custom user limits
						if ( !strcmp(actual_uname, rlimit->username) ) {
							memcpy(&saved_limits, rlimit, sizeof(struct userlimits));
							found_user_limits=0;
							break;
						}
					}
					fclose(fp);
				}

				if (!found_user_limits)
					rlimit = &saved_limits;

				/*
				 * set the MAXIMUM USER PROCESSES that this user can have
				 */
				getrlimit (RLIMIT_NPROC, &rlim);
		#ifdef DEBUGLIMITS
				log_err("debug: old RLIMIT_NPROC - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif
				if (found_user_limits) {
					rlim.rlim_cur = MAX_NUMPROC;
					rlim.rlim_max = MAX_NUMPROC + 1;
				} else {
					rlim.rlim_cur = rlimit->nproc;
					rlim.rlim_max = rlimit->nproc + 1;
				}
				/*
				 * set the limit only if it is larger then 0
				 * this way we can set no limits for certain users
				 */
				if (rlim.rlim_cur > 0)
					if (setrlimit (RLIMIT_NPROC, &rlim) == -1)
						log_err("crit: unable to set RLIMIT_NPROC (%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
		#ifdef DEBUGLIMITS
				getrlimit (RLIMIT_NPROC, &rlim);
				log_err("debug: new RLIMIT_NPROC - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif

				/*
				 * set the MAXIMUM MEMORY that this process can use
				 */
				getrlimit (RLIMIT_AS, &rlim);
		#ifdef DEBUGLIMITS
				log_err("debug: old RLIMIT_AS - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif
				if (found_user_limits) {
					rlim.rlim_cur = MAX_MEMLIMIT;
					rlim.rlim_max = MAX_MEMLIMIT + 1000000;
				} else {
					rlim.rlim_cur = rlimit->memlimit;
					rlim.rlim_max = rlimit->memlimit + 1000000;
				}
				/*
				 * set the limit only if it is larger then 0
				 * this way we can set no limits for certain users
				 */
				if (rlim.rlim_cur > 0)
					if (setrlimit (RLIMIT_AS, &rlim) == -1)
						log_err("crit: unable to set RLIMIT_AS (%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);

		#ifdef DEBUGLIMITS
				getrlimit (RLIMIT_AS, &rlim);
				log_err("debug: new RLIMIT_AS - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif
				/*
				 * set the MAXIMUM CPU that this process can use
				 */

				getrlimit (RLIMIT_CPU, &rlim);
		#ifdef DEBUGLIMITS
				log_err("debug: old RLIMIT_CPU - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif
				if (found_user_limits) {
					rlim.rlim_cur = MAX_CPUTIME;
					rlim.rlim_cur = MAX_CPUTIME + 4;
				} else {
					rlim.rlim_cur = rlimit->cputime;
					rlim.rlim_max = rlimit->cputime + 4;
				}

				// set the limit only if it is larger then 0, this way we can disable limits for certain users
				if (rlim.rlim_cur > 0)
					if (setrlimit (RLIMIT_CPU, &rlim) == -1)
						log_err("crit: unable to set RLIMIT_CPU (%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
		#ifdef DEBUGLIMITS
				getrlimit (RLIMIT_CPU, &rlim);
				log_err("debug: new RLIMIT_CPU - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif

				/*
				 * set the MAXIMUM OPENED FILES that this process can use
				 */

				getrlimit (RLIMIT_NOFILE, &rlim);
		#ifdef DEBUGLIMITS
				log_err("debug: old RLIMIT_NOFILE - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif
				if (found_user_limits) {
					rlim.rlim_cur = MAX_OFILE;
					rlim.rlim_max = MAX_OFILE + 1;
				} else {
					rlim.rlim_cur = rlimit->ofile;
					rlim.rlim_max = rlimit->ofile + 1;
				}

				// set the limit only if it is larger then 0, this way we can disable limits for certain users
				if (rlim.rlim_cur > 0)
					if (setrlimit (RLIMIT_NOFILE, &rlim) == -1)
						log_err("crit: unable to set RLIMIT_NOFILE (%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
		#ifdef DEBUGLIMITS
				getrlimit (RLIMIT_NOFILE, &rlim);
				log_err("debug: new RLIMIT_NOFILE - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif

				/*
				 * set the MAXIMUM FILE SIZE that this process can open
				 */

				getrlimit (RLIMIT_FSIZE, &rlim);
		#ifdef DEBUGLIMITS
				log_err("debug: old RLIMIT_FSIZE - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif
				if (found_user_limits) {
					rlim.rlim_cur = MAX_FSIZE;
					rlim.rlim_max = MAX_FSIZE + 1000000;
				} else {
					rlim.rlim_cur = rlimit->fsize;
					rlim.rlim_max = rlimit->fsize + 1000000;
				}

				// set the limit only if it is larger then 0, this way we can disable limits for certain users
				if (rlim.rlim_cur > 0)
					if (setrlimit (RLIMIT_FSIZE, &rlim) == -1)
						log_err("crit: unable to set RLIMIT_FSIZE (%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
		#ifdef DEBUGLIMITS
				getrlimit (RLIMIT_FSIZE, &rlim);
				log_err("debug: new RLIMIT_FSIZE - soft: %d hard: %d\n", rlim.rlim_cur, rlim.rlim_max);
		#endif

			}
#endif	/* INCLUDELIMITS */
#ifdef SUEXEC_CHROOT
			// Chroot to the new location
			if (chroot_enabled) {
	#ifdef HAVECGIDIR
				if (is_cgi_dir == 0) {
	#endif /* HAVECGIDIR */
					if (chroot(chroot_path) == -1) {
						log_err("crit: failed to perform chroot to %s (%s)\n", chroot_path, strerror(errno));
						exit(118);
					}
					// Go to the CWD
					if (chdir(cwd) != 0) {
						log_err("crit: unable to changed to go to CWD\n");
						exit(118);
					}
	#ifdef HAVECGIDIR
				}
	#endif /* HAVECGIDIR */
			}
#endif /* SUEXEC_CHROOT */


			/*
			* Change UID/GID here so that the following tests work over NFS.
			*
			* Initialize the group access list for the target user,
			* and setgid() to the target group. If unsuccessful, error out.
			*/
			if (((setgid(gid)) != 0) || (initgroups(actual_uname, gid) != 0)) {
				log_err("emerg: failed to setgid (%ld: %s)\n", gid, cmd);
				exit(122);
			}

			/*
			 * setuid() to the target user. Error out on fail.
			 */
			if ((setuid(uid)) != 0) {
				if (errno == 11)
					log_err("warn: too many user processes for user %s command(%s) aborted\n", actual_uname, cmd);
				else
					log_err("emerg: failed to setuid (%ld: %s) user target/actual: (%s/%s)\n", uid, cmd, target_uname, actual_uname);
				exit(123);
			}

			/*
			* Get the current working directory, as well as the proper
			* document root (dependant upon whether or not it is a
			* ~userdir request).  Error out if we cannot get either one,
			* or if the current working directory is not in the docroot.
			* Use chdir()s and getcwd()s to avoid problems with symlinked
			* directories.  Yuck.
			*/

/*			if (getcwd(cwd, AP_MAXPATH) == NULL) {
				log_err("emerg: cannot get current working directory\n");
				exit(124);
			}*/
#ifdef DEBUG
			log_err("debug:\n  chroot_path: %s\n  USERDIR_SUFFIX: %s\n  cwd: %s\n", target_homedir, USERDIR_SUFFIX, cwd);
#endif

/*
			if (chdir(target_homedir) == -1) {
				log_err("failed to change current working directory to %s (%s)\n", target_homedir, strerror(errno));
				exit(59);
			}
			if (getcwd(dwd, AP_MAXPATH) == NULL) {
				log_err("cannot get current working directory\n");
				exit(60);
			}

			if ( strncmp(dwd, target_homedir, strlen(target_homedir)) != 0 ) {
				log_err("command not within chroot home directory (cwd=%s, home=%s)\n", dwd, target_homedir);
				exit(151);
			}
*/


			/*
			* Be sure to close the log file so the CGI can't
			* mess with it.  If the exec fails, it will be reopened
			* automatically when log_err is called.  Note that the log
			* might not actually be open if LOG_EXEC isn't defined.
			* However, the "log" cell isn't ifdef'd so let's be defensive
			* and assume someone might have done something with it
			* outside an ifdef'd LOG_EXEC block.
			*/

			newargv[0] = phphandler;
			newargv[1] = cmd;
			newargv[2] = NULL;

			if (log != NULL) {
				fclose(log);
				log = NULL;
			}

			/*
			* Execute the command, replacing our image with its own.
			*/
#ifdef NEED_HASHBANG_EMUL
		    /* We need the #! emulation when we want to execute scripts */
			extern char **environ;
			ap_execve(cmd, &argv[3], environ);
#else /*NEED_HASHBANG_EMUL*/
		/*
		* change the interpreter used for execution
		* of cmd if we have used INCLUDEPHP
		*/
			if (!usephp) {
		#ifdef DEBUG
				if (execv(cmd, &argv[3]) == -1)
					printf("Content-type: text/html\n\n1<br />suexec emerg: (%d)%s<br />\n", errno, strerror(errno));
		#else
				execv(cmd, &argv[3]);
		#endif
			} else {
				newargv[0] = phphandler;
				newargv[1] = cmd;
				newargv[2] = NULL;
			#ifdef DEBUG
				if (execv(newargv[0], newargv) == -1)
					printf("Content-type: text/html\n\n2<br />suexec emerg: (%d)%s<br />\n", errno, strerror(errno));
			#else
				execv(newargv[0], newargv);
			#endif
			}
#endif		/* NEED_HASHBANG_EMUL */
			/*
			* (I can't help myself...sorry.)
			*
			* Uh oh.  Still here.  Where's the kaboom?  There was supposed to be an
			* EARTH-shattering kaboom!
			*
			* Oh well, log the failure and error out.
			*/
#ifdef DEBUG
			printf("Content-type: text/html\n\n3<br />suexec emerg: (%d)%s: exec failed (%s/%s)<br />\n",
				errno, strerror(errno), cwd, cmd);
			printf("Additional: phphandler: %s<br />\n", phphandler);
#endif
			exit(139);		/* the child exits */
        } else {			/* fork() returns new pid to the parent process */
			if (stats_disabled == 0) {
#ifdef MEMIOSTATS
				while(childwait) {
					get_memusage(&childpid, &mem);
					get_io_usage(&childpid, &read_chars, &write_chars, &read_bytes, &write_bytes);
					nanosleep(&sleeper, NULL);
					memcount++;
				}
#endif // MEMIOSTATS
#ifdef INCLUDESTATS
			resuse_end(childpid, &tinfo);
#endif /* INCLUDESTATS */
			}
        }
#ifdef DEBUG
    } else {			/* fork returns -1 on failure */
		printf("Content-type: text/html\n\n5<br />");
        perror("fork"); /* display error message */
#endif
    }
	if (stats_disabled == 0) {
#ifdef INCLUDESTATS
		summarize(&tinfo, &uid, (memcount==0 ? 0 : (mem/memcount)), &read_chars, &write_chars, &read_bytes, &write_bytes);
#endif /* INCLUDESTATS */
	}
#ifdef DEBUG
	log_err("info: Child's exit code is: %d\n", WEXITSTATUS(childstatus));
#endif

#ifdef SUEXEC_CHROOT
	/*
	 * if we have PREMOUNT defined we have never mounted the base os trough suexec
	 * so there is no reason to unmount it here. But if we haven't it required to
	 * umount it.
	 */
#endif /* SUEXEC_CHROOT */
	exit(0);
}
