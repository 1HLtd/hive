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
 * suexec.h -- user-definable variables for the suexec wrapper code.
 *             (See README.configure on how to customize these variables.)
 */

#ifndef _SUEXEC_H
#define _SUEXEC_H

// Standard includes
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>

// apache variables & functions
#ifndef _SUEXEC_MOUNTS_H
#include "ap_config.h"
#endif
// Functions to verify if a folder is already mounted
#include "mounts_check.h"


#if defined(NEED_STRERROR)
extern char *sys_errlist[];
#define strerror(x) sys_errlist[(x)]
#endif

#if defined(PATH_MAX)
#define AP_MAXPATH PATH_MAX
#elif defined(MAXPATHLEN)
#define AP_MAXPATH MAXPATHLEN
#else
#define AP_MAXPATH 2048
#endif

#define AP_ENVBUF 256

//Define APACHE24 to compile for apache 2.4
#define APACHE24
#ifdef APACHE24
	#define APACHE2
#endif
//Define APACHE2 to compile for apache 2.2 otherwise compile for 1.3
#define APACHE2
//Define PLESK to compile for apache2 on PLESK
//#define PLESK
//Define PLAIN to build for plain CentOS installation (no control panel)
//#define PLAIN
#ifdef PLESK
	#define PLESK_GROUP "psaserv"
#endif

#if defined(PLESK) || defined(PLAIN)
	#define APACHE2
#endif

/*
 * Turn this on in order to see debug messages
 */
// #define DEBUG
// #define DEBUGENV
// #define DEBUGSTATS
// #define DEBUGLIMITS
// #define DEBUGMOUNTS

// 
#define MAILMAN

/*
 *
 */
#define SUEXEC_CHROOT
#define DISABLE_CHROOT "/etc/disable_hivechroot"

/*
 * Include limits for CPU, MEM, Number of processes and etc.
 *
 */
#define INCLUDELIMITS
// resource limits functions & types
#ifdef INCLUDELIMITS
#include "rlimit_config.h"
#include <limits.h>
#endif

/*
 * Include statistics
 */
#define INCLUDESTATS
// times functions & declarations
#ifdef INCLUDESTATS
#include "time.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

/*
 * HTTPD_USER -- Define as the username under which Apache normally
 *               runs.  This is the only user allowed to execute
 *               this program.
 */
#if defined(PLESK) || defined(PLAIN)
	#define HTTPD_USER "apache"
#endif
#ifndef HTTPD_USER
#define HTTPD_USER "nobody"
#endif

/*
 * READ THIS BEFORE CONTINUING!!
 *
 * The patch below adds a feature which makes it possible to run "shared"
 * scripts. Suppose you are a systems admin for $large hosting provider and
 * you want to offer your customers some standard scripts. These scripts would
 * cause a security violation based on the uid owner of the script.
 *
 * This patch makes it possible to "trust" a certain user/group. Look below to
 * define the user/group ID.
 *
 * Uncomment the define to make it actually happen.
 *
 * patch added by Sabri Berisha <sabri@bit.nl> modified for cpanel by nick@darkorb.net
 */

// #define PATH_TRANSLATED
#define TRUSTED_USERS_SCRIPTS
#ifndef PLESK
# define HAVECGIDIR
#endif /* PLESK */

#ifdef HAVECGIDIR
#define CGIDIR "/usr/local/cpanel/cgi-sys"
#define CGIDIRUID 0
#define CGIDIRGID 10
#endif

#define MEMIOSTATS
#ifdef MEMIOSTATS
    #include "memstats.h"
    #include "iostats.h"
#endif


#ifdef TRUSTED_USERS_SCRIPTS
#define SUEXEC_TRUSTED_USER 0
#define SUEXEC_TRUSTED_GROUP 10
#endif


/*
 * UID_MIN -- Define this as the lowest UID allowed to be a target user
 *            for suEXEC.  For most systems, 500 or 100 is common.
 */
#ifndef UID_MIN
#define UID_MIN 99
#endif

/*
 * GID_MIN -- Define this as the lowest GID allowed to be a target group
 *            for suEXEC.  For most systems, 100 is common.
 */
#ifndef GID_MIN
#define GID_MIN 99
#endif

/*
 * USERDIR_SUFFIX -- Define to be the subdirectory under users'
 *                   home directories where suEXEC access should
 *                   be allowed.  All executables under this directory
 *                   will be executable by suEXEC as the user so
 *                   they should be "safe" programs.  If you are
 *                   using a "simple" UserDir directive (ie. one
 *                   without a "*" in it) this should be set to
 *                   the same value.  suEXEC will not work properly
 *                   in cases where the UserDir directive points to
 *                   a location that is not the same as the user's
 *                   home directory as referenced in the passwd file.
 *
 *                   If you have VirtualHosts with a different
 *                   UserDir for each, you will need to define them to
 *                   all reside in one parent directory; then name that
 *                   parent directory here.  IF THIS IS NOT DEFINED
 *                   PROPERLY, ~USERDIR CGI REQUESTS WILL NOT WORK!
 *                   See the suEXEC documentation for more detailed
 *                   information.
 */
#ifndef USERDIR_SUFFIX
#define USERDIR_SUFFIX "public_html"
#endif

/*
 * LOG_EXEC -- Define this as a filename if you want all suEXEC
 *             transactions and errors logged for auditing and
 *             debugging purposes.
 */
#ifdef PLAIN
# define LOG_EXEC "/var/log/httpd/suexec.log"
#endif
#ifndef LOG_EXEC
# define LOG_EXEC "/usr/local/apache/logs/suexec_log"	/* Need me? */
#endif
void log_err(const char *fmt,...);


/*
 * DOC_ROOT -- Define as the DocumentRoot set for Apache.  This
 *             will be the only hierarchy (aside from UserDirs)
 *             that can be used for suEXEC behavior.
 */
#ifndef DOC_ROOT
#define DOC_ROOT "/usr/local/apache/htdocs"
#endif

/* SAFE_PATH -- Define a safe PATH environment to pass to CGI executables. */
#ifndef SAFE_PATH
#define SAFE_PATH "/usr/local/bin:/usr/bin:/bin"
#endif

/* Enable the handling of PHP files */
#define INCLUDEPHP
#if defined(PLESK) || defined(PLAIN)
#  define DEFAULT_PHP_HANDLER "/usr/bin/php-cgi"
#else
#  define DEFAULT_PHP_HANDLER "/usr/bin/php"
#endif

#ifdef INCLUDELIMITS
#define LIMITS_CONF "/usr/local/apache/conf/rlimit-config"
#define MAX_CPUTIME 120ul
#define MAX_MEMLIMIT 536870912ul
#define MAX_NUMPROC 40ul
#define MAX_FSIZE 2000000000ul
#define MAX_OFILE 30ul
#endif

/* Enable chroot(2) to user's home folders */
#ifdef SUEXEC_CHROOT
#define HOME_PATH "/home/"
#define CHROOT_DIR "/var/suexec/"
#define BASE_OS "/var/suexec/baseos"
	#ifndef MS_REC
	#define MS_REC          0x4000  /* 16384: Recursive loopback */
	#endif
#endif

/*
/var/baseos
	/bin
	/etc -> mount /etc /var/baseos/etc/
	/lib
	/proc -> mount /proc/ /var/baseos/proc
	/usr
	/var
	/home

mount /var/baseos 		->	/var/suexec/username0
mount /home/username0	->	/var/suexec/username0/home/username0

mount /var/baseos 		->	/var/suexec/username1
mount /home/username1	->	/var/suexec/username1/home/username1
*/

#ifndef MAX_UNAME
# define MAX_UNAME 65
#endif

#endif /* _SUEXEC_H */
