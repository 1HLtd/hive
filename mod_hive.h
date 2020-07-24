/*
 * @file  mod_hive.h
 * @brief CGI Script Execution Extension Module for Apache
 * 
 * @defgroup MOD_HIVE mod_hive
 * @ingroup APACHE_MODS
 * @{
 */

#ifndef _MOD_HIVE_H
#define _MOD_HIVE_H 1


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>



#include "apr.h"
#include "apr_version.h"
#include "apu_version.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"    /* for RLIMIT stuff */
#include "apr_optional.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_poll.h"
#include "apr_tables.h"

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#define CORE_PRIVATE

#include "util_filter.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"
#include "ap_mpm.h"
#include "mod_core.h"
#include "mpm_common.h"

#if defined(AP_SERVER_MAJORVERSION_NUMBER) && AP_SERVER_MAJORVERSION_NUMBER == 2 && defined(AP_SERVER_MINORVERSION_NUMBER) && AP_SERVER_MINORVERSION_NUMBER == 4
#define APACHE24
#endif

#ifdef APACHE24
#include "unixd.h"
#define unixd_config ap_unixd_config
#endif

//#define DEBUG_SYMLINK_OWNER
//#define DEBUG_HIVE
//#define DEBUG_CGI
//#define DEBUG_OPTIONS

// Add URI filter capability
#define URI_FILTER
#ifdef URI_FILTER
//#define DEBUG_URI
//#define DEBUG_IP
#define MAX_ENTRIES 5000
#define MAX_URL_SIZE 40
#define MAX_PARAM_SIZE 100
#define MAX_PARAMS 5
#define SHM_KEY IPC_PRIVATE
#define SHM_FILE "/chroot/tmp/.urilimit"
#define SOCKET_FILE "/chroot/tmp/.urisocket"
#define MATCHES_SIZE 20
#define SLEEP_TIME 3
#define TTL 12
#define IP_BINARY
#endif

// 2.0 compatibility
#if !defined(APR_VERSION) && !defined(APU_VERSION)
#define APR_SUCCESS 0
#endif

#define MODULE_NAME "mod_hive"
#define MODULE_VERSION "6.25"
#define HIVE_VERSION MODULE_NAME "/" MODULE_VERSION

#define DEFAULT_LOGBYTES 10385760
#define DEFAULT_BUFBYTES 1024

#define DEFAULT_MAXLOAD 20.0

#ifndef CGI_MAGIC_TYPE
#define CGI_MAGIC_TYPE "application/x-httpd-cgi"
#endif

// Define PHP 5.2.9-suhosin handling
#define PHP52SHANDLER "/usr/local/php52s/bin/php"
#define PHP52STYPE "application/x-httpd-php52s"

// Define PHP 7.5 handling
#define PHP75HANDLER "/usr/local/php75/bin/php"
#define PHP75TYPE "application/x-httpd-php75"

// Define PHP 7.4 handling
#define PHP74HANDLER "/usr/local/php74/bin/php"
#define PHP74TYPE "application/x-httpd-php74"

// Define PHP 7.3 handling
#define PHP73HANDLER "/usr/local/php73/bin/php"
#define PHP73TYPE "application/x-httpd-php73"

// Define PHP 7.2 handling
#define PHP72HANDLER "/usr/local/php72/bin/php"
#define PHP72TYPE "application/x-httpd-php72"

// Define PHP 7.1 handling
#define PHP71HANDLER "/usr/local/php71/bin/php"
#define PHP71TYPE "application/x-httpd-php71"

// Define PHP 7.0 handling
#define PHP70HANDLER "/usr/local/php70/bin/php"
#define PHP70TYPE "application/x-httpd-php70"

// Define PHP 5.7 handling
#define PHP57HANDLER "/usr/local/php57/bin/php"
#define PHP57TYPE "application/x-httpd-php57"

// Define PHP 5.6 handling
#define PHP56HANDLER "/usr/local/php56/bin/php"
#define PHP56TYPE "application/x-httpd-php56"

// Define PHP 5.5 handling
#define PHP55HANDLER "/usr/local/php55/bin/php"
#define PHP55TYPE "application/x-httpd-php55"

// Define PHP 5.4 handling
#define PHP54HANDLER "/usr/local/php54/bin/php"
#define PHP54TYPE "application/x-httpd-php54"

// Define PHP 5.3 handling
#define PHP53HANDLER "/usr/local/php53/bin/php"
#define PHP53TYPE "application/x-httpd-php53"

// Define PHP 5.2 handling
#define PHP52HANDLER "/usr/local/php52/bin/php"
#define PHP52TYPE "application/x-httpd-php52"

// Define PHP 5.1 handling
#define PHP51HANDLER "/usr/local/php51/bin/php"
#define PHP51TYPE "application/x-httpd-php51"

// Define PHP 5 handling
#define PHP5HANDLER "/usr/local/php5/bin/php"
#define PHP5TYPE "application/x-httpd-php5"

// Define PHP 4 handling
#define PHP4HANDLER "/usr/local/php4/bin/php"
#define PHP4TYPE "application/x-httpd-php4"

// Define standard PHP handling
// The standard handler on cpanel servers must be /usr/bin/php
#define PHPSTDHANDLER "/usr/bin/php"
#define PHPSTDTYPE "application/x-httpd-php"

#define SHM_SIZE	100

#define START_OFFSET 21
#define MAX_PROC_PID_LEN 21

#define MAGIC_NUMBER 17

#define HIVE_BIN "/usr/local/1h/sbin/hive_exec"

#include "mod_include.h"

#ifdef URI_FILTER
typedef struct {
#ifdef IP_BINARY
    uint32_t ip;
#else
    char ip[16];
#endif
    time_t first_access;
    time_t last_access;
    short match;
    short count;
} uri_rec;

typedef struct {
    uri_rec entry[MAX_ENTRIES];
    int requests;
} uri_scoreboard;

typedef struct {
    short type;
    short separate;
    char *arg;
} param;

typedef struct {
    short count;
    short time;
    int method;
    char *uri;
    char *exclude_hdr;
    param params[MAX_PARAMS];
} match_entry;

static uri_scoreboard *sb = NULL;
static int score_shmid;
static int score_semid;
static int total_matches = 0;
match_entry matches[MATCHES_SIZE];


#endif

typedef enum {RUN_AS_SSI, RUN_AS_CGI} prog_types;

struct ip_range {
	struct in_addr net;
	struct in_addr mask;
};

typedef struct {
    const char          *logname;
    long                 logbytes;
    apr_size_t           bufbytes;
    double               maxloadlimit;
    ap_unix_identity_t   ugid;
	int					 hive_exec;
    int                  active;
    int					 chroot;
    int					 limits;
    int					 stats;
	int					 relaxperms;
	int					 symlink_prot;
	int					 full_symlink;
#ifdef URI_FILTER
	int					 count;
	int					 time;
#endif
	apr_array_header_t	*excluded_nets;
} hive_server_conf;

typedef struct {
    apr_int32_t          in_pipe;
    apr_int32_t          out_pipe;
    apr_int32_t          err_pipe;
    int                  process_cgi;
    apr_cmdtype_e        cmd_type;
    apr_int32_t          detached;
    prog_types           prog_type;
    apr_bucket_brigade **bb;
    include_ctx_t       *ctx;
    ap_filter_t         *next;
    apr_int32_t          addrspace;
} cgi_exec_info_t;

/**
 * Registerable optional function to override CGI behavior;
 * Reprocess the command and arguments to execute the given CGI script.
 * @param cmd Pointer to the command to execute (may be overridden)
 * @param argv Pointer to the arguments to pass (may be overridden)
 * @param r The current request
 * @param p The pool to allocate correct cmd/argv elements within.
 * @param process_cgi Set true if processing r->filename and r->args
 *                    as a CGI invocation, otherwise false
 * @param type Set to APR_SHELLCMD or APR_PROGRAM on entry, may be
 *             changed to invoke the program with alternate semantics.
 * @param detach Should the child start in detached state?  Default is no. 
 * @remark This callback may be registered by the os-specific module 
 * to correct the command and arguments for apr_proc_create invocation
 * on a given os.  mod_cgi will call the function if registered.
 */
APR_DECLARE_OPTIONAL_FN(apr_status_t, ap_cgi_build_command, 
                        (const char **cmd, const char ***argv,
                         request_rec *r, apr_pool_t *p, 
                         cgi_exec_info_t *e_info));
#endif /* _MOD_CGI_H */
/** @} */

