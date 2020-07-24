/*
 * @file  mod_hive.c
 * @brief CGI Script Execution Extension Module for Apache
 * 
 * @defgroup MOD_HIVE mod_hive
 * @ingroup APACHE_MODS
 * @{
 */

#include "mod_hive.h"

module AP_MODULE_DECLARE_DATA hive_module;

static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *cgi_pfn_reg_with_ssi;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *cgi_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *cgi_pfn_ps;
static APR_OPTIONAL_FN_TYPE(ap_cgi_build_command) *cgi_build_command;

/* Read and discard the data in the brigade produced by a CGI script */
static void discard_script_output(apr_bucket_brigade *bb);

/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
static char *strnstr(const char *s, const char *find, size_t slen) {
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == '\0' || slen-- < 1)
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

/* KLUDGE --- for back-combatibility, we don't have to check ExecCGI
 * in ScriptAliased directories, which means we need to know if this
 * request came through ScriptAlias or not... so the Alias module
 * leaves a note for us.
 */

static int is_scriptaliased(request_rec *r) {
    const char *t = apr_table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "cgi-script"));
}

// Parse a string into an ip_range struct
static int parse_ip(apr_pool_t *p, const char *string, struct ip_range *ip) {
	char *s = NULL;
	char *buf = apr_pstrdup(p, string);
	int ipsize=0;
	// Check for netmask and parse it
	if ((s = strchr(buf, '/'))) {
		// We have netmask
		s++;
		if (strchr(s, '.')) {
			// it is in the a.b.c.d form
			if (inet_aton(s, &ip->mask) == 0)
#ifdef DEBUG_OPTIONS
				fprintf(stderr, "mod_hive: parse_ip - inet_aton unable to parse the netmask(%s)\n", s);
#endif
				return 0; // inet_aton error
			} else {
				int m = 0;
				// it is in the /xx form
				m = atoi(s);
				if (m > 32 || m <= 0) {
#ifdef DEBUG_OPTIONS
					fprintf(stderr, "mod_hive: parse_ip - ip in the form /xx and %d is not valid netmask\n", m);
#endif
					return 0;
				}
				ip->mask.s_addr = 0xFFFFFFFFUL << (32 - m);	//
				ip->mask.s_addr = htonl(ip->mask.s_addr);	// convert the value between host and network byte order
			}
	} else {
		ip->mask.s_addr = 0xFFFFFFFFUL;
	}
	// Parse the IP portion
	s = apr_pcalloc(p, 16);
	memset(s, 0, 16); 		// clear the memory

	// copy the IP string
	while (*buf) {
		if (*buf == '/' || *buf == '\0' || ipsize == 16)
			break;
		if (isdigit(*buf) || *buf == '.') {
			*s = *buf;
			buf++;
			s++;
			ipsize++;
		}
	}
	s = s - ipsize;
#ifdef DEBUG_OPTIONS
	fprintf(stderr, "mod_hive: parse_ip - ip to parse: %s\n", s);
#endif
	// convert the IP string into 32bit binary IP
	if (inet_aton(s, &ip->net) == 0) {
#ifdef DEBUG_OPTIONS
		fprintf(stderr, "mod_hive: parse_ip - inet_aton unable to parse the ip(%s)\n", s);
#endif
		return 0;	// inet_aton error
	}
    return 1;
}

// check the excluded_nets for the client ip
static int check_for_excluded_ip(request_rec *r) {
	hive_server_conf *cfg = (hive_server_conf *) ap_get_module_config(r->server->module_config, &hive_module);
	struct ip_range *excluded_nets = (struct ip_range *)cfg->excluded_nets->elts;
	int i;
	struct in_addr h;
	for (i = 0; i < cfg->excluded_nets->nelts; i++) {
#ifdef APACHE24
		if (inet_pton(AF_INET, r->connection->client_ip, &h) &&
#else
		if (inet_pton(AF_INET, r->connection->remote_ip, &h) &&
#endif
			excluded_nets[i].net.s_addr != INADDR_NONE &&
			(h.s_addr & excluded_nets[i].mask.s_addr) == (excluded_nets[i].net.s_addr & excluded_nets[i].mask.s_addr))
			return 1;
	}
	return 0;
}

static void *create_hive_perdir_config(apr_pool_t *p, char *dir) {
    hive_server_conf *cfg = (hive_server_conf *) apr_pcalloc(p, sizeof(hive_server_conf));
    cfg->logname = NULL;
    cfg->logbytes = DEFAULT_LOGBYTES;
    cfg->bufbytes = DEFAULT_BUFBYTES;
	cfg->maxloadlimit = DEFAULT_MAXLOAD;
	cfg->active = 1;
	cfg->hive_exec = 0;
	cfg->chroot = 1;
	cfg->limits = 1;
	cfg->stats = 1;
	cfg->relaxperms = 0;
	cfg->ugid.userdir = 0;
	cfg->symlink_prot = 1;
	cfg->full_symlink = 1;
	cfg->excluded_nets = apr_array_make(p, 1, sizeof(struct ip_range));
    return cfg;
}


static void *create_hive_config(apr_pool_t *p, server_rec *s) {
    hive_server_conf *cfg = (hive_server_conf *) apr_pcalloc(p, sizeof(hive_server_conf));
    cfg->logname = NULL;
    cfg->logbytes = DEFAULT_LOGBYTES;
    cfg->bufbytes = DEFAULT_BUFBYTES;
	cfg->maxloadlimit = DEFAULT_MAXLOAD;
	cfg->active = 1;
	cfg->hive_exec = 0;
	cfg->chroot = 1;
	cfg->limits = 1;
	cfg->stats = 1;
	cfg->relaxperms = 0;
	cfg->ugid.userdir = 0;
	cfg->symlink_prot = 1;
	cfg->full_symlink = 1;
	cfg->excluded_nets = apr_array_make(p, 1, sizeof(struct ip_range));
#ifdef URI_FILTER
	cfg->time = 10;
	cfg->count = 5;
#endif
    return cfg;
}

static void *merge_hive_perdir_config(apr_pool_t *p, void *basev, void *overridesv) {
    hive_server_conf *cfg = (hive_server_conf *) basev, *overrides = (hive_server_conf *) overridesv;
	if (overrides->chroot == 0 ||
		overrides->limits == 0 ||
		overrides->stats == 0 ||
		overrides->relaxperms == 0 ||
		overrides->symlink_prot == 0) {
		// override the local changes with the globals
		if (cfg->chroot == 0)
			overrides->chroot = 0;
		if (cfg->limits == 0)
			overrides->limits = 0;
		if (cfg->stats == 0)
			overrides->stats = 0;
		if (cfg->relaxperms == 1)
			overrides->relaxperms = 1;
		// if the global maxloadlimit is lower then the current one, reset it to the global
//		if (overrides->maxloadlimit > cfg->maxloadlimit)
			overrides->maxloadlimit = cfg->maxloadlimit;

		return overrides;
	} else {
		return cfg;
	}
}

static void *merge_hive_config(apr_pool_t *p, void *basev, void *overridesv) {
    hive_server_conf *cfg = (hive_server_conf *) basev, *overrides = (hive_server_conf *) overridesv;
	if (overrides->chroot == 0 ||
		overrides->limits == 0 ||
		overrides->stats == 0 ||
		overrides->relaxperms == 0 ||
		overrides->symlink_prot == 0) {
		// override the local changes with the globals
		if (cfg->chroot == 0)
			overrides->chroot = 0;
		if (cfg->limits == 0)
			overrides->limits = 0;
		if (cfg->stats == 0)
			overrides->stats = 0;
		if (cfg->relaxperms == 1)
			overrides->relaxperms = 1;
		if (cfg->symlink_prot == 0)
			overrides->symlink_prot = 0;
		if (cfg->full_symlink == 0)
			overrides->full_symlink = 0;
		// if the global maxloadlimit is lower then the current one, reset it to the global
		if (overrides->maxloadlimit > cfg->maxloadlimit)
			overrides->maxloadlimit = cfg->maxloadlimit;
		if (cfg->excluded_nets && cfg->excluded_nets->nelts > 0) {
			overrides->excluded_nets = cfg->excluded_nets;
		}
#ifdef URI_FILTER
		if (overrides->time == 10)
			overrides->time = cfg->time;
		if (overrides->count == 5)
			overrides->count = cfg->count;
#endif
		return overrides;
	} else {
		return cfg;
	}
}
static const char *set_excluded_ips(cmd_parms *cmd, void *dummy, const char *arg) {
    hive_server_conf *cfg = ap_get_module_config(cmd->server->module_config, &hive_module);
    struct ip_range *net;
	net = (struct ip_range *) apr_array_push(cfg->excluded_nets);
	parse_ip(cmd->pool, arg, net);
    return NULL;
}

static const char *set_scriptlog(cmd_parms *cmd, void *dummy, const char *arg) {
    hive_server_conf *cfg = ap_get_module_config(cmd->server->module_config, &hive_module);
    cfg->logname = ap_server_root_relative(cmd->pool, arg);
    if (!cfg->logname)
        return apr_pstrcat(cmd->pool, "Invalid ScriptLog path ", arg, NULL);
    return NULL;
}

static const char *set_scriptlog_length(cmd_parms *cmd, void *dummy, const char *arg) {
    hive_server_conf *cfg = ap_get_module_config(cmd->server->module_config, &hive_module);
    cfg->logbytes = atol(arg);
    return NULL;
}

static const char *set_scriptlog_buffer(cmd_parms *cmd, void *dummy, const char *arg) {
    hive_server_conf *cfg = ap_get_module_config(cmd->server->module_config, &hive_module);
    cfg->bufbytes = atoi(arg);
    return NULL;
}

static const char *set_maxload(cmd_parms *cmd, void *mconfig, const char *arg) {
	hive_server_conf *cfg = (hive_server_conf *) mconfig;
    cfg->maxloadlimit = atof(arg);
    return NULL;
}

static const char *set_disable_chroot(cmd_parms *cmd, void *mconfig) {
	hive_server_conf *cfg = (hive_server_conf *) mconfig;
	cfg->chroot = 0;
	return NULL;
}

static const char *set_disable_limits(cmd_parms *cmd, void *mconfig) {
	hive_server_conf *cfg = (hive_server_conf *) mconfig;
	cfg->limits = 0;
	return NULL;
}

static const char *set_disable_stats(cmd_parms *cmd, void *mconfig) {
	hive_server_conf *cfg = (hive_server_conf *) mconfig;
	cfg->stats = 0;
	return NULL;
}

static const char *set_disable_symlink(cmd_parms *cmd, void *mconfig) {
	hive_server_conf *cfg = (hive_server_conf *) mconfig;
	cfg->symlink_prot = 0;
	return NULL;
}

static const char *set_disable_fullsymlink(cmd_parms *cmd, void *mconfig) {
	hive_server_conf *cfg = (hive_server_conf *) mconfig;
	cfg->full_symlink = 0;
	return NULL;
}

static const char *set_relaxperms(cmd_parms *cmd, void *mconfig) {
	hive_server_conf *cfg = (hive_server_conf *) mconfig;
	cfg->relaxperms = 1;
	return NULL;
}

static const char *set_suexec_ugid(cmd_parms *cmd, void *mconfig, const char *uid, const char *gid) {
    hive_server_conf *cfg = (hive_server_conf *) mconfig;
    cfg->ugid.uid = ap_uname2id(uid);
    cfg->ugid.gid = ap_gname2id(gid);
    cfg->active = 1;
    return NULL;
}

static int log_scripterror(request_rec *r, hive_server_conf * cfg, int ret, apr_status_t rv, char *error) {
    apr_file_t *f = NULL;
    apr_finfo_t finfo;
    char time_str[APR_CTIME_LEN];
    int log_flags = rv ? APLOG_ERR : APLOG_ERR;

    ap_log_rerror(APLOG_MARK, log_flags, rv, r, "%s: %s", error, r->filename);

    /* XXX Very expensive mainline case! Open, then getfileinfo! */
    if (!cfg->logname ||
        ((apr_stat(&finfo, cfg->logname, APR_FINFO_SIZE, r->pool) == APR_SUCCESS) &&
		(finfo.size > cfg->logbytes)) ||
        (apr_file_open(&f, cfg->logname, APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS)) {
        return ret;
    }

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgi-bin/printenv HTTP/1.0" */
    apr_ctime(time_str, apr_time_now());
    apr_file_printf(f, "%%%% [%s] %s %s%s%s %s\n", time_str, r->method, r->uri,
                    r->args ? "?" : "", r->args ? r->args : "", r->protocol);
    /* "%% 500 /usr/local/apache/cgi-bin */
    apr_file_printf(f, "%%%% %d %s\n", ret, r->filename);
    apr_file_printf(f, "%%error\n%s\n", error);

    apr_file_close(f);
    return ret;
}

/* Soak up stderr from a script and redirect it to the error log.
 */
static apr_status_t log_script_err(request_rec *r, apr_file_t *script_err) {
    char argsbuffer[HUGE_STRING_LEN];
    char *newline;
    apr_status_t rv;

    while ((rv = apr_file_gets(argsbuffer, HUGE_STRING_LEN, script_err)) == APR_SUCCESS) {
        newline = strchr(argsbuffer, '\n');
        if (newline) 
            *newline = '\0';
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", argsbuffer);
    }

    return rv;
}

static int log_script(request_rec *r, hive_server_conf * cfg, int ret,
                      char *dbuf, const char *sbuf, apr_bucket_brigade *bb,
                      apr_file_t *script_err) {
    const apr_array_header_t *hdrs_arr = apr_table_elts(r->headers_in);
    const apr_table_entry_t *hdrs = (const apr_table_entry_t *) hdrs_arr->elts;
    char argsbuffer[HUGE_STRING_LEN];
    apr_file_t *f = NULL;
    apr_bucket *e;
    const char *buf;
    apr_size_t len;
    apr_status_t rv;
    int first;
    int i;
    apr_finfo_t finfo;
    char time_str[APR_CTIME_LEN];

    /* XXX Very expensive mainline case! Open, then getfileinfo! */
    if (!cfg->logname ||
        ((apr_stat(&finfo, cfg->logname, APR_FINFO_SIZE, r->pool) == APR_SUCCESS) &&
         (finfo.size > cfg->logbytes)) ||
        (apr_file_open(&f, cfg->logname, APR_APPEND|APR_WRITE|APR_CREATE, APR_OS_DEFAULT, r->pool) != APR_SUCCESS)) {
        /* Soak up script output */
        discard_script_output(bb);
        log_script_err(r, script_err);
        return ret;
    }

    /* "%% [Wed Jun 19 10:53:21 1996] GET /cgi-bin/printenv HTTP/1.0" */
    apr_ctime(time_str, apr_time_now());
    apr_file_printf(f, "%%%% [%s] %s %s%s%s %s\n", time_str, r->method, r->uri,
                    r->args ? "?" : "", r->args ? r->args : "", r->protocol);
    /* "%% 500 /usr/local/apache/cgi-bin" */
    apr_file_printf(f, "%%%% %d %s\n", ret, r->filename);

    apr_file_puts("1h %request\n", f);
    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key)
            continue;
        apr_file_printf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val);
    }
    if ((r->method_number == M_POST || r->method_number == M_PUT) && *dbuf) {
        apr_file_printf(f, "\n%s\n", dbuf);
    }

    apr_file_puts("%response\n", f);
    hdrs_arr = apr_table_elts(r->err_headers_out);
    hdrs = (const apr_table_entry_t *) hdrs_arr->elts;

    for (i = 0; i < hdrs_arr->nelts; ++i) {
        if (!hdrs[i].key)
            continue;
        apr_file_printf(f, "%s: %s\n", hdrs[i].key, hdrs[i].val);
    }

    if (sbuf && *sbuf)
        apr_file_printf(f, "%s\n", sbuf);

    first = 1;
    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e)) {
        if (APR_BUCKET_IS_EOS(e))
            break;

        rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS || (len == 0)) 
            break;

        if (first) {
            apr_file_puts("%stdout\n", f);
            first = 0;
        }
        apr_file_write(f, buf, &len);
        apr_file_puts("\n", f);
    }

    if (apr_file_gets(argsbuffer, HUGE_STRING_LEN, script_err) == APR_SUCCESS) {
        apr_file_puts("%stderr\n", f);
        apr_file_puts(argsbuffer, f);
        while (apr_file_gets(argsbuffer, HUGE_STRING_LEN, script_err) == APR_SUCCESS) {
            apr_file_puts(argsbuffer, f);
        }
        apr_file_puts("\n", f);
    }

    apr_brigade_destroy(bb);
    apr_file_close(script_err);

    apr_file_close(f);
    return ret;
}


static int block_ip(request_rec *r,short match) {
	struct sockaddr_un address;
	int  socket_fd, nbytes;
	char *buf = NULL;
	int buf_size = 0;
	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if ( socket_fd < 0 ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, MODULE_NAME " unable to create socket.");
		return 1;
	}

	/* start with a clean address structure */
	memset(&address, 0, sizeof(struct sockaddr_un));

	address.sun_family = AF_UNIX;
	apr_snprintf(address.sun_path, 256, SOCKET_FILE);

	if ( connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0 ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, MODULE_NAME " connection to IP block server failed!");
		return 2;
	}
	// Count the size of IP + 4 spaces + \n + \0 + the size of the actual URL
	buf_size = 22 + strlen(r->uri) + strlen(r->hostname ? r->hostname : r->server->server_hostname);
	buf = apr_palloc(r->pool, buf_size);
#ifdef APACHE24
	nbytes = apr_snprintf(buf, buf_size, "%s %s%s\n", r->connection->client_ip, r->hostname ? r->hostname : r->server->server_hostname, r->uri);
#else
	nbytes = apr_snprintf(buf, buf_size, "%s %s%s\n", r->connection->remote_ip, r->hostname ? r->hostname : r->server->server_hostname, r->uri);
#endif
	nbytes = write(socket_fd, buf, nbytes);
	close(socket_fd);

	usleep(SLEEP_TIME * 1000000);
	return 0;
}

static signed short lookup_ip(request_rec *r, short match) {
	short i = 0;
	short last = -1;
	int check_count = 0;
	int check_time = 0;
	time_t now = time(NULL);
	hive_server_conf *cfg = (hive_server_conf*) ap_get_module_config(r->server->module_config, &hive_module);
#ifdef IP_BINARY
	uint32_t *ip;
#ifdef APACHE24
	if (r->connection->client_addr->sa.sin.sin_family == AF_INET6) {
#else
	if (r->connection->remote_addr->sa.sin.sin_family == AF_INET6) {
#endif
#ifdef DEBUG_IP
		ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " IPv6");
#endif
		// Get only the last 4 bytes of the IPv6 address and use them as uint32
#ifdef APACHE24
		ip = (uint32_t *) &(r->connection->client_addr->sa.sin6.sin6_addr.s6_addr[12]);
#else
		ip = (uint32_t *) &(r->connection->remote_addr->sa.sin6.sin6_addr.s6_addr[12]);
#endif // APACHE24
    } else {
#ifdef DEBUG_IP
		ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " IPv4");
#endif
#ifdef APACHE24
		ip = &(r->connection->client_addr->sa.sin.sin_addr.s_addr);
#else
		ip = &(r->connection->remote_addr->sa.sin.sin_addr.s_addr);
#endif // APACHE24
    }
#ifdef DEBUG_IP
	ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " looking up IP %0x", *ip);
#endif
#endif // IP_BINARY

	if ( matches[match].count == 0 )
		check_count = cfg->count + 1;
	else
		check_count = matches[match].count + 1;

	if ( matches[match].time == 0 )
		check_time = cfg->time;
	else
		check_time = matches[match].time;

#ifdef DEBUG_IP
	ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " check_time %d check_count %d", check_time, check_count);
#endif

	for ( ; i <= MAX_ENTRIES; i++ ) {
#ifdef IP_BINARY
		if ( sb->entry[i].ip == *ip ) {
#ifdef DEBUG_IP
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " matched IP %0x", *ip);
#endif
#else
#ifdef APACHE24
		if (strcmp(r->connection->client_ip, sb->entry[i].ip) == 0) {
#else
		if (strcmp(r->connection->remote_ip, sb->entry[i].ip) == 0) {
#endif // APACHE24

#endif // IP_BINARY

			sb->entry[i].last_access = now;
			sb->entry[i].count++;

			// If the first request is older then check_time or older then the TTL reset its counter and first request time
			if ( sb->entry[i].first_access + check_time < now || now - sb->entry[i].first_access > TTL ) {
				sb->entry[i].first_access = now;
				sb->entry[i].count = 1;
				sb->entry[i].match = match;
				last = i;
#ifdef DEBUG_IP
				ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " reset counter for IP %0x", *ip);
#endif
				// We don't need to continue beyond this point
				continue;
            }

			if ( sb->entry[i].count >= check_count && sb->entry[i].first_access + check_time > now ) {
				ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " client reached the maximum connections(%d) per URI http://%s%s %s for %d seconds",
					check_count,
					r->hostname ? r->hostname : r->server->server_hostname,
					r->uri,
					r->filename,
					check_time);
				block_ip(r, match);
				sb->entry[i].first_access = 0;
				sb->entry[i].last_access = 0;
				sb->entry[i].match = 0;
				sb->entry[i].count = 1;
#ifdef IP_BINARY
				sb->entry[i].ip = 0;
#else
				memset(sb->entry[i].ip, 0 , 16);
#endif
			}
			return i;
		} // IP not matched
		if ( sb->entry[i].count == 0 )
			last = i;
	} // for () MAX_ENTRIES

	if ( last == -1 )
		return -1;

#ifdef IP_BINARY
	sb->entry[last].ip = *ip;
#else
#ifdef APACHE24
	strcat(sb->entry[last].ip, r->connection->client_ip);
#else
	strcat(sb->entry[last].ip, r->connection->remote_ip);
#endif
#endif
	sb->entry[last].first_access = sb->entry[last].last_access = time(NULL);
	sb->entry[last].match = match;
	sb->entry[last].count = 1;
#ifdef DEBUG_URI
	ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " crated new entry(%d) in the scoreboard", last);
#endif

	return last;
}

static void add_hive_vars(request_rec *r) {
	hive_server_conf *cfg = (hive_server_conf *) ap_get_module_config(r->per_dir_config, &hive_module);
#ifdef DEBUG_HIVE
	ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "mod_hive: DisabledStats (%d)", check_for_excluded_ip(r));
#endif

		apr_table_unset(r->subprocess_env, "DisableChroot");
		apr_table_unset(r->subprocess_env, "DisableLimits");
		apr_table_unset(r->subprocess_env, "DisableStats");
		apr_table_unset(r->subprocess_env, "RelaxPerms");
		if (cfg->chroot == 0)
			apr_table_setn(r->subprocess_env, "DisableChroot", "1");
		if (cfg->limits == 0)
			apr_table_setn(r->subprocess_env, "DisableLimits", "1");
		if (cfg->stats == 0 || check_for_excluded_ip(r))
			apr_table_setn(r->subprocess_env, "DisableStats", "1");
		if (cfg->relaxperms == 1)
			apr_table_setn(r->subprocess_env, "RelaxPerms", "1");
		if (r->handler) {
			if (!strcmp(r->handler, PHP55TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP55HANDLER);
			} else if (!strcmp(r->handler, PHP54TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP54HANDLER);
			} else if (!strcmp(r->handler, PHP53TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP53HANDLER);
			} else if (!strcmp(r->handler, PHP56TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP56HANDLER);
			} else if (!strcmp(r->handler, PHP57TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP57HANDLER);
			} else if (!strcmp(r->handler, PHP70TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP70HANDLER);
			} else if (!strcmp(r->handler, PHP71TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP71HANDLER);
			} else if (!strcmp(r->handler, PHP72TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP72HANDLER);
			} else if (!strcmp(r->handler, PHP73TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP73HANDLER);
			} else if (!strcmp(r->handler, PHP74TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP74HANDLER);
			} else if (!strcmp(r->handler, PHP75TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP75HANDLER);
			} else if (!strcmp(r->handler, PHP52TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP52HANDLER);
			} else if (!strcmp(r->handler, PHP52STYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP52SHANDLER);
			} else if (!strcmp(r->handler, PHP51TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP51HANDLER);
			} else if (!strcmp(r->handler, PHP5TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP5HANDLER);
			} else if (!strcmp(r->handler, PHP4TYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHP4HANDLER);
			} else if (!strcmp(r->handler, PHPSTDTYPE)) {
				apr_table_setn(r->subprocess_env, "PHPHANDLER", PHPSTDHANDLER);
			}
		}
}
/* This is the special environment used for running the "exec cmd="
 *   variety of SSI directives.
 */
static void add_ssi_vars(request_rec *r) {
    apr_table_t *e = r->subprocess_env;

    if (r->path_info && r->path_info[0] != '\0') {
        request_rec *pa_req;

        apr_table_setn(e, "PATH_INFO", ap_escape_shell_cmd(r->pool, r->path_info));

        pa_req = ap_sub_req_lookup_uri(ap_escape_uri(r->pool, r->path_info), r, NULL);
        if (pa_req->filename) {
            apr_table_setn(e, "PATH_TRANSLATED", apr_pstrcat(r->pool, pa_req->filename, pa_req->path_info, NULL));
        }
        ap_destroy_sub_req(pa_req);
    }

    if (r->args) {
        char *arg_copy = apr_pstrdup(r->pool, r->args);

        apr_table_setn(e, "QUERY_STRING", r->args);
        ap_unescape_url(arg_copy);
        apr_table_setn(e, "QUERY_STRING_UNESCAPED", ap_escape_shell_cmd(r->pool, arg_copy));
    }
}

static void cgi_child_errfn(apr_pool_t *pool, apr_status_t err, const char *description) {
    apr_file_t *stderr_log;
    char errbuf[200];

    apr_file_open_stderr(&stderr_log, pool);
    /* Escape the logged string because it may be something that
     * came in over the network.
     */
    apr_file_printf(stderr_log, "(%d)%s: %s\n", err, apr_strerror(err, errbuf, sizeof(errbuf)),
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
                    ap_escape_logitem(pool,
#endif
                    description
#ifndef AP_UNSAFE_ERROR_LOG_UNESCAPED
                    )
#endif
                    );
}

static apr_status_t hive_exec(
	const request_rec *r,
	apr_proc_t *newproc, const char *progname,
	const char * const *args,
	const char * const *env,
	apr_procattr_t *attr, apr_pool_t *p) {
	ap_unix_identity_t *ugid = NULL;
	ap_unix_identity_t ugid_to_use;

    int i = 0;
    const char **newargs;
    char *newprogname;
    char *execuser, *execgroup;
    const char *argv0;
//	hive_server_conf *cfg = (hive_server_conf *) ap_get_module_config(r->server->module_config, &hive_module);
	hive_server_conf *cfg = (hive_server_conf *) ap_get_module_config(r->per_dir_config, &hive_module);

    argv0 = ap_strrchr_c(progname, '/');
    /* Allow suexec's "/" check to succeed */
    if (argv0 != NULL) {
        argv0++;
    } else {
        argv0 = progname;
    }
#ifdef DEBUG_HIVE
	ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "mod_hive: [exec] userdir: %d uid: %d gid: %d symlink: %d", cfg->ugid.userdir, cfg->ugid.uid, cfg->ugid.gid,  cfg->symlink_prot);
#endif

	//Get uid from suexec
	ugid = ap_run_get_suexec_identity(r);
	const char *username = apr_table_get(r->notes, "mod_userdir_user");
	if (username != NULL) {
		if (ugid == NULL) {
			ugid_to_use.uid = unixd_config.user_id;
			ugid_to_use.gid = unixd_config.group_id;
		} else {
			ugid_to_use.uid = ugid->uid;
			ugid_to_use.gid = ugid->gid;
		}
		ugid_to_use.userdir = 1;
	} else {
		ugid_to_use.userdir = 0;
		if (cfg->ugid.uid != 0) {
			ugid_to_use.uid = cfg->ugid.uid;
			ugid_to_use.gid = cfg->ugid.gid;
		} else {
			ugid_to_use.uid = unixd_config.user_id;
			ugid_to_use.gid = unixd_config.group_id;
		}
	}


    if (ugid_to_use.userdir) {
        execuser = apr_psprintf(p, "~%ld", (long) ugid_to_use.uid);
    } else {
        execuser = apr_psprintf(p, "%ld", (long) ugid_to_use.uid);
    }
    execgroup = apr_psprintf(p, "%ld", (long) ugid_to_use.gid);

    if (!execuser || !execgroup)
        return APR_ENOMEM;
    i = 0;
    if (args)
        while (args[i])
            i++;

    /* allocate space for 4 new args, the input args, and a null terminator */
    newargs = apr_palloc(p, sizeof(char *) * (i + 4));
    newprogname = HIVE_BIN;
    newargs[0] = HIVE_BIN;
    newargs[1] = execuser;
    newargs[2] = execgroup;
    newargs[3] = apr_pstrdup(p, argv0);

    /*
    ** using a shell to execute suexec makes no sense thus
    ** we force everything to be APR_PROGRAM, and never
    ** APR_SHELLCMD
    */
    if(apr_procattr_cmdtype_set(attr, APR_PROGRAM) != APR_SUCCESS) {
        return APR_EGENERAL;
    }

    i = 1;
    do {
        newargs[i + 3] = args[i];
    } while (args[i++]);

	return apr_proc_create(newproc, newprogname, newargs, env, attr, p);
}

static apr_status_t run_cgi_child(apr_file_t **script_out,
                                  apr_file_t **script_in,
                                  apr_file_t **script_err,
                                  const char *command,
                                  const char * const argv[],
                                  request_rec *r,
                                  apr_pool_t *p,
                                  cgi_exec_info_t *e_info) {
    const char * const *env;
    apr_procattr_t *procattr;
    apr_proc_t *procnew;
    apr_status_t rc = APR_SUCCESS;

#ifdef DEBUG_CGI
    FILE *dbg = fopen("/dev/tty", "w");
    int i;
#endif

    RAISE_SIGSTOP(CGI_CHILD);
#ifdef DEBUG_CGI
    fprintf(dbg, "Attempting to exec %s as CGI child (argv0 = %s)\n", r->filename, argv[0]);
#endif

    env = (const char * const *)ap_create_environment(p, r->subprocess_env);

#ifdef DEBUG_CGI
    fprintf(dbg, "Environment: \n");
    for (i = 0; env[i]; ++i)
        fprintf(dbg, "'%s'\n", env[i]);
#endif

    /* Transmute ourselves into the script.
     * NB only ISINDEX scripts get decoded arguments.
     */
    if (((rc = apr_procattr_create(&procattr, p)) != APR_SUCCESS) ||
        ((rc = apr_procattr_io_set(procattr, e_info->in_pipe, e_info->out_pipe, e_info->err_pipe)) != APR_SUCCESS) ||
        ((rc = apr_procattr_dir_set(procattr, ap_make_dirstr_parent(r->pool, r->filename))) != APR_SUCCESS) ||
        ((rc = apr_procattr_cmdtype_set(procattr, e_info->cmd_type)) != APR_SUCCESS) ||
        ((rc = apr_procattr_detach_set(procattr, e_info->detached)) != APR_SUCCESS) ||
        ((rc = apr_procattr_addrspace_set(procattr, e_info->addrspace)) != APR_SUCCESS) ||
        ((rc = apr_procattr_child_errfn_set(procattr, cgi_child_errfn)) != APR_SUCCESS)) {
        /* Something bad happened, tell the world. */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, "couldn't set child process attributes: %s", r->filename);
    } else {
        procnew = apr_pcalloc(p, sizeof(*procnew));
//		rc = ap_os_create_privileged_process(r, procnew, command, argv, env, procattr, p);
        rc = hive_exec(r, procnew, command, argv, env, procattr, p);

        if (rc != APR_SUCCESS) {
            /* Bad things happened. Everyone should have cleaned up. */
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_TOCLIENT, rc, r,
                          "couldn't create child process: %d: %s", rc,
                          apr_filepath_name_get(r->filename));
        } else {
            apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);

            *script_in = procnew->out;
            if (!*script_in)
                return APR_EBADF;
            apr_file_pipe_timeout_set(*script_in, r->server->timeout);

            if (e_info->prog_type == RUN_AS_CGI) {
                *script_out = procnew->in;
                if (!*script_out)
                    return APR_EBADF;
                apr_file_pipe_timeout_set(*script_out, r->server->timeout);

                *script_err = procnew->err;
                if (!*script_err)
                    return APR_EBADF;
                apr_file_pipe_timeout_set(*script_err, r->server->timeout);
            }
        }
    }
#ifdef DEBUG_CGI
    fclose(dbg);
#endif
    return (rc);
}


static apr_status_t default_build_command(const char **cmd, const char ***argv,
                                          request_rec *r, apr_pool_t *p,
                                          cgi_exec_info_t *e_info) {
    int numwords, x, idx;
    char *w;
    const char *args = NULL;

    if (e_info->process_cgi) {
        *cmd = r->filename;
        /* Do not process r->args if they contain an '=' assignment
         */
        if (r->args && r->args[0] && !ap_strchr_c(r->args, '='))
            args = r->args;
    }

    if (!args) {
        numwords = 1;
    } else {
        /* count the number of keywords */
        for (x = 0, numwords = 2; args[x]; x++) {
            if (args[x] == '+') {
                ++numwords;
            }
        }
    }
    /* Everything is - 1 to account for the first parameter
     * which is the program name.
     */
    if (numwords > APACHE_ARG_MAX - 1) {
        numwords = APACHE_ARG_MAX - 1;    /* Truncate args to prevent overrun */
    }
    *argv = apr_palloc(p, (numwords + 2) * sizeof(char *));
    (*argv)[0] = *cmd;
    for (x = 1, idx = 1; x < numwords; x++) {
        w = ap_getword_nulls(p, &args, '+');
        ap_unescape_url(w);
        (*argv)[idx++] = ap_escape_shell_cmd(p, w);
    }
    (*argv)[idx] = NULL;

    return APR_SUCCESS;
}

static void discard_script_output(apr_bucket_brigade *bb) {
    apr_bucket *e;
    const char *buf;
    apr_size_t len;
    apr_status_t rv;

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e)) {
        if (APR_BUCKET_IS_EOS(e)) 
            break;
        rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) 
            break;
    }
}

#if APR_FILES_AS_SOCKETS

/* A CGI bucket type is needed to catch any output to stderr from the
 * script; see PR 22030. */
static const apr_bucket_type_t bucket_type_cgi;

struct cgi_bucket_data {
    apr_pollset_t *pollset;
    request_rec *r;
};

/* Create a CGI bucket using pipes from script stdout 'out'
 * and stderr 'err', for request 'r'. */
static apr_bucket *cgi_bucket_create(request_rec *r,
                                     apr_file_t *out, apr_file_t *err,
                                     apr_bucket_alloc_t *list) {
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    apr_status_t rv;
    apr_pollfd_t fd;
    struct cgi_bucket_data *data = apr_palloc(r->pool, sizeof *data);

    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->type = &bucket_type_cgi;
    b->length = (apr_size_t)(-1);
    b->start = -1;

    /* Create the pollset */
    rv = apr_pollset_create(&data->pollset, 2, r->pool, 0);
    AP_DEBUG_ASSERT(rv == APR_SUCCESS);

    fd.desc_type = APR_POLL_FILE;
    fd.reqevents = APR_POLLIN;
    fd.p = r->pool;
    fd.desc.f = out; /* script's stdout */
    fd.client_data = (void *)1;
    rv = apr_pollset_add(data->pollset, &fd);
    AP_DEBUG_ASSERT(rv == APR_SUCCESS);

    fd.desc.f = err; /* script's stderr */
    fd.client_data = (void *)2;
    rv = apr_pollset_add(data->pollset, &fd);
    AP_DEBUG_ASSERT(rv == APR_SUCCESS);

    data->r = r;
    b->data = data;
    return b;
}

/* Create a duplicate CGI bucket using given bucket data */
static apr_bucket *cgi_bucket_dup(struct cgi_bucket_data *data, apr_bucket_alloc_t *list) {
    apr_bucket *b = apr_bucket_alloc(sizeof(*b), list);
    APR_BUCKET_INIT(b);
    b->free = apr_bucket_free;
    b->list = list;
    b->type = &bucket_type_cgi;
    b->length = (apr_size_t)(-1);
    b->start = -1;
    b->data = data;
    return b;
}

/* Handle stdout from CGI child.  Duplicate of logic from the _read
 * method of the real APR pipe bucket implementation. */
static apr_status_t cgi_read_stdout(apr_bucket *a, apr_file_t *out, const char **str, apr_size_t *len) {
    char *buf;
    apr_status_t rv;

    *str = NULL;
    *len = APR_BUCKET_BUFF_SIZE;
    buf = apr_bucket_alloc(*len, a->list); /* XXX: check for failure? */

    rv = apr_file_read(out, buf, len);

    if (rv != APR_SUCCESS && rv != APR_EOF) {
        apr_bucket_free(buf);
        return rv;
    }

    if (*len > 0) {
        struct cgi_bucket_data *data = a->data;
        apr_bucket_heap *h;

        /* Change the current bucket to refer to what we read */
        a = apr_bucket_heap_make(a, buf, *len, apr_bucket_free);
        h = a->data;
        h->alloc_len = APR_BUCKET_BUFF_SIZE; /* note the real buffer size */
        *str = buf;
        APR_BUCKET_INSERT_AFTER(a, cgi_bucket_dup(data, a->list));
    } else {
        apr_bucket_free(buf);
        a = apr_bucket_immortal_make(a, "", 0);
        *str = a->data;
    }
    return rv;
}

/* Read method of CGI bucket: polls on stderr and stdout of the child,
 * sending any stderr output immediately away to the error log. */
static apr_status_t cgi_bucket_read(apr_bucket *b, const char **str, apr_size_t *len, apr_read_type_e block) {
    struct cgi_bucket_data *data = b->data;
    apr_interval_time_t timeout;
    apr_status_t rv;
    int gotdata = 0;

    timeout = block == APR_NONBLOCK_READ ? 0 : data->r->server->timeout;

    do {
        const apr_pollfd_t *results;
        apr_int32_t num;

        rv = apr_pollset_poll(data->pollset, timeout, &num, &results);
        if (APR_STATUS_IS_TIMEUP(rv)) {
            if (timeout) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, data->r,
                              "Timeout waiting for output from CGI script %s",
                              data->r->filename);
                return rv;
            } else {
                return APR_EAGAIN;
            }
        } else if (APR_STATUS_IS_EINTR(rv)) {
            continue;
        } else if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, data->r, "poll failed waiting for CGI child");
            return rv;
        }

        for (; num; num--, results++) {
            if (results[0].client_data == (void *)1) {
                /* stdout */
                rv = cgi_read_stdout(b, results[0].desc.f, str, len);
                if (APR_STATUS_IS_EOF(rv))
                    rv = APR_SUCCESS;
                gotdata = 1;
            } else {
                /* stderr */
                apr_status_t rv2 = log_script_err(data->r, results[0].desc.f);
                if (APR_STATUS_IS_EOF(rv2))
                    apr_pollset_remove(data->pollset, &results[0]);
            }
        }

    } while (!gotdata);

    return rv;
}

static const apr_bucket_type_t bucket_type_cgi = {
    "CGI", 5, APR_BUCKET_DATA,
    apr_bucket_destroy_noop,
    cgi_bucket_read,
    apr_bucket_setaside_notimpl,
    apr_bucket_split_notimpl,
    apr_bucket_copy_notimpl
};

#endif

static int symlink_handler(request_rec *r) {
	struct stat link_stat;
	struct stat file_stat;
#ifdef FORWARD_SYMLINK_CHECKS
#define MIN_PATH_SEARCH_SIZE 8
	char *new_path = NULL;
	int i = 0;
#endif
	char *cpy_path = NULL;
	char *tmp_path = NULL;
	int path_len = 0;
    hive_server_conf *cfg = ap_get_module_config(r->per_dir_config, &hive_module);

	// Symlink protection disabled
	if (cfg->symlink_prot == 0)
		return OK;

	// In some cases it is possible that the filename is missing from the request, in these cases we must not perform the symlink check
	if (r->filename == NULL)
		return OK;

#ifdef DEBUG_SYMLINK_OWNER
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "mod_hive: uid: %d checking filename: %s", cfg->ugid.uid ? cfg->ugid.uid : unixd_config.user_id, r->filename);
#endif

	if (cfg->full_symlink || cfg->ugid.uid == 0) {
		path_len = strlen(r->filename);
		if (path_len > 0) {
			cpy_path = apr_pstrdup(r->pool, r->filename);

#ifdef FORWARD_SYMLINK_CHECKS
			tmp_path = apr_pcalloc(r->pool, path_len);
			memset(tmp_path, '\0', path_len);	// initialize it as null terminated string
			new_path = tmp_path;				// set new_path to the begining of the string
			while(i < path_len) {
				if (*cpy_path == '/') {
					// limit the actual checks by not checking if we have not reached a char position higher then MIN_PATH_SEARCH_SIZE
					if (i <= MIN_PATH_SEARCH_SIZE)
						goto cont;
					lstat(new_path, &link_stat);
#ifdef DEBUG_SYMLINK_OWNER
					ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "mod_hive: checking path: %s", new_path);
#endif
					if ((link_stat.st_mode & S_IFMT) == S_IFLNK) {
#ifdef DEBUG_SYMLINK_OWNER
						ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "mod_hive: %s is link", new_path);
#endif
						if (stat(new_path, &file_stat) == 0 && link_stat.st_uid != file_stat.st_uid )
							return log_scripterror(r, cfg, HTTP_FORBIDDEN, 0, "A symlink in the path has wrong destination owner");
					}
				}
				cont:
				*tmp_path = *cpy_path;	// copy the actual char
				cpy_path++;
				tmp_path++;
				i++;
			}   // while (i < path_len)
#else // BACKWARD_SYMLINK_CHECKS
			tmp_path = cpy_path;
			cpy_path += path_len;

			// check if the current file is a symlink
			if (*cpy_path != '/') {
				lstat(tmp_path, &link_stat);
#ifdef DEBUG_SYMLINK_OWNER
				ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "mod_hive: checking path: %s", tmp_path);
#endif
				if ((link_stat.st_mode & S_IFMT) == S_IFLNK) {
#ifdef DEBUG_SYMLINK_OWNER
					ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "mod_hive: %s is link", tmp_path);
#endif
					// check if the desitnation file is owned by the same owner
					if (stat(tmp_path, &file_stat) == 0 && link_stat.st_uid != file_stat.st_uid)
						return log_scripterror(r, cfg, HTTP_FORBIDDEN, 0, "A symlink in the path has wrong destination owner");
				}
			}

			// check if the desitnation file is owned by the same owner
			while ( path_len > 0 ) {
				if (*cpy_path == '/') {
					*cpy_path = '\0';	// null terminate the string
					lstat(tmp_path, &link_stat);
#ifdef DEBUG_SYMLINK_OWNER
					ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "mod_hive: checking path: %s", tmp_path);
#endif
					if ((link_stat.st_mode & S_IFMT) == S_IFLNK) {
#ifdef DEBUG_SYMLINK_OWNER
						ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "mod_hive: %s is link", tmp_path);
#endif
						// check if the desitnation file is owned by the same owner
						if (stat(tmp_path, &file_stat) == 0 && link_stat.st_uid != file_stat.st_uid)
								return log_scripterror(r, cfg, HTTP_FORBIDDEN, 0, "A symlink in the path has wrong destination owner");
					}
				}
				cpy_path--;	// move the pointer one position to the left
				path_len--; // decrease the amount of remaining chars
			}   // while( path_len > 0 )
#endif // FORWARD_SYMLINK_CHECKS
		}
	} else {
		// Check if the file is owned by the UID for this Vhost
		// Or if it is owned by the user under which Apache runs
		if (stat(r->filename, &file_stat) == 0 && cfg->ugid.uid != file_stat.st_uid && file_stat.st_uid != unixd_config.user_id )
			return log_scripterror(r, cfg, HTTP_FORBIDDEN, 0, "File owner is not the same as the vhost user");
	}
	return OK;
}

static int urilimit_handler(request_rec *r, const char *data, size_t len, int in_filter) {
	short i, n, matched = 0, failed_and;
	char m_str[3];

//  ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " checking data %d", in_filter );

	if (apr_table_get(r->notes, "matched"))
		return 0;

// Search for match in the URL DB
	for ( i = 0 ; i < total_matches; i++ ) {
		n = 0;
		if ( r->uri && r->method_number == matches[i].method && strstr(r->uri, matches[i].uri) != NULL ) {
			// Skip to lookup if we don't have any parameters to check
			if ( matches[i].params[0].arg == NULL ) {
				matched = 1;
				// If we have EXCLUDE header and we have found it in the request, continue to the next match
				if ( matches[i].exclude_hdr != NULL && apr_table_get(r->headers_in, matches[i].exclude_hdr) )
					goto NEXT_MATCH;
				goto LOOKUP;
			}

			failed_and = 0;
			for ( n = 0; n < MAX_PARAMS && matches[i].params[n].arg != NULL; n++ ) {
				// We have failed a match in this group
				if (failed_and) {
					// If this is the last condition in the group - mark the next group as OK (not failed)
					if (matches[i].params[n].separate)
						failed_and = 0;
					continue;
				}

				matched = 0;
				switch (matches[i].params[n].type) {
					case 'P':	// POST param match
						if (in_filter && strnstr(data, matches[i].params[n].arg, len) != NULL) {
							matched = 1;
#ifdef DEBUG_URI
							ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " found POST arg %s in args %.*s", matches[i].params[n].arg, len, data);
#endif
						}
					break;
					case 'G':	// GET param match
						if (r->args != NULL && strstr(r->args, matches[i].params[n].arg) != NULL) {
							matched = 1;
#ifdef DEBUG_URI
						ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " found GET arg %s in args %s", matches[i].params[n].arg, r->args);
#endif
					}
					break;
					case 'N':
						if (strnstr(data, matches[i].params[n].arg, len) != NULL || (r->args != NULL && strstr(r->args, matches[i].params[n].arg) != NULL)) {
#ifdef DEBUG_URI
							ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
								r->args == data ?
									(MODULE_NAME " giving up because arg %s in GET args %.*s") :
									(MODULE_NAME " giving up because arg %s in POST args %.*s or GET args %s"),
								matches[i].params[n].arg, len, data, r->args ? r->args : "(none)");
#endif
							goto NEXT_MATCH;
						}
					break;
				}

				if (matched) {
					if (matches[i].params[n].separate)
						break;
				} else {
					if (!matches[i].params[n].separate)
						failed_and = 1;
				}
			} // params

			if ( matched > 0 ) {
				if ( in_filter ) {
					goto LOOKUP;
				}
			} else {
				goto NEXT_MATCH;
			}

			LOOKUP:
			sprintf(m_str, "%d", i);
			apr_table_set(r->notes, "matched", m_str);
			return 0;
		}
		NEXT_MATCH: ;
	}

	return 0;
}

static int hive_handler(request_rec *r) {
    apr_size_t dbpos = 0;
    const char *command;
    const char **argv;
    char *dbuf = NULL;
    apr_file_t *script_out = NULL, *script_in = NULL, *script_err = NULL;
    apr_bucket_brigade *bb;
    apr_bucket *b;
    int seen_eos, child_stopped_reading;
    apr_pool_t *p;
    hive_server_conf *cfg;
    apr_status_t rv = 0;
    cgi_exec_info_t e_info;
    conn_rec *c = r->connection;
	double loadavg[] = { 0.0, 0.0, 0.0 };
	int checked_notes = 0;

    if (strcmp(r->handler, CGI_MAGIC_TYPE) &&
		strcmp(r->handler, "cgi-script") &&
		strcmp(r->handler, PHPSTDTYPE) &&
		strcmp(r->handler, PHP75TYPE) &&
		strcmp(r->handler, PHP74TYPE) &&
		strcmp(r->handler, PHP73TYPE) &&
		strcmp(r->handler, PHP72TYPE) &&
		strcmp(r->handler, PHP71TYPE) &&
		strcmp(r->handler, PHP70TYPE) &&
		strcmp(r->handler, PHP57TYPE) &&
		strcmp(r->handler, PHP56TYPE) &&
		strcmp(r->handler, PHP55TYPE) &&
		strcmp(r->handler, PHP54TYPE) &&
		strcmp(r->handler, PHP53TYPE) &&
		strcmp(r->handler, PHP52TYPE) &&
		strcmp(r->handler, PHP52STYPE) &&
		strcmp(r->handler, PHP51TYPE) &&
		strcmp(r->handler, PHP5TYPE) &&
		strcmp(r->handler, PHP4TYPE))
        return DECLINED;

//	cfg = ap_get_module_config(r->server->module_config, &hive_module);
	cfg = ap_get_module_config(r->per_dir_config, &hive_module);
#ifdef DEBUG_HIVE
	ap_log_error(APLOG_MARK, APLOG_NOTICE, rv, r->server, "mod_hive: chroot: %d stats: %d limits %d", cfg->chroot, cfg->stats, cfg->limits);
    ap_log_error(APLOG_MARK, APLOG_NOTICE, rv, r->server, "mod_hive: [handle] userdir: %d uid: %d gid: %d ",
		cfg->ugid.userdir, cfg->ugid.uid, cfg->ugid.gid);
#endif

		if( getloadavg(loadavg, 1) > 0 )
			if (loadavg[0] > cfg->maxloadlimit ) {
				ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, rv, r->server,
					"Execute of %s stopped because of load %.2f", r->filename, loadavg[0]);
				 return HTTP_SERVICE_UNAVAILABLE;
			}

    p = r->main ? r->main->pool : r->pool;

	if (r->args != NULL && r->method_number != M_POST)
		urilimit_handler(r, r->args, strlen(r->args), 0);

	if (cfg->relaxperms == 0)
	    if (!(ap_allow_options(r) & OPT_EXECCGI) && !is_scriptaliased(r))
	        return log_scripterror(r, cfg, HTTP_FORBIDDEN, 0, "Options ExecCGI is off in this directory");
    if (r->finfo.filetype == 0)
        return log_scripterror(r, cfg, HTTP_NOT_FOUND, 0, "script not found or unable to stat");
    if (r->finfo.filetype == APR_DIR)
        return log_scripterror(r, cfg, HTTP_FORBIDDEN, 0, "attempt to invoke directory as script");

    if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
        r->path_info && *r->path_info) {
        /* default to accept */
        return log_scripterror(r, cfg, HTTP_NOT_FOUND, 0, "AcceptPathInfo off disallows user's path");
    }
/*
    if (!ap_suexec_enabled) {
        if (!ap_can_exec(&r->finfo))
            return log_scripterror(r, cfg, HTTP_FORBIDDEN, 0,
                                   "file permissions deny server execution");
    }

*/
	add_hive_vars(r);
    ap_add_common_vars(r);
    ap_add_cgi_vars(r);

    e_info.process_cgi = 1;
    e_info.cmd_type    = APR_PROGRAM;
    e_info.detached    = 0;
    e_info.in_pipe     = APR_CHILD_BLOCK;
    e_info.out_pipe    = APR_CHILD_BLOCK;
    e_info.err_pipe    = APR_CHILD_BLOCK;
    e_info.prog_type   = RUN_AS_CGI;
    e_info.bb          = NULL;
    e_info.ctx         = NULL;
    e_info.next        = NULL;
    e_info.addrspace   = 0;

    /* build the command line */
    if ((rv = cgi_build_command(&command, &argv, r, p, &e_info)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "don't know how to spawn child process: %s", r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* run the script in its own process */
    if ((rv = run_cgi_child(&script_out, &script_in, &script_err, command, argv, r, p, &e_info)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "couldn't spawn child process: %s", r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Transfer any put/post args, CERN style...
     * Note that we already ignore SIGPIPE in the core server.
     */
    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    seen_eos = 0;
    child_stopped_reading = 0;
    if (cfg->logname) {
        dbuf = apr_palloc(r->pool, cfg->bufbytes + 1);
        dbpos = 0;
    }
    do {
        apr_bucket *bucket;

        rv = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);

        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Error reading request entity data");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

		if (! checked_notes) {
			checked_notes = 1;
			const char *match = NULL;
			if ( match = apr_table_get(r->notes, "matched") ) {
				ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " matched URI http://%s%s (%s) with match %s",
					r->hostname ? r->hostname : r->server->server_hostname,
					r->uri,
					r->filename,
					match);
#ifdef DEBUG_URI
				short m = 0;
				m = lookup_ip(r, atoi(match));
				if ( m == -1 ) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r, MODULE_NAME " IP DB full");
				} else if ( m == 0 ) {
					ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " IP added to the DB");
				} else {
					ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, MODULE_NAME " IP matched %d times", sb->entry[m].count);
				}
#else
				lookup_ip(r, atoi(match));
#endif
			}
		}

        for (bucket = APR_BRIGADE_FIRST(bb);
             bucket != APR_BRIGADE_SENTINEL(bb);
             bucket = APR_BUCKET_NEXT(bucket)) {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }

            /* We can't do much with this. */
            if (APR_BUCKET_IS_FLUSH(bucket))
                continue;

            /* If the child stopped, we still must read to EOS. */
            if (child_stopped_reading)
                continue;

            /* read */
            apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);

            if (cfg->logname && dbpos < cfg->bufbytes) {
                int cursize;

                if ((dbpos + len) > cfg->bufbytes) {
                    cursize = cfg->bufbytes - dbpos;
                } else {
                    cursize = len;
                }
                memcpy(dbuf + dbpos, data, cursize);
                dbpos += cursize;
            }

            /* Keep writing data to the child until done or too much time
             * elapses with no progress or an error occurs.
             */
            rv = apr_file_write_full(script_out, data, len, NULL);

            if (rv != APR_SUCCESS) {
                /* silly script stopped reading, soak up remaining message */
                child_stopped_reading = 1;
            }
        }
        apr_brigade_cleanup(bb);
    }
    while (!seen_eos);

    if (cfg->logname) {
        dbuf[dbpos] = '\0';
    }
    /* Is this flush really needed? */
    apr_file_flush(script_out);
    apr_file_close(script_out);

    AP_DEBUG_ASSERT(script_in != NULL);

    apr_brigade_cleanup(bb);

#if APR_FILES_AS_SOCKETS
    apr_file_pipe_timeout_set(script_in, 0);
    apr_file_pipe_timeout_set(script_err, 0);

    b = cgi_bucket_create(r, script_in, script_err, c->bucket_alloc);
#else
    b = apr_bucket_pipe_create(script_in, c->bucket_alloc);
#endif
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    /* Handle script return... */
    const char *location;
    char sbuf[MAX_STRING_LEN];
    int ret;

    if ((ret = ap_scan_script_header_err_brigade(r, bb, sbuf))) {
		ret = log_script(r, cfg, ret, dbuf, sbuf, bb, script_err);

        /*
         * ret could be HTTP_NOT_MODIFIED in the case that the CGI script
         * does not set an explicit status and ap_meets_conditions, which
         * is called by ap_scan_script_header_err_brigade, detects that
         * the conditions of the requests are met and the response is
         * not modified.
         * In this case set r->status and return OK in order to prevent
         * running through the error processing stack as this would
         * break with mod_cache, if the conditions had been set by
         * mod_cache itself to validate a stale entity.
         * BTW: We circumvent the error processing stack anyway if the
         * CGI script set an explicit status code (whatever it is) and
         * the only possible values for ret here are:
         *
         * HTTP_NOT_MODIFIED          (set by ap_meets_conditions)
         * HTTP_PRECONDITION_FAILED   (set by ap_meets_conditions)
         * HTTP_INTERNAL_SERVER_ERROR (if something went wrong during the
         * processing of the response of the CGI script, e.g broken headers
         * or a crashed CGI process).
         */
        if (ret == HTTP_NOT_MODIFIED) {
        	r->status = ret;
	        return OK;
        }

    	return ret;
    }

    location = apr_table_get(r->headers_out, "Location");

    if (location && r->status == 200) {
            /* For a redirect whether internal or not, discard any
             * remaining stdout from the script, and log any remaining
             * stderr output, as normal. */
            discard_script_output(bb);
            apr_brigade_destroy(bb);
            apr_file_pipe_timeout_set(script_err, r->server->timeout);
            log_script_err(r, script_err);
    }

    if (location && location[0] == '/' && r->status == 200) {
            /* This redirect needs to be a GET no matter what the original
             * method was.
             */
            r->method = apr_pstrdup(r->pool, "GET");
            r->method_number = M_GET;

            /* We already read the message body (if any), so don't allow
             * the redirected request to think it has one.  We can ignore
             * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
             */
            apr_table_unset(r->headers_in, "Content-Length");

            ap_internal_redirect_handler(location, r);
            return OK;
    } else if (location && r->status == 200) {
            /* XX Note that if a script wants to produce its own Redirect
             * body, it now has to explicitly *say* "Status: 302"
             */
            return HTTP_MOVED_TEMPORARILY;
    }

    rv = ap_pass_brigade(r->output_filters, bb);

    /* don't soak up script output if errors occurred writing it
     * out...  otherwise, we prolong the life of the script when the
     * connection drops or we stopped sending output for some other
     * reason */
    if (rv == APR_SUCCESS && !r->connection->aborted) {
        apr_file_pipe_timeout_set(script_err, r->server->timeout);
        log_script_err(r, script_err);
    }

    apr_file_close(script_err);

    return OK;                      /* NOT r->status, even if it has changed. */
}

/*============================================================================
 *============================================================================
 * This is the beginning of the cgi filter code moved from mod_include. This
 *   is the code required to handle the "exec" SSI directive.
 *============================================================================
 *============================================================================*/
#if APR_MAJOR_VERSION >= 1 && APU_MAJOR_VERSION >= 1
static apr_status_t include_cgi(include_ctx_t *ctx, ap_filter_t *f, apr_bucket_brigade *bb, char *s) {
    request_rec *r = f->r;
    request_rec *rr = ap_sub_req_lookup_uri(s, r, f->next);
#else
static int include_cgi(char *s, request_rec *r, ap_filter_t *next, apr_bucket *head_ptr, apr_bucket **inserted_head) {
	request_rec *rr = ap_sub_req_lookup_uri(s, r, next);
	apr_bucket  *tmp_buck, *tmp2_buck;
#endif
    int rr_status;

    if (rr->status != HTTP_OK) {
        ap_destroy_sub_req(rr);
        return APR_EGENERAL;
    }

    /* No hardwired path info or query allowed */
    if ((rr->path_info && rr->path_info[0]) || rr->args) {
        ap_destroy_sub_req(rr);
        return APR_EGENERAL;
    }
    if (rr->finfo.filetype != APR_REG) {
        ap_destroy_sub_req(rr);
        return APR_EGENERAL;
    }

    /* Script gets parameters of the *document*, for back compatibility */
    rr->path_info = r->path_info;       /* hard to get right; see mod_cgi.c */
    rr->args = r->args;

    /* Force sub_req to be treated as a CGI request, even if ordinary
     * typing rules would have called it something else.
     */
    ap_set_content_type(rr, CGI_MAGIC_TYPE);

    /* Run it. */
    rr_status = ap_run_sub_req(rr);
    if (ap_is_HTTP_REDIRECT(rr_status)) {
#if APR_MAJOR_VERSION >= 1 && APU_MAJOR_VERSION >= 1
        const char *location = apr_table_get(rr->headers_out, "Location");

        if (location) {
            char *buffer;

            location = ap_escape_html(rr->pool, location);
            buffer = apr_pstrcat(ctx->pool, "<a href=\"", location, "\">", location, "</a>", NULL);

            APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(buffer, strlen(buffer), ctx->pool, f->c->bucket_alloc));
        }
#else
		apr_size_t len_loc;
		const char *location = apr_table_get(rr->headers_out, "Location");
		conn_rec *c = r->connection;

		location = ap_escape_html(rr->pool, location);
		len_loc = strlen(location);

		/* XXX: if most of this stuff is going to get copied anyway,
		 * it'd be more efficient to pstrcat it into a single pool buffer
		 * and a single pool bucket */

		tmp_buck = apr_bucket_immortal_create("<A HREF=\"", sizeof("<A HREF=\"") - 1, c->bucket_alloc);
		APR_BUCKET_INSERT_BEFORE(head_ptr, tmp_buck);
		tmp2_buck = apr_bucket_heap_create(location, len_loc, NULL, c->bucket_alloc);
		APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);
		tmp2_buck = apr_bucket_immortal_create("\">", sizeof("\">") - 1, c->bucket_alloc);
		APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);
		tmp2_buck = apr_bucket_heap_create(location, len_loc, NULL, c->bucket_alloc);
		APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);
		tmp2_buck = apr_bucket_immortal_create("</A>", sizeof("</A>") - 1, c->bucket_alloc);
		APR_BUCKET_INSERT_BEFORE(head_ptr, tmp2_buck);

		if (*inserted_head == NULL) {
			*inserted_head = tmp_buck;
		}
#endif
    }

    ap_destroy_sub_req(rr);

    return APR_SUCCESS;
}

#if APR_MAJOR_VERSION >= 1 && APU_MAJOR_VERSION >= 1
static apr_status_t include_cmd(include_ctx_t *ctx, ap_filter_t *f, apr_bucket_brigade *bb, const char *command) {
#else
static int include_cmd(include_ctx_t *ctx, apr_bucket_brigade **bb, const char *command, request_rec *r, ap_filter_t *f) {
#endif
    cgi_exec_info_t  e_info;
    const char **argv;
    apr_file_t *script_out = NULL, *script_in = NULL, *script_err = NULL;
    apr_status_t rv;
#if APR_MAJOR_VERSION >= 1 && APU_MAJOR_VERSION >= 1
    request_rec *r = f->r;
#else
	apr_bucket_brigade *bcgi;
	apr_bucket *b;
#endif
	add_hive_vars(r);
	add_ssi_vars(r);

    e_info.process_cgi = 0;
    e_info.cmd_type    = APR_SHELLCMD;
    e_info.detached    = 0;
    e_info.in_pipe     = APR_NO_PIPE;
    e_info.out_pipe    = APR_FULL_BLOCK;
    e_info.err_pipe    = APR_NO_PIPE;
    e_info.prog_type   = RUN_AS_SSI;
#if APR_MAJOR_VERSION >= 1 && APU_MAJOR_VERSION >= 1
    e_info.bb          = &bb;
    e_info.addrspace   = 0;
#else
    e_info.bb          = bb;
#endif
    e_info.ctx         = ctx;
    e_info.next        = f->next;

    if ((rv = cgi_build_command(&command, &argv, r, r->pool, &e_info)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "don't know how to spawn cmd child process: %s", r->filename);
        return rv;
    }

    /* run the script in its own process */
    if ((rv = run_cgi_child(&script_out, &script_in, &script_err, command, argv, r, r->pool, &e_info)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "couldn't spawn child process: %s", r->filename);
        return rv;
    }
#if APR_MAJOR_VERSION >= 1 && APU_MAJOR_VERSION >= 1
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pipe_create(script_in, f->c->bucket_alloc));
    ctx->flush_now = 1;
#else
	bcgi = apr_brigade_create(r->pool, f->c->bucket_alloc);
	b = apr_bucket_pipe_create(script_in, f->c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bcgi, b);
	ap_pass_brigade(f->next, bcgi);
#endif

    /* We can't close the pipe here, because we may return before the
     * full CGI has been sent to the network.  That's okay though,
     * because we can rely on the pool to close the pipe for us.
     */
    return APR_SUCCESS;
}

#if APR_MAJOR_VERSION >= 1 && APU_MAJOR_VERSION >= 1
static apr_status_t handle_exec(include_ctx_t *ctx, ap_filter_t *f, apr_bucket_brigade *bb) {
    char *tag = NULL;
    char *tag_val = NULL;
    request_rec *r = f->r;
    char *file = r->filename;
    char parsed_string[MAX_STRING_LEN];

    if (!ctx->argc) {
        ap_log_rerror(APLOG_MARK, (ctx->flags & SSI_FLAG_PRINTING)? APLOG_ERR : APLOG_WARNING,
                      0, r, "missing argument for exec element in %s", r->filename);
    }

    if (!(ctx->flags & SSI_FLAG_PRINTING)) {
        return APR_SUCCESS;
    }

    if (!ctx->argc) {
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    if (ctx->flags & SSI_FLAG_NO_EXEC) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "exec used but not allowed in %s", r->filename);
        SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
        return APR_SUCCESS;
    }

    while (1) {
        cgi_pfn_gtv(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
        if (!tag || !tag_val) {
            break;
        }

        if (!strcmp(tag, "cmd")) {
            apr_status_t rv;

            cgi_pfn_ps(ctx, tag_val, parsed_string, sizeof(parsed_string), SSI_EXPAND_LEAVE_NAME);

            rv = include_cmd(ctx, f, bb, parsed_string);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "execution failure for parameter \"%s\" to tag exec in file %s", tag, r->filename);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        } else if (!strcmp(tag, "cgi")) {
            apr_status_t rv;

            cgi_pfn_ps(ctx, tag_val, parsed_string, sizeof(parsed_string), SSI_EXPAND_DROP_NAME);

            rv = include_cgi(ctx, f, bb, parsed_string);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "invalid CGI ref \"%s\" in %s", tag_val, file);
                SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
                break;
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "unknown parameter \"%s\" to tag exec in %s", tag, file);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            break;
        }
    }

    return APR_SUCCESS;
}
#else
static int handle_exec(include_ctx_t *ctx, apr_bucket_brigade **bb, request_rec *r,
						ap_filter_t *f, apr_bucket *head_ptr, apr_bucket **inserted_head) {
	char *tag     = NULL;
	char *tag_val = NULL;
	char *file = r->filename;
	apr_bucket  *tmp_buck;
	char parsed_string[MAX_STRING_LEN];

	*inserted_head = NULL;
	if (ctx->flags & FLAG_PRINTING) {
		if (ctx->flags & FLAG_NO_EXEC) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"exec used but not allowed in %s", r->filename);
			CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
		} else {
			while (1) {
				cgi_pfn_gtv(ctx, &tag, &tag_val, 1);
				if (tag_val == NULL) {
					if (tag == NULL) {
						return 0;
					} else {
						return 1;
					}
				}
				if (!strcmp(tag, "cmd")) {
					cgi_pfn_ps(r, ctx, tag_val, parsed_string, sizeof(parsed_string), 1);
					if (include_cmd(ctx, bb, parsed_string, r, f) == -1) {
						ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
							"execution failure for parameter \"%s\" "
							"to tag exec in file %s", tag, r->filename);
						CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
					}
				} else if (!strcmp(tag, "cgi")) {
					apr_status_t retval = APR_SUCCESS;

					cgi_pfn_ps(r, ctx, tag_val, parsed_string, sizeof(parsed_string), 0);

					SPLIT_AND_PASS_PRETAG_BUCKETS(*bb, ctx, f->next, retval);
					if (retval != APR_SUCCESS) {
						return retval;
					}

					if (include_cgi(parsed_string, r, f->next, head_ptr, inserted_head) == -1) {
						ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
							"invalid CGI ref \"%s\" in %s", tag_val, file);
						CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
					}
				} else {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						"unknown parameter \"%s\" to tag exec in %s", tag, file);
					CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
				}
			}
		}
	}
	return 0;
}
#endif

/*============================================================================
 *============================================================================
 * This is the end of the cgi filter code moved from mod_include.
 *============================================================================
 *============================================================================*/

#define SUEXEC_POST_CONFIG_USERDATA "suexec_post_config_userdata"
static int hive_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
	ap_add_version_component(p, HIVE_VERSION);
    hive_server_conf *cfg = (hive_server_conf *) apr_pcalloc(p, sizeof(hive_server_conf));
    cgi_pfn_reg_with_ssi = APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);
    cgi_pfn_gtv          = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    cgi_pfn_ps           = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_parse_string);
	void *reported;

    if ((cgi_pfn_reg_with_ssi) && (cgi_pfn_gtv) && (cgi_pfn_ps)) {
        /* Required by mod_include filter. This is how mod_cgi registers
         *   with mod_include to provide processing of the exec directive.
         */
        cgi_pfn_reg_with_ssi("exec", handle_exec);
    }

    /* This is the means by which unusual (non-unix) os's may find alternate
     * means to run a given command (e.g. shebang/registry parsing on Win32)
     */
    cgi_build_command    = APR_RETRIEVE_OPTIONAL_FN(ap_cgi_build_command);
    if (!cgi_build_command)
        cgi_build_command = default_build_command;


	if (access(HIVE_BIN,R_OK|X_OK) == 0) {
		cfg->hive_exec = 1;
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "HiveEXEC mechanism enabled (wrapper: %s)", HIVE_BIN);
		apr_pool_userdata_get(&reported, SUEXEC_POST_CONFIG_USERDATA, s->process->pool);
		if (reported == NULL)
		    apr_pool_userdata_set((void *)1, SUEXEC_POST_CONFIG_USERDATA, apr_pool_cleanup_null, s->process->pool);
	} else {
		cfg->hive_exec = 0;
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "HiveEXEC mechanism disabled (wrapper: %s)", HIVE_BIN);
	}

    return OK;
}
#undef SUEXEC_POST_CONFIG_USERDATA

static apr_status_t uripost_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes) {
	apr_bucket *bktIn;
	apr_status_t ret;
	apr_size_t len;
	const char *data;

	ret = ap_get_brigade(f->next, bb, mode, block, readbytes);
	if (ret != APR_SUCCESS)
		return ret;

	for ( bktIn = APR_BRIGADE_FIRST(bb) ;
	      bktIn != APR_BRIGADE_SENTINEL(bb) ;
	      bktIn = APR_BUCKET_NEXT(bktIn) )
	{
		if ( APR_BUCKET_IS_EOS(bktIn) ) {
			break;
		}
		if ( APR_BUCKET_IS_METADATA(bktIn) )
			continue;

		ret=apr_bucket_read(bktIn, &data, &len, block);
		if ( ret != APR_SUCCESS )
			break;

		urilimit_handler(f->r, data, (size_t)len, 1);
	}
	return ret;
}

static apr_status_t uri_detach_shm(void *data) {
	if (sb)
		shmdt(sb);
	return APR_SUCCESS;
}

static void shm_init(apr_pool_t *p, server_rec *s) {
	int i = 0;
	int fd;
	key_t k;
#ifdef SEM
	union semun arg;
	struct sembuf sop;
	arg.val = 0;
	sop.sem_num = 0;
	sop.sem_op = 0;
	sop.sem_flg = 0;
#endif

	// Cleanup any leftover shm file
	if ( access(SHM_FILE, R_OK) == 0 ) {
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, MODULE_NAME "/" MODULE_VERSION " removing old SHM file(%s)", SHM_FILE);
		unlink(SHM_FILE);
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, MODULE_NAME "/" MODULE_VERSION " creating new SHM file(%s)", SHM_FILE);
		fd = open(SHM_FILE, O_CREAT, S_IRUSR|S_IWUSR);
		if ( fd != -1 )
			close(fd);
	}

	k = ftok(SHM_FILE, 1);
#ifdef SEM
    score_semid = semget(k, 1, IPC_CREAT | 0662);
	if ( score_semid == -1 )
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, MODULE_NAME "/" MODULE_VERSION " unable to aquire semaphore");

	if ( semctl(score_semid, 0, SETVAL, arg) == -1 )
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, MODULE_NAME "/" MODULE_VERSION " unable to initialize semaphore");

	if ( semop(semid, &sop, 1) == -1 )
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, MODULE_NAME "/" MODULE_VERSION " unable to set semaphore");
#endif

	score_shmid = shmget(k, sizeof(uri_scoreboard), IPC_CREAT | 0662);
	if ( score_shmid == -1 )
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, MODULE_NAME "/" MODULE_VERSION " unable to initialize shared memory");

//  ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, MODULE_NAME "/" MODULE_VERSION " Initialized shared memory (%d) and semaphore(%d)", score_shmid, score_semid);
	if ( (sb = (uri_scoreboard *) shmat(score_shmid, NULL, 0)) == (uri_scoreboard *) -1 ) {
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, MODULE_NAME " shmat error");
		// exit later after marking the segment to remove itself
	} else {
		// Register a cleanup function to ensure that we cleanup the internal SHM resources.
		apr_pool_cleanup_register(p, (void *)sb, uri_detach_shm, apr_pool_cleanup_null);
	}

	// Mark the segment for deletion once all attachments are detached
	if ( shmctl(score_shmid, IPC_RMID, NULL) == -1 )
		ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, MODULE_NAME " Could not mark shared segment for deletion, you must manually clean it up");
	// exit if we didn't attach successfully
	if ( sb == (uri_scoreboard *) -1 )
		exit(1);

	// Initialize the whole SHM
	sb->requests = 0;
	for ( ; i <= MAX_ENTRIES; i++ ) {
		sb->entry[i].first_access = sb->entry[i].last_access = 0;
		sb->entry[i].match = 0;
		sb->entry[i].count = 0;
#ifdef IP_BINARY
		sb->entry[i].ip = 0;
#else
		memset(sb->entry[i].ip, 0, 16);
#endif
	}
}

static int urilimit_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptmp, server_rec *s) {
	short i,j;
	void *data = NULL;
	const char *key = "filter_post_config";

	// This code is used to prevent double initialization of the module during Apache startup
	apr_pool_userdata_get(&data, key, s->process->pool);
	if ( data == NULL ) {
		apr_pool_userdata_set((const void *)1, key, apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	if ( sb == (uri_scoreboard *) -1 )
		return OK;

	char *url = apr_pcalloc(p, MAX_URL_SIZE);
	char *param = apr_palloc(p, MAX_PARAM_SIZE);

	memset(url, '\0', MAX_URL_SIZE);
	memset(param, '\0', MAX_PARAM_SIZE);
	for ( i = 0; i < MATCHES_SIZE; i++ ) {
		for ( j = 0; j < MAX_PARAMS; j++ ) {
			matches[i].params[j].type = 0;
			matches[i].params[j].separate = 1;
			matches[i].params[j].arg = NULL;
		}
		matches[i].exclude_hdr = NULL;
		matches[i].count = 0;
		matches[i].time = 0;
	}
	// Add the URLs to the global array
/* Example match rule :)
	matches[total_matches].uri = apr_pstrcat(p, url, "/ucp.php", NULL);
	matches[total_matches].method = M_POST;
	matches[total_matches].params[0].type = 'N';
	matches[total_matches].params[0].arg = apr_pstrcat(p, param, "agreed=I+agree+to+these+terms", NULL);
	matches[total_matches].params[1].type = 'N';
	matches[total_matches].params[1].arg = apr_pstrcat(p, param, "not_agreed=I+do+not+agree+to+these+terms", NULL);
	matches[total_matches].params[2].type = 'G';
	matches[total_matches].params[2].arg = apr_pstrcat(p, param, "mode=login", NULL);
	matches[total_matches].params[3].type = 'G';
	matches[total_matches].params[3].arg = apr_pstrcat(p, param, "mode=register", NULL);
	total_matches++;
	memset(url, '\0', MAX_URL_SIZE);
	memset(param, '\0', MAX_PARAM_SIZE);
*/

	shm_init(p, s);

	return OK;
}

#ifdef URI_FILTER
static const char *set_count(cmd_parms *cmd, void *mconfig, const char *arg) {
	hive_server_conf *cfg = (hive_server_conf*) ap_get_module_config(cmd->server->module_config, &hive_module);
	if (apr_isdigit(*arg))
		cfg->count = atoi(arg);
	return NULL;
}

static const char *set_time(cmd_parms *cmd, void *mconfig, const char *arg) {
	hive_server_conf *cfg = (hive_server_conf*) ap_get_module_config(cmd->server->module_config, &hive_module);
	if (apr_isdigit(*arg))
		cfg->time = atoi(arg);
	return NULL;
}
#endif // URI_FILTER

static const command_rec hive_cmds[] = {
	AP_INIT_TAKE1("ScriptLog", set_scriptlog, NULL, RSRC_CONF, "the name of a log for script debugging info"),
	AP_INIT_TAKE1("ScriptLogLength", set_scriptlog_length, NULL, RSRC_CONF, "the maximum length (in bytes) of the script debug log"),
	AP_INIT_TAKE1("ScriptLogBuffer", set_scriptlog_buffer, NULL, RSRC_CONF, "the maximum size (in bytes) to record of a POST request"),
	AP_INIT_TAKE1("MaxLoadLimit", set_maxload, NULL, RSRC_CONF, "Maximum Server load before processing of scripts stops(default: 20.0)" ),
    /* XXX - Another important reason not to allow this in .htaccess is that
     * the ap_[ug]name2id() is not thread-safe */
	AP_INIT_TAKE2("SuexecUserGroup", set_suexec_ugid, NULL, RSRC_CONF, "User and group for spawned processes"),
	AP_INIT_NO_ARGS("RelaxPerms", set_relaxperms, NULL, RSRC_CONF | ACCESS_CONF, "Relaxed permission checking"),
	AP_INIT_NO_ARGS("DisableChroot", set_disable_chroot, NULL, RSRC_CONF | ACCESS_CONF, "Disable chrooting of the executed scripts"),
	AP_INIT_NO_ARGS("DisableLimits", set_disable_limits, NULL, RSRC_CONF | ACCESS_CONF, "Disable resource limits of the executed scripts"),
	AP_INIT_NO_ARGS("DisableStats",  set_disable_stats, NULL, RSRC_CONF | ACCESS_CONF, "Disable CPU, Memory and I/O statistics of the executed scripts"),
	AP_INIT_NO_ARGS("DisableSymlinkProtection",  set_disable_symlink, NULL, RSRC_CONF | ACCESS_CONF, "Disable the symlink protection"),
	AP_INIT_NO_ARGS("DisableFullSymlinkCheck",  set_disable_fullsymlink, NULL, RSRC_CONF | ACCESS_CONF, "Disable the recursive stat of file path, for the symlink protection"),
	AP_INIT_ITERATE("ExcludeFromStats",  set_excluded_ips, NULL, RSRC_CONF | ACCESS_CONF, "List of IP ranges for exclusion"),
#ifdef URI_FILTER
	AP_INIT_TAKE1( "DefaultURIcount", set_count , NULL, RSRC_CONF, "Default count for URIs without one" ),
	AP_INIT_TAKE1( "DefaultURItime", set_time, NULL, RSRC_CONF, "Default timeframe for URIs without one" ),
#endif
    {NULL}
};

static void uri_post(request_rec *r) {
	ap_add_input_filter("uri-post-filter", NULL, r, r->connection);
}

static void register_hooks(apr_pool_t *p) {
    static const char * const aszPre[] = { "mod_include.c", "mod_hostinglimits.c", NULL };
    static const char * const aszPost[] = { "mod_cgi.c", "mod_cgid.c", "mod_fcgid.c", "mod_php.c", "mod_suphp.c", "mod_perl.c", "mod_python.c", NULL };

    ap_hook_post_config(hive_post_config, aszPre, aszPost, APR_HOOK_MIDDLE);
    ap_hook_post_config(urilimit_init, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_fixups(symlink_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(hive_handler, NULL, aszPost, APR_HOOK_MIDDLE);

    ap_hook_insert_filter(uri_post, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_input_filter("uri-post-filter", uripost_filter, NULL, AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA hive_module = {
    STANDARD20_MODULE_STUFF,
    create_hive_perdir_config,		/* dir config creater */
    merge_hive_perdir_config,		/* dir merger --- default is to override */
    create_hive_config,				/* server config */
	merge_hive_config,				/* merge server config */
    hive_cmds,						/* command apr_table_t */
    register_hooks					/* register hooks */
};
