/*************************************************************
 * Description: 
 *  - For use with AuthorizedKeysCommand in sshd_conf.
 *    Connects to LDAP server and builds authorized_keys from
 *    the sshPublicKey attribute(s) of the members of the 
 *    group(s) matching grp_filter expression in conf file. 
 *  - Successful results are cached in CACHE_DIR/<user>.cache
 *    for each login. Keys are served from cache if file is 
 *    modified less than CACHE_TTL seconds ago or if no LDAP 
 *    server can be reached.
 *
 * Config file: defined in CONFIG_FILE
 *
 * Author: Jack
 * Modified Date: 2015-10-09
 *
**************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <lber.h>
#include <ldap.h>
#include <sys/stat.h>
#include <time.h>
#include <regex.h>

/* 
 * Simple INI-style config parser from
 * https://github.com/benhoyt/inih
 */
#include "ini.h"

/* 
 * C hash fuctions implemented as macros
 * https://github.com/troydhanson/uthash/tree/master/src
 */
#include "uthash.h"
#include "utlist.h"

/* 
 * Typedefs used in LDAPSSH 
 */
#include "ldapssh.h"


/*******************************************************************
 * config hash table functions
 *******************************************************************/

/* init head element
hash_struct *admins = NULL;
hash_struct *servers = NULL;
*/

/* add config to hash table */
filterset *h_add_conf(filterset **h, const char *name)
{
	filterset *s;

	HASH_FIND_STR( *h, name, s );
	if (s == NULL) 
	{
		s = malloc(sizeof(filterset));
		if (s == NULL) {
			fprintf(stderr, "ERROR: cannot allocate memory\n");
			return NULL;
		}

		s->name = strdup(name);
		s->cache_file = NULL;
		s->sshkeys = NULL;

		s->grp.dn = LDAP_GRPDN_ATTR;
		s->grp.flt = LDAP_GRP_FLT;
		s->grp.attr = LDAP_MEMBER_ATTR;

		s->ssh.dn = LDAP_USRDN_ATTR;
		s->ssh.flt = LDAP_USR_FLT;
		s->ssh.attr = LDAP_SSHPK_ATTR;

		HASH_ADD_KEYPTR( hh, *h, s->name, strlen(s->name), s );
	}

	return s;
}


/* find config by section name */
filterset *h_find_conf(filterset **h, const char *name)
{
    filterset *s;

    HASH_FIND_STR( *h, name, s );  /* s: output pointer */
    return s;
}


/*******************************************************************
 * users hash table functions
 *******************************************************************/

/* add user to hash table */
int h_add_user(hash_struct **h, char *name)
{
	hash_struct *s;

	HASH_FIND_STR( *h, name, s );
	if (s == NULL) 
	{
		s = malloc(sizeof(hash_struct));
		if (s == NULL)
			return 1;

		s->name = strdup(name);
		s->sshpk = NULL;
		HASH_ADD_KEYPTR( hh, *h, s->name, strlen(s->name), s );
	}

	return 0;
}


/* find user by username */
hash_struct *h_find_user(hash_struct **h, char *name)
{
    hash_struct *s;

    HASH_FIND_STR( *h, name, s );  /* s: output pointer */
    return s;
}


/*******************************************************************
 * sshkey hash table functions
 *******************************************************************/

/* add sshpk to user in hash table */
int h_add_sshpk(hash_struct **h, char *name, char *sshpk)
{
	hash_struct *s;
	sshpk_struct *k;

	HASH_FIND_STR( *h, name, s );
	if (s == NULL) {
#ifdef DEBUG
		fprintf(stderr, "NULL pointer for %s\n", name);
#endif
		return 1;
	}

	if ( (k = malloc(sizeof(sshpk_struct))) == NULL )
		return 1;

	k->pk = strdup(sshpk);
	LL_PREPEND( s->sshpk, k );

	return 0;
}


/* print all ssh keys */
void h_print_sshpk(FILE *f, hash_struct **h)
{
    hash_struct *s, *tmp;
	sshpk_struct *k;

    HASH_ITER(hh, *h, s, tmp) {
		LL_FOREACH( s->sshpk, k ) fprintf(f, "%s", k->pk);
    }
}


/*******************************************************************
 * Config parser
 *******************************************************************/

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    configuration *pconfig = (configuration*)user;
	filterset *s;

	if ( strcmp(section, "global") == 0 ) {
		if (strcmp(name, "ldap_uri") == 0) {
			pconfig->ldap.uri = strdup(value);
		} else if (strcmp(name, "bind_dn") == 0) {
			pconfig->ldap.bind_dn = strdup(value);
		} else if (strcmp(name, "bind_pw") == 0) {
			pconfig->ldap.bind_pw = strdup(value);
		} else if (strcmp(name, "cache_dir") == 0) {
			pconfig->cache.dir = strdup(value);
		} else if (strcmp(name, "cache_ttl") == 0) {
			pconfig->cache.ttl = atoi(value);
		} else if (strcmp(name, "ldap_timeout") == 0) {
			pconfig->ldap.timeout.tv_sec = 0.1;
			pconfig->ldap.timeout.tv_usec = (atoi(value) * 1000000);
		}
	} else {
		if ( (s = h_find_conf(&pconfig->ldapgrp, section)) == NULL )
			if ( (s = h_add_conf(&pconfig->ldapgrp, section)) == NULL )
				return 1;

		/* group search config */
		if (strcmp(name, "grp_base") == 0) {
			s->grp.base = strdup(value);
		} else if (strcmp(name, "grp_filter") == 0) {
			s->grp.flt = strdup(value);
		} else if (strcmp(name, "grp_attr") == 0) {
			s->grp.attr = strdup(value);
		} else if (strcmp(name, "grp_dn") == 0) {
			s->grp.dn = strdup(value);
		} else if (strcmp(name, "grp_list") == 0) {
			s->grp.list = strdup(value);
		/* user search config */
		} else if (strcmp(name, "ssh_base") == 0) {
			s->ssh.base = strdup(value);
		} else if (strcmp(name, "ssh_filter") == 0) {
			s->ssh.flt = strdup(value);
		} else if (strcmp(name, "ssh_attr") == 0) {
			s->ssh.attr = strdup(value);
		} else if (strcmp(name, "ssh_dn") == 0) {
			s->ssh.dn = strdup(value);
		}
	}

    return 0;
}


/*******************************************************************
 * Check username against regex
 *******************************************************************/
int check_username(char* username)
{
	regex_t reg;
    int r;

	if ( strlen(username) > USERNAME_LEN )
	{
        fprintf(stderr, "ERROR: invalid username length\n");
		return 1;
	}

    /* prepare regex for username */
    if ( (r = regcomp(&reg, USERNAME_REG, 
                    REG_NOSUB | REG_EXTENDED)) != 0 )
    {
        char errbuf[1024];

        regerror(r, &reg, errbuf, sizeof(errbuf));
        fprintf(stderr, "ERROR: %s\n", errbuf);

		return 1;
    }

    /* check supplied username against regex */
    if (regexec(&reg, username, 0, NULL, 0) == REG_NOMATCH)
    {
        fprintf(stderr, "ERROR: invalid characters in username\n");
		return 1;
    }

	return 0;
}


/*******************************************************************
 * Check file permissions and owner
 *******************************************************************/
int check_file_perms(char *path, mode_t mode, uid_t uid, uid_t gid)
{
    struct stat st; 
    int ret;

    if ( (ret = stat(path, &st)) != 0 )
    {
#ifdef DEBUG
        fprintf(stderr, "ERROR: Cannot stat file '%s'.\n", path);
#endif
        return 1;
    }

    if ( (st.st_mode & mode) != mode )
    {
        fprintf(stderr, "ERROR: Wrong file '%s' octal mode! \
                Currently is %04o and should be %04o.\n", 
                path, st.st_mode, mode);
        return 1;
    }

    if ( st.st_uid != uid )
    {
        fprintf(stderr, "ERROR: Wrong file owner! '%s' is owned \
                by UID %d and should be UID %d.\n", 
                path, st.st_uid, uid);
        return 1;
    }

#ifdef CONFIG_FILE_CHECK_GID
    if ( st.st_gid != gid )
    {
        fprintf(stderr, "ERROR: Wrong file owner! '%s' is owned \
                by GID %d and should be GID %d.\n", 
                path, st.st_gid, gid);
        return 1;
    }
#endif

    return 0;
}


/*******************************************************************
 * Check file modification time and compare it with now()
 *******************************************************************/
int check_ttl(cacheconfig config, char *cache_file)
{
    struct stat st; 
    time_t mtime_diff;
    int rc;

    if ( (rc = stat(cache_file, &st)) != 0 )
    {
#ifdef DEBUG
        fprintf(stderr, "ERROR: Cannot stat file '%s'.\n", 
                cache_file);
#endif
        return 1;
    }

    mtime_diff = difftime(time(NULL), st.st_mtime);
    if ( mtime_diff < config.ttl )
        return 0;
    
#ifdef DEBUG
    printf("Seconds from last modified time: %ld\n", mtime_diff);
#endif

    return 1;
}


/*******************************************************************
 * Read authorized keys from cache file
 *******************************************************************/
int serve_cache(cacheconfig config, char *cache_file)
{
    FILE *f;
    char* line;
    int rc;

    /* check if cache file permissions are as configured */
    if ( check_file_perms(cache_file, config.file_mode, 
                        config.owner_uid, config.owner_gid) != 0 )
        return 1;

    /* open cache file */
    if ( (f = fopen(cache_file, "r")) == NULL )
    {
        fprintf(stderr, "ERROR: failed to open cache file for reading \
                (%s).\n", cache_file);
        return 1;
    }

	line = malloc(LINE_BUF_LEN);

    /* read from file and write to stdout */
    while((fgets(line, LINE_BUF_LEN, f)) != NULL)
    {
        if ( (rc = fputs(line, stdout)) < 0 )
        {
            fprintf(stderr, "ERROR: failed writing cachefile to \
                    stdout.\n");
			free(line);
			return 1;
        }
    }

#ifdef DEBUG
    printf("\nServed from cache: %s\n", cache_file);
#endif

	free(line);
    return fclose(f);
}


/*******************************************************************
 * Write keys to cache file
 *******************************************************************/
int write_cache(cacheconfig config, char *cache_file, hash_struct **h)
{
	FILE *f;
	hash_struct *s, *tmp;
	sshpk_struct *k;

	umask(~DEFAULT_CACHE_FILE_MODE);

	if ( (f = fopen(cache_file, "w")) == NULL)
	{
		fprintf(stderr, "ERROR: failed to open file for writing (%s)\n",
				cache_file);
		return 1;
	}

	/* print all keys to file */
	h_print_sshpk(f, h);

	return fclose(f);
}


/*******************************************************************
 * Perform the ldap search
 *******************************************************************/
/* Do the LDAP search and for each attribute call handler function 
 *      ld      - LDAP descriptor
 *      config  - ldap search struct (base, filter, attr)
 *      sub_tpl - template to apply to result values
 *      res_buff - char buffer to hold the search result
 */
int do_ldap_search(LDAP* ld, ldapfilter config, hash_struct **h)
{
    struct berval **vals = NULL;
    char* attr = NULL;
	char *dn = NULL;
	char **rdn = NULL;
    int i, rc;

	int err = 0;

	struct timeval timeout;

    char *attrs[] = { "", NULL };

    BerElement* ber;
    LDAPMessage* msg;
    LDAPMessage* entry;

    attrs[0] = config.attr;

	/*
	#ifdef DEBUG
	fprintf(stderr, "attrs[0]=%s\n", attrs[0]);
	#endif
	*/

#ifdef DEBUG
	fprintf(stderr, "config.flt=%s\n", config.flt);
#endif

	timeout.tv_sec = 0.1;
	timeout.tv_usec = LDAP_SEARCH_TIMEOUT * 1000000;

    /* Make the search query */
    rc = ldap_search_ext_s(ld, config.base, LDAP_SCOPE_SUBTREE, 
            config.flt, attrs, 0, NULL, NULL, &timeout, 
            LDAP_NO_LIMIT, &msg);
    if ( ( rc != LDAP_SUCCESS ) )
    {
#ifdef DEBUG
        fprintf(stderr, "ldap_search_ext_s: %s\n", ldap_err2string(rc));
#endif
        return 1;
    }

    /* Iterate through the returned entries */
    for(entry = ldap_first_entry(ld, msg); entry != NULL; 
            entry = ldap_next_entry(ld, entry))
    {
		dn = ldap_get_dn(ld, entry);
		rdn = ldap_explode_dn(dn, LDAP_NOTYPES);

        /* iterate through all the attributes */
        for(attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; 
                attr = ldap_next_attribute(ld, entry, ber))
        {
            vals = ldap_get_values_len(ld, entry, attr);

            if (vals != NULL)
            {
                for(i = 0; vals[i] != NULL; i++)
                {
#ifdef DEBUG
					fprintf(stderr, "%s:\t\t%s\n", rdn[0], vals[i]->bv_val);
#endif
					if (strcasecmp(attr, LDAP_SSHPK_ATTR) == 0) {
						err = h_add_sshpk(h, rdn[0], vals[i]->bv_val);
#ifdef DEBUG
						if (err != 0 )
							fprintf(stderr, "We have an error on h_add_sshpk() ?!?\n");
#endif
					} else if (strcasecmp(attr, LDAP_MEMBER_ATTR) == 0) {
						err = h_add_user(h, vals[i]->bv_val);
#ifdef DEBUG
						if (err != 0 )
							fprintf(stderr, "We have an error on h_add_user() ?!?\n");
#endif
					}

					if ( err != 0)
						break;
                }

                ldap_value_free_len(vals);
            }

            ldap_memfree(attr);

			if ( err != 0 )
				break;
        }

        if (ber != NULL)
            ber_free(ber,0);

		if (dn != NULL)
			ldap_memfree(dn);

		if (rdn != NULL)
			ldap_value_free(rdn);

		if ( err != 0 )
			break;
    }

    /* clean on normal exit */
    ldap_msgfree(msg);

    return err;
}


/*******************************************************************
 * Build string by substituting 2 str args in template
 *******************************************************************/
int str_tpl(char *buf, int buf_size, const char *tpl, char *str1, 
		const char *str2)
{
	int len;
	
	len = strlen(tpl) + strlen(str1) + strlen(str2);

	if ( (len + 1) > buf_size )
	{
		fprintf(stderr, "ERROR: result str cannot fit in buffer.\n");
		return 1;
	}

	sprintf(buf, tpl, str1, str2);
	return 0;
}


/*******************************************************************
 * Append string by template
 *******************************************************************/
int str_app(char *buf, int buf_size, const char *tpl, char *str1, 
		const char *str2)
{
	int buf_len = strlen(buf);

	if ( (strlen(str1) + strlen(str2) + strlen(tpl) + buf_len + 2) > 
			buf_size )
	{
		fprintf(stderr, "ERROR: result str cannot fit in buffer.\n");
		return 1;
	}

	/* substitute val in template and append to buf */
	sprintf((buf + buf_len), tpl, str1, str2);

	return 0;
}


/*******************************************************************
 * Build ldap filter from list
 *******************************************************************/
char *get_grp_filter(ldapfilter grp)
{
	char *flt_buf, *tmp_buf;
	char *s, *res;
	int i = 0;
	int err = 0;

	/* allocate filter buffer */
	if ( (flt_buf = malloc(FILTER_BUF_LEN)) == NULL)
		return NULL;

	flt_buf[0] = '\0';

	/* parse group list */
	s = strtok (grp.list, LIST_DELIMITERS);
	while (s != NULL)
	{
		if (str_app(flt_buf, FILTER_BUF_LEN, "(%s=%s)", grp.dn, s) != 0)
			return NULL;
		s = strtok (NULL, LIST_DELIMITERS);
		i++;
	}

#ifdef DEBUG
	fprintf(stderr, "%s\n", flt_buf);
#endif

	/* use (|()()) filter syntax when more than one group is found */
	if ( i > 1 ) {
		if ( ((tmp_buf = strdup(flt_buf)) == NULL) )
			return NULL;
		if (str_tpl(flt_buf, FILTER_BUF_LEN, "(|%s)", tmp_buf, "") != 0)
			return NULL;
		free(tmp_buf);
	}

	/* create final filter by using configured template */
	if ((tmp_buf = strdup(flt_buf)) == NULL)
		return NULL;
	if (str_tpl(flt_buf, FILTER_BUF_LEN, grp.flt, tmp_buf, "") != 0)
		return NULL;

	free(tmp_buf);

	res = strdup(flt_buf);

	free(flt_buf);

#ifdef DEBUG
	fprintf(stderr, "grp_filter=%s\n", res);
#endif
	return res;
}


/*******************************************************************
 * Build ldap filter from group members
 *******************************************************************/
char *get_usr_filter(LDAP* ld, char* username, filterset *config, 
		hash_struct **h)
{
	char *flt_buf, *tmp_buf, *res;
	char buf[SEARCH_BASE_BUF_LEN] = "";
	char *grp_flt_tpl;
	int err = 0;
	int i = 0;

    hash_struct *s, *tmp;

	/* get group filter expression template extended with found
	 * LDAP groups */
	if ( (config->grp.flt = get_grp_filter(config->grp)) == NULL )
		return NULL;

	/* allocate filter buffer */
	if ( (flt_buf = malloc(FILTER_BUF_LEN)) == NULL)
		return NULL;
	/* ensure buffer is \0 terminated before use as string */
	flt_buf[0] = '\0';

	/* make a LDAP search and save results in a hash table */
    if ( do_ldap_search(ld, config->grp, h) != 0 )
        return NULL;

	flt_buf[0] = '\0';

	/* concat usernames into filter expression using sub_tpl */
    HASH_ITER(hh, *h, s, tmp) {
#ifdef DEBUG
		fprintf(stderr, "%s\n", s->name);
#endif
		if ( (strcmp(username, "root") == 0) || (strcmp(s->name, username) == 0) )
		{
			i++;
			if ( str_app(flt_buf, FILTER_BUF_LEN,"(%s=%s)", config->ssh.dn, s->name) != 0 )
				return NULL;
		}
    }

#ifdef DEBUG
	fprintf(stderr, "flt_buf=%s\n", flt_buf);
#endif
	/* allocate temporary buffer */
	if ( (tmp_buf = malloc(FILTER_BUF_LEN)) == NULL)
		return NULL;

	/* use '|()()' filter syntax when more than one user is found */
	if ( i > 1 )
		err = str_tpl(tmp_buf, FILTER_BUF_LEN, "(|%s)", flt_buf, "");
	else 
		err = str_tpl(tmp_buf, FILTER_BUF_LEN, "%s", flt_buf, "");
	
	if ( err != 0 )
		return NULL;
   
	/* create final filter by substituting user list in configured template */
	if (str_tpl(flt_buf, FILTER_BUF_LEN, config->ssh.flt, tmp_buf, "") != 0)
		return NULL;

	free(tmp_buf);

	res = strdup(flt_buf);

	free(flt_buf);

#ifdef DEBUG
	fprintf(stderr, "ssh_filter=%s\n", res);
#endif
	return res;
}


/*******************************************************************
 * Get ssh keys
 *******************************************************************/
int get_ssh_keys(LDAP* ld, char* username, filterset *config, 
        hash_struct **h)
{
    char rdn[SEARCH_BASE_BUF_LEN] = "";
    char buf[SEARCH_BASE_BUF_LEN] = "";

	char *flt_buf;
	char *usr_flt_tpl;
	int err = 0;
	
	/* allocate filter buffer */
	if ((flt_buf = malloc(FILTER_BUF_LEN)) == NULL)
		return 1;

	flt_buf[0] = '\0';

	/* get user filter expression */
    if ( (config->ssh.flt = get_usr_filter(ld, username, config, h)) == NULL) 
		return 1;
	 
	/* when user is not 'root' base dn is users's own dn */
	if (strcmp(username, "root") != 0)
	{
		if (str_tpl(rdn, SEARCH_BASE_BUF_LEN, 
					"%s=%s", config->ssh.dn, username) != 0)
			return 1;

		if (str_tpl(flt_buf, FILTER_BUF_LEN, 
					config->ssh.flt, rdn, "") != 0)
			return 1;

		if (str_tpl(buf, SEARCH_BASE_BUF_LEN, 
					"%s,%s", rdn, config->ssh.base) != 0)
			return 1;

        config->ssh.base = strdup(buf);
	}


#ifdef DEBUG
	fprintf(stderr, "config.ssh.base = %s\n", config->ssh.base);
	fprintf(stderr, "config.ssh.filter = %s\n", config->ssh.flt);
#endif

    err = do_ldap_search(ld, config->ssh, h);

	free(flt_buf);

    return err;
}


/*******************************************************************
 * Init LDAP connection
 *******************************************************************/
int init_ldap(LDAP **ld, configuration config)
{
	int rc;
    int auth_method = LDAP_AUTH_SIMPLE;
    int desired_version = LDAP_VERSION3;

    /* intit LDAP structure */
    if ( ( rc = ldap_initialize(ld, config.ldap.uri) != LDAP_SUCCESS ) )
    {
        fprintf(stderr, "ERROR: ldap_initialize failed: %s\n", 
                ldap_err2string(rc));
        return 1;
    }

    /* set the LDAP version to be 3 */
    if ( ( rc = ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, 
                    &desired_version) != LDAP_OPT_SUCCESS) )
    {
        fprintf(stderr, "ERROR: ldap_set_option failed: %s\n", 
                ldap_err2string(rc));
        return 1;
    }

    /* set the LDAP default timeout */
    if ( ( rc = ldap_set_option(*ld, LDAP_OPT_TIMEOUT, 
                    &config.ldap.timeout) != LDAP_OPT_SUCCESS) )
    {
        fprintf(stderr, "ERROR: ldap_set_option failed: %s\n", 
                ldap_err2string(rc));
        return 1;
    }

    /* set the LDAP network timeout */
    if ( ( rc = ldap_set_option(*ld, LDAP_OPT_NETWORK_TIMEOUT, 
                    &config.ldap.timeout) != LDAP_OPT_SUCCESS) )
    {
        fprintf(stderr, "ERROR: ldap_set_option failed: %s\n", 
                ldap_err2string(rc));
        return 1;
    }

    /* bind to LDAP server with configured auth params */
    if ( ( rc = ldap_bind_s(*ld, config.ldap.bind_dn, config.ldap.bind_pw, 
                    auth_method) != LDAP_SUCCESS ) )
    {
        fprintf(stderr, "ERROR: ldap_bind_s failed: %s\n", 
                ldap_err2string(rc));
        return 1;
    }

	return 0;
}


/*******************************************************************
 * Cenerate config_file name from template
 *******************************************************************/
int set_config_file(cacheconfig cache, filterset *group, char *username)
{
	int len;
	char *cache_file;

	len = strlen(cache.dir) + strlen(username) + strlen(group->name) + 
		strlen(CACHE_FILE_TPL) + 1;

    /* check if cache file path will fit in buffer */
	if ( len > CACHE_FILE_NAME_LEN )
	{
		fprintf(stderr, "ERROR: cache filename too long.\n\
	Consider increasing CACHE_FILE_NAME_LEN.\n");
		return 1;
	}

	if ( (cache_file = malloc(len)) == NULL )
		return 1;

	sprintf(cache_file, CACHE_FILE_TPL, cache.dir, group->name, username);

    group->cache_file = cache_file;

	return 0;
}


/*******************************************************************
 * Core logic
 * - check cache ttl and serve from cache
 * - or connect to LDAP, read keys and save them in cache file
 *******************************************************************/
int print_ssh_keys(LDAP **ld, configuration config, filterset *ldapgrp, 
		char *username)
{
	char *flt_buf = NULL;
	hash_struct **h = &ldapgrp->sshkeys;

    /* assemble cache file path */
	if ( set_config_file(config.cache, ldapgrp, username) != 0)
		return 1;

    /* serve from cache if not older than TTL seconds */
    if ( (check_ttl(config.cache, ldapgrp->cache_file)) == 0)
    {
		return serve_cache(config.cache, ldapgrp->cache_file);
    }

	/* init ldap connection */
	if ( init_ldap(ld, config) != 0 || ld == NULL )
	{
		return serve_cache(config.cache, ldapgrp->cache_file);
	}

	flt_buf = malloc(FILTER_BUF_LEN);
	flt_buf[0] = '\0';

	/* get admins keys */
    if ( get_ssh_keys(*ld, username, ldapgrp, h) != 0 )
    {
		if ( serve_cache(config.cache, ldapgrp->cache_file) != 0 )
		{
			return 1;
		}
    } else {
		/* print keys to stdout */
		h_print_sshpk(stdout, h);
		/* write to cache file */
		return write_cache(config.cache, ldapgrp->cache_file, h);
	}

	free(flt_buf);
	return 0;
}


/*******************************************************************
 * MAIN
 *******************************************************************/
int main( int argc, char *argv[] )
{
    LDAP *ld = NULL;

	int err = 0;

	int uid = getuid();
	int gid = getgid();

	char *username;

    configuration config;
	filterset *s, *tmp;
	hash_struct *lgrp;

	/* init hash head element */
	hash_struct *ldapgrp = NULL;

    /* Check if any command line args are supplied */
    if (argc < 2)
    {
        fprintf(stderr, "USAGE: %s <username>\n", argv[0] );
        return 1;
    }

	/* Check username if syntacticaly valid */
	if ( check_username(argv[1]) != 0 )
    {
		return 1;
    }

    /* Check config file perms */
    if ( check_file_perms(CONFIG_FILE, CONFIG_FILE_MODE, uid, gid) != 0 ) 
	{
		fprintf(stderr, "ERROR: bad configuration file %s.\n", 
                CONFIG_FILE);
        return 1;
	}

	username = argv[1];

	/* set config defaults */
	config.ldap.timeout.tv_sec = 0.1;
	config.ldap.timeout.tv_usec = LDAP_NETWORK_TIMEOUT * 1000000;
    config.cache.dir = strdup(DEFAULT_CACHE_DIR);
    config.cache.file_mode = DEFAULT_CACHE_FILE_MODE;
    config.cache.ttl = DEFAULT_CACHE_TTL;
	config.cache.owner_uid = getuid();
	config.cache.owner_gid = getgid();

	/* init hash head pointer */
	config.ldapgrp = NULL;

    /* parse config file */
    if (ini_parse(CONFIG_FILE, handler, &config) < 0) {
        fprintf(stderr, "Can't load '%s'\n", CONFIG_FILE);
        return 1;
    }

#ifdef DEBUG
    printf("cache_ttl: %d\n", config.cache.ttl);
    printf("cache_dir: %s\n", config.cache.dir);
    printf("cache_file_mode: %04o\n", config.cache.file_mode);
    printf("file_owner_uid: %d\n", config.cache.owner_uid);
    printf("file_owner_gid: %d\n", config.cache.owner_gid);
    printf("\nldap_uri: %s\n", config.ldap.uri);
    printf("ldap_timeout: %ld\n", config.ldap.timeout.tv_usec);
    printf("bind_dn: %s\n", config.ldap.bind_dn);
    printf("bind_pw: %s\n", config.ldap.bind_pw);

    HASH_ITER(hh, config.ldapgrp, s, tmp) {
		printf("\n%s grp_base: %s\n", s->name, s->grp.base);
		printf("\n%s grp_filter: %s\n", s->name, s->grp.flt);
		printf("\n%s grp_attr: %s\n", s->name, s->grp.attr);
		printf("\n%s ssh_base: %s\n", s->name, s->ssh.base);
		printf("\n%s ssh_filter: %s\n", s->name, s->ssh.flt);
		printf("\n%s ssh_attr: %s\n", s->name, s->ssh.attr);
		printf("\n%s ssh_dn: %s\n", s->name, s->ssh.dn);
	}
#endif

	/* iterate over config filter sections */
    HASH_ITER(hh, config.ldapgrp, s, tmp) {
		err &= print_ssh_keys(&ld, config, s, username);
	}

	if (ld != NULL)
		ldap_unbind(ld);

    return err;
}
