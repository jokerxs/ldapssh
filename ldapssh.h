/*
 * LDAPSSH is a tool to fetch the SSH pub keys for all members 
 * of a certain LDAP group.
 * The idea is to be used with AuthorizedKeysCommand keyword in 
 * sshd_conf to allow passwordless access for configured group
 * members.
 *
 * Group members are selected by 'memberUid' attribute.
 * The dn user attribute is 'uid' from posixAccount class.
 * The ssh pub key attribute is 'sshPubKey' from ldapPubKey class.
 *
 * LDAPSSH uses two queries to fetch the keys:
 * 1. Get group members list.
 * 2. Get the SSH pub keys for the accounts in the list.
 * 3. Save the result in cache file and use it to answer 
 * subsequent AuthorizedKeys requests for the configured TTL.
 *
 * The configuration file is /etc/ldapssh.conf and is in simple
 * INI style.
 *
 * A [global] config group is requred with LDAP bind details and
 * cache configuration options.
 * One or more [<group>] sections must be present where the
 * definitions of the LDAP filters used for group members query 
 * and the users SSH keys query are defined.
 *
 *
 * Author: Jack
 * Modified Date: 2015-10-09
 *
 */


/*******************************************************************
 * Hashes and lists
 *******************************************************************/
/*
 * SSH keys list entries.
 */
typedef struct sshpk_struct
{
    const char *pk;				/* pointer to ssh pubkey string */
	struct sshpk_struct *next;	/* pointer to next list element */
} sshpk_struct;

/*
 * uthash hash entries
 */
typedef struct hash_struct
{
    const char *name;			/* key, e.g. the username */
    struct sshpk_struct *sshpk;
    UT_hash_handle hh;			/* makes this structure hashable */
} hash_struct;


/*******************************************************************
 * Config parser structs
 *******************************************************************/

/*
 * LDAP bind details
 */
typedef struct ldapconfig
{
    const char* uri;		/* LDAP bind URI - space separated */
    const char* bind_dn;	/* Bind DN with rights to query info */
    const char* bind_pw;
	struct timeval timeout;	/* LDAP timeout */
} ldapconfig;

/*
 * Cache configuration options
 */
typedef struct cacheconfig
{
	char* dir;			/* Cache directory */
    int ttl;			/* Cache TTL */
	int owner_uid;		/* Cache file and directory owner UID */
	int owner_gid;		/* Cache file and directory group GID */
	mode_t file_mode;	/* Cache file creation mode */
} cacheconfig;

/*
 * LDAP search options
 */
typedef struct ldapfilter
{
    const char* base;	/* LDAP base dn */
    const char* flt;	/* LDAP filter template */
    char* attr;	/* LDAP search attribute, i.e. the one in result */
	char* dn;	/* LDAP dn attribute to use in filter */ 
	char* list; /* space separated list of dn items for filter */
} ldapfilter;

/*
 * A configuration set for LDAP group
 */
typedef struct filterset
{
	char* name;			/* key, e.g. section name in INI file */
	char* cache_file;	/* Cache file path */
    ldapfilter grp;		/* Struct with info for group LDAP query */
    ldapfilter ssh;		/* Struct with info for SSH pubkey query */
	hash_struct *sshkeys;	/* hash table with users ssh keys lists */
    UT_hash_handle hh;	/* makes this structure hashable */
} filterset;

/*
 * The whole configuration
 */
typedef struct configuration
{
    ldapconfig ldap;	/* LDAP bind details */
    cacheconfig cache;	/* Cache file TTL, perms and owner */
    filterset *ldapgrp;	/* Struct with info from a filter section */
} configuration;

/*******************************************************************
 * Macro definitions
 *******************************************************************/
/*
 * Uncomment for extra verbous output
#define DEBUG 1
 */

/* 
 * Some constants and file paths
 */
#define USERNAME_LEN 32

#define USERNAME_REG "^[a-z][a-z0-9._]+$"

#define CACHE_FILE_TPL "%s/%s.%s.cache"

/*
 * Config file path
 */
#ifdef DEBUG
#define CONFIG_FILE "ldapssh.conf"
#else
#define CONFIG_FILE "/etc/ldapssh.conf"
#endif

/*
 * Cache files directory path
 */
#define DEFAULT_CACHE_DIR "/var/cache/ldapssh"

/* 
 * File permissions.
 *
 * If a less stricter mode is enabled (like 0640) than
 * consider enabling group owner check as well !!!
 *
#define CONFIG_FILE_CHECK_GID
 */
#define CONFIG_FILE_MODE (S_IRUSR | S_IWUSR)
#define DEFAULT_CACHE_FILE_MODE (S_IRUSR | S_IWUSR)

/*
 * Buffer lengts
 */
#define CACHE_FILE_NAME_LEN 512
#define FILTER_BUF_LEN 8192
#define LINE_BUF_LEN 8192
#define SEARCH_BASE_BUF_LEN 512
#define ATTR_BUF_LEN 64

/*
 * Cache TTL can be configured in ldapssh.conf
 */
#define DEFAULT_CACHE_TTL 300

/*
 * Default LDAP attributes
 */
#define LDAP_GRPDN_ATTR "cn"
#define LDAP_MEMBER_ATTR "memberUid"
#define LDAP_GRP_FLT "(&(objectClass=posixGroup)%s)"

#define LDAP_USRDN_ATTR "uid"
#define LDAP_SSHPK_ATTR "sshPublicKey"
#define LDAP_USR_FLT "(&(objectClass=posixAccount)(objectClass=ldapPublicKey)%s)"

/*
 * Delimiters used when parsing a string as list
 */
#define LIST_DELIMITERS " ,"

/*
 * Return results just as 'name' instead of 'cn=name'
 */
#define LDAP_NOTYPES 1
#define LDAP_SEARCH_TIMEOUT 5
#define LDAP_NETWORK_TIMEOUT 2
