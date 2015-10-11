# ldapssh
**ldapssh** is a SSH helper program for use with **AuthorizedKeysCommand** confiiguration option in sshd_config. 
It connects to a configured LDAP server and fetches the SSH pub keys for all group members. The idea is to allow passwordless **root** logins via SSH for specific LDAP groups.

The utility works by invoking from sshd on login attempt and before reading the AuthorizedKeys file. The login username is passed as first argument. It connects to LDAP server and reads the sshPubKey attribute for all the members of configured groups(s). The list is printed on stdout. If sshd finds a match the login succeeds, otherwise the authentication continues with the AuthorizedKeys file and a password as a last option.

If you have the same users in multiple groups their SSH keys will appear only once in the output.

To use **ldapssh** you need an LDAP server (like slapd) configured with [openssh-lpk](https://code.google.com/p/openssh-lpk/) schema. It is possible to adjust it to use different attributes from another schema for SSH keys, but that would ban you from using the defaults in the configuration file.

## Configuration file ##
The configuration is in /etc/ldapssh.conf. The file has to be chmod 0600 because LDAP bind dn password is stored there. It also must be owned by the user specified in AuthorizedKeysCommandUser option in sshd_config.
The file consists of two or more sections - a mandatory **global** and one or more **filter** sections. There is no limit on the number of filter sections but each one will cost you two LDAP queries.

**global** section contains LDAP bind details and cache configuration options.
  * **ldap_uri** - list of LDAP URIs.
  * **bind_dn** - bind DN for the configured LDAP URIs.
  * **bind_pw** - bind password,
  * **ldap_timeout** - timout in seconds used for both network and select timeout in LDAP connection.
  * **cache_ttl** - how long in seconds the cache file is considered valid. 
  * **cache_dir** - where to store cache files. The directory has to be with perms 0700 and owned by the user specified by AuthorizedKeysCommandUser option in sshd_config.

All other sections are considered **filter** sections. The options are two types - **grp** and **ssh**. Most of them have working defaults and only grp_list, grp_base, ssh_base need to be set.

**grp_** are for query fetching group members:
  * **grp_list** - space separate list of group names allowed to login to this servers.
  * **grp_base** - base DN for the group LDAP search.
  * grp_dn - the attribute containing group name for use in filter. Default is 'cn'.
  * grp_attr - the attribute to be searched. Default is 'memberUid'.
  * grp_filter - LDAP filter expression template. Default is '(&(objectClass=posixGroup)%s)'.
**ssh_** are for the query fetching the SSH keys:
  * **ssh_base** - base DN for the SSH pub key search.
  * ssh_dn - the attribute containing user name RDN used in memberUid entries. Default is 'uid'.
  * ssh_attr - the attribute containing user SSH pub key(s). Default is 'sshPublicKey'.
  * ssh_filter - LDAP filter expression template. Default is '(&(objectClass=posixAccount)(objectClass=ldapPublicKey)%s)'.

## Cache directory ##
**ldapssh** writes fetched SSH keys in cache files to improve speed and reduce load on LDAP servers. The files are stored under the directory specified in **cache_dir** option and named by this pattern **<section>.<user>.cache**:
    * section - filter configuration section from which query the keys were fetched.
    * user - the login username given as first argument when the utility is invoked by sshd.

Files are created with perms 0600.

On subsequent ligins the modification time on the corresponding cache file is checked and if it's less than **cache_ttl** seconds old its contents is served instead connecting to LDAP servers.

Old cache files are not deleted automatically. A cron job may be set up to do this.

## Security ##
Several things need to be considered for secure implementation:
  * Run the utility with its own user, so that no one but root can read its files.
  * Make sure you have secured your LDAP server with proper ACLs.
  * You might consider using IP addresses in LDAP URIs if a risk of DNS poisoning exists.

## Install ##
Tested only on Debian and FreeBSD.

Build dependencies Debian: libldap-2.4 libldap2-dev
Build dependencies FreeBSD: openldap-client

To install:
```sh
make
make install
```

To deinstall:
```sh
make deinstall
```

## Debian ##
Debian package build files are included in the debian/ directory.


## Copyright notes ##
A code is used from two other projects. Their license files are included.
* [inih](https://github.com/benhoyt/inih) from Ben Hoyt
* [uthash](https://troydhanson.github.io/uthash/) from Troy D. Hanson

