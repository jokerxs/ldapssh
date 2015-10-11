INCLUDE=	-I/usr/include/ -I/usr/local/include/
LIB=		-L/usr/lib/ -L/usr/local/lib/

# set with '-g' to enable debugging sybbols
SYMBOLS=	
# add '-ansi' to enforce ANSI complience
ANSI=
CFLAGS=		-pedantic -Wno-deprecated-declarations ${ANSI} ${SYMBOLS}

INSTALL=	/usr/bin/install
CP=			/bin/cp

USER=		root
GROUP=		root

PREFIX=		${DESTDIR}/usr
BIN_PREFIX=	${PREFIX}/sbin

CACHEDIR=	${DESTDIR}/var/cache/ldapssh

CONFIGFILE=	ldapssh.conf.dist
CONFIGDIR= ${DESTDIR}/etc
SHAREDDIR= ${DESTDIR}/usr/share/doc/ldapssh


all: ldapssh

ldapssh:
	${CC} $(CFLAGS) -DWITH_OPENLDAP -o ldapssh ini.c ldapssh.c $(INCLUDE) $(LIB) -lldap -llber

clean:
	rm -f ldapssh

install:
	${INSTALL} -o ${USER} -g ${GROUP} -m 0700 ldapssh ${BIN_PREFIX}
	${INSTALL} -o ${USER} -g ${GROUP} -m 0600 -d ${CACHEDIR}
	${INSTALL} -o ${USER} -g ${GROUP} -m 0755 -d ${SHAREDDIR}
	${INSTALL} -o ${USER} -g ${GROUP} -m 0600 ${CONFIGFILE} ${SHAREDDIR}
	test -f ${CONFIGDIR}/ldapssh.conf || \
		${CP} -p ${SHAREDDIR}/${CONFIGFILE} ${CONFIGDIR}/ldapssh.conf

deinstall:
	rm -f ${BIN_PREFIX}/ldapssh
	rm -Rf ${CACHEDIR}
	rm -Rf ${SHAREDDIR}
	rm -f ${CONFIGDIR}/ldapssh.conf

