PREFIX   ?=	/usr/local
EPREFIX  ?=	/usr/local
BINDIR   ?=	/usr/local/bin
SHAREDIR ?=	/usr/local/share
MANDIR   ?=	/usr/local/share/man
SYSCONFDIR?=	/etc
BINMODE  ?=	4755
BINOWN  ?=	root
BINGRP  ?=	root
OS_CFLAGS   +=	-D__linux__ -D_DEFAULT_SOURCE -D_GNU_SOURCE
SRCS +=	libopenbsd/errc.c
SRCS +=	libopenbsd/verrc.c
SRCS +=	libopenbsd/progname.c
SRCS +=	libopenbsd/readpassphrase.c
SRCS +=	libopenbsd/strtonum.c
SRCS +=	libopenbsd/execvpe.c
SRCS     +=	pam.c
LDLIBS +=	-lpam
SRCS	+= timestamp.c
