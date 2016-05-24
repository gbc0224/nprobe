SUBDIRS = . 
PLUGIN_DIST_COMMON = Makefile.am Makefile.in
DISTCLEANFILES =  \#* *~ *.log *.o
CLEANFILES     = $(DISTCLEANFILES)
EXTRA_DIST  =
SUFFIXES    = .so
# 
# Where to install the plugin 
# 
plugindir = ${exec_prefix}/lib/nprobe/plugins
libdir = $(plugindir)

INCLUDES = -I.. @INCS@ -I @NDPI_INC@
LIBS     = @LIBS@ @CORELIBS@ @MORELIBS@ @NDPI_LIB@

.NOTPARALLEL:

############################################

libbgpPlugin_la_SOURCES = bgpPlugin.c
libbgpPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libbgpPlugin_la_CFLAGS = $(AM_CFLAGS)

.libs/libbgpPlugin.so@SO_VERSION_PATCH@:
	@if test -f libbgpPlugin_la-bgpPlugin.o; then \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libbgpPlugin.so@SO_VERSION_PATCH@ libbgpPlugin_la-bgpPlugin.o; \
    else \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libbgpPlugin.so@SO_VERSION_PATCH@ bgpPlugin.o; \
    fi

bgpPlugin.so$(EXEEXT): .libs/libbgpPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libbgpPlugin.so bgpPlugin.so$(EXEEXT)


############################################

libdbPlugin_la_SOURCES = dbPlugin.c
libdbPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libdbPlugin_la_CFLAGS = $(AM_CFLAGS)

.libs/libdbPlugin.so@SO_VERSION_PATCH@:
	@if test -f libdbPlugin_la-dbPlugin.o; then \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libdbPlugin.so@SO_VERSION_PATCH@ libdbPlugin_la-dbPlugin.o; \
    else \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libdbPlugin.so@SO_VERSION_PATCH@ dbPlugin.o; \
    fi

dbPlugin.so$(EXEEXT): .libs/libdbPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libdbPlugin.so dbPlugin.so$(EXEEXT)


############################################

libdumpPlugin_la_SOURCES = dumpPlugin.c
libdumpPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libdumpPlugin_la_CFLAGS = $(AM_CFLAGS)

.libs/libdumpPlugin.so@SO_VERSION_PATCH@:
	@if test -f libdumpPlugin_la-dumpPlugin.o; then \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libdumpPlugin.so@SO_VERSION_PATCH@ libdumpPlugin_la-dumpPlugin.o; \
    else \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libdumpPlugin.so@SO_VERSION_PATCH@ dumpPlugin.o; \
    fi

dumpPlugin.so$(EXEEXT): .libs/libdumpPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libdumpPlugin.so dumpPlugin.so$(EXEEXT)


############################################

libmysqlPlugin_la_SOURCES = mysqlPlugin.c
libmysqlPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libmysqlPlugin_la_CFLAGS = $(AM_CFLAGS)

.libs/libmysqlPlugin.so@SO_VERSION_PATCH@:
	@if test -f libmysqlPlugin_la-mysqlPlugin.o; then \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libmysqlPlugin.so@SO_VERSION_PATCH@ libmysqlPlugin_la-mysqlPlugin.o; \
    else \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libmysqlPlugin.so@SO_VERSION_PATCH@ mysqlPlugin.o; \
    fi

mysqlPlugin.so$(EXEEXT): .libs/libmysqlPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libmysqlPlugin.so mysqlPlugin.so$(EXEEXT)


############################################

librtpPlugin_la_SOURCES = rtpPlugin.c
librtpPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
librtpPlugin_la_CFLAGS = $(AM_CFLAGS)

.libs/librtpPlugin.so@SO_VERSION_PATCH@:
	@if test -f librtpPlugin_la-rtpPlugin.o; then \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/librtpPlugin.so@SO_VERSION_PATCH@ librtpPlugin_la-rtpPlugin.o; \
    else \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/librtpPlugin.so@SO_VERSION_PATCH@ rtpPlugin.o; \
    fi

rtpPlugin.so$(EXEEXT): .libs/librtpPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/librtpPlugin.so rtpPlugin.so$(EXEEXT)


############################################

libsipPlugin_la_SOURCES = sipPlugin.c
libsipPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libsipPlugin_la_CFLAGS = $(AM_CFLAGS)

.libs/libsipPlugin.so@SO_VERSION_PATCH@:
	@if test -f libsipPlugin_la-sipPlugin.o; then \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsipPlugin.so@SO_VERSION_PATCH@ libsipPlugin_la-sipPlugin.o; \
    else \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsipPlugin.so@SO_VERSION_PATCH@ sipPlugin.o; \
    fi

sipPlugin.so$(EXEEXT): .libs/libsipPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libsipPlugin.so sipPlugin.so$(EXEEXT)


############################################

libsmtpPlugin_la_SOURCES = smtpPlugin.c
libsmtpPlugin_la_LDFLAGS = -shared -release @PACKAGE_VERSION@ @DYN_FLAGS@
libsmtpPlugin_la_CFLAGS = $(AM_CFLAGS)

.libs/libsmtpPlugin.so@SO_VERSION_PATCH@:
	@if test -f libsmtpPlugin_la-smtpPlugin.o; then \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsmtpPlugin.so@SO_VERSION_PATCH@ libsmtpPlugin_la-smtpPlugin.o; \
    else \
    $(CC) @MAKE_SHARED_LIBRARY_PARM@ -o .libs/libsmtpPlugin.so@SO_VERSION_PATCH@ smtpPlugin.o; \
    fi

smtpPlugin.so$(EXEEXT): .libs/libsmtpPlugin.so@SO_VERSION_PATCH@
	@$(LN_S) .libs/libsmtpPlugin.so smtpPlugin.so$(EXEEXT)

############################################
noinst_PROGRAMS =  bgpPlugin.so dbPlugin.so dumpPlugin.so mysqlPlugin.so rtpPlugin.so sipPlugin.so smtpPlugin.so
lib_LTLIBRARIES =  libbgpPlugin.la libdbPlugin.la libdumpPlugin.la libmysqlPlugin.la librtpPlugin.la libsipPlugin.la libsmtpPlugin.la
