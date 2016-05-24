# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# auto makefile for the nprobe
# (this file is processed with 'automake' to produce Makefile.in)
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
#       Copyright (C) 2002-12 Luca Deri <deri@ntop.org> 
#
#                     http://www.ntop.org/ 
# 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#



AUTOMAKE_OPTIONS = 1.6   # Require Automake 1.6 or better.
ACLOCAL_AMFLAGS  = -I m4

#
## The name of the game with its own major, minor and release version.
VERSION  = @PACKAGE_VERSION@
PROGRAM  = @PACKAGE_NAME@

PLATFORM =`uname -p`

APPL= nprobe
PACKAGE=$(APPL)-@PACKAGE_VERSION@-0.$(PLATFORM).rpm
PKGNAME  = @PACKAGE_NAME@

DEFS      = @DEFS@
INCS      = @INCS@

INCLUDES  = -I. $(INCS) -I @NDPI_INC@
LIBS      = @LIBS@ @CORELIBS@ @MORELIBS@ @NDPI_LIB@
CC        = @CC@
CCLD      = @CCLD@
AM_CFLAGS = @CFLAGS@
AM_LDFLAGS= @LDFLAGS@

DISTCLEANFILES =  *~ *.log *.lo *.so *.o $(APPL) @PLUGINS@/*.o @PLUGINS@/*.lo  @PLUGINS@/*~ @PLUGINS@/*.so @PLUGINS@/*.la ./private/dmidecode-2.9/*.[oa~] .libs @PLUGINS@/.libs @USE_LICENSE@ nprobes
CLEANFILES     = $(DISTCLEANFILES)

SUBDIRS = . @PLUGINS@

PKG=nProbe-$(PACKAGE_VERSION)-0.$(PLATFORM).rpm

bin_PROGRAMS = nprobe

# nprobe
nprobe_SOURCES = nprobe.c
nprobe_DEPENDENCIES = systemId.o libnprobe.la
nprobe_LDADD = libnprobe.la
nprobe_LDFLAGS = systemId.o $(AM_LDFLAGS) -pthread -lm
nprobe_CFLAGS =

lib_LTLIBRARIES = libnprobe.la

# nprobe core library

#
# On old systems getopt might be undefined
#
GETOPT_FILES=#getopt1.c getopt.c
libnprobe_la_SOURCES = collect.c engine.c export.c database.c fb.c \
		       $(GETOPT_FILES) globals.c plugin.c template.c \
		       sflow_collect.c util.c version.c $(PF_RING)
libnprobe_la_LDFLAGS = systemId.o $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@
libnprobe_la_DEPENDENCIES = systemId.o

private/license/liblicense.a:
	cd private/license; make

#
# We need to compile it this way as the -fPIC libtool directive
# will break the logic
#

systemId.o: systemId.c Makefile @USE_LICENSE@
	g++ $(CFLAGS) -I@HERE@ @PIC@ -c systemId.c

cleanup-rpm:
	rm -rf $(HOME)/rpmbuild/BUILD/nprobe* $(HOME)/rpmbuild/SOURCES/nProbe*

build-rpm: cleanup-rpm maketarproplugins datfiles $(APPL)
# Do NOT build package as root (http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment)
#	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
#	echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
	rm -rf nProbe-@PACKAGE_VERSION@
	mv nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins nProbe-@PACKAGE_VERSION@
	mkdir nProbe-@PACKAGE_VERSION@/packages
	cp packages/nprobe.spec.in nProbe-@PACKAGE_VERSION@/packages
	cp -r pro nProbe-@PACKAGE_VERSION@
	cp -r private nProbe-@PACKAGE_VERSION@
	cp *.dat COPYING LICENSE EULA.txt nProbe-@PACKAGE_VERSION@
	cp plugins/bgpPlugin.c plugins/dbPlugin.c plugins/dnsPlugin.c plugins/dumpPlugin.c \
	plugins/httpPlugin.c plugins/logPlugin.c plugins/mysqlPlugin.c plugins/nflitePlugin.c \
	plugins/rtpPlugin.c plugins/sipPlugin.c plugins/smtpPlugin.c nProbe-@PACKAGE_VERSION@/plugins
	tar cvfz $(HOME)/rpmbuild/SOURCES/nProbe-@PACKAGE_VERSION@.tgz nProbe-@PACKAGE_VERSION@
	@rm -f $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)
	@cp $(APPL) $(HOME)/rpmbuild/BUILD
	@rpmbuild -bb ./packages/$(APPL).spec
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)"

build-cisco: cleanup-rpm maketarcisco $(APPL)
	rm -rf nprobe-@PACKAGE_VERSION@
	mv nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco nprobe-@PACKAGE_VERSION@
	cp -r private nprobe-@PACKAGE_VERSION@
	cp -r utils nprobe-@PACKAGE_VERSION@
	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	echo '%_topdir %(echo $HOME)/rpmbuild' > $(HOME)/.rpmmacros
	tar cvfz $(HOME)/rpmbuild/SOURCES/nProbe-@PACKAGE_VERSION@.tgz nprobe-@PACKAGE_VERSION@
	mkdir -p $(HOME)/rpmbuild/SOURCES
	@rm -f $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PACKAGE)
	@cp $(APPL) $(HOME)/rpmbuild/BUILD
	@rpmbuild -bb $(APPL)-cisco.spec
	@mv $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PACKAGE) .
	echo "Package $(PACKAGE) is now available"

CLEANLIST = `ls -l $(DESTDIR)$(libdir)/*nprobe*.so $(DESTDIR)$(libdir)/*Plugin*.so | \
          grep -v $(VERSION) | \
          grep -v '\->' | \
          $(AWK) '{ print $$NF }'`

listlibclean:
	@echo ""
	@echo "This is a list of old shared library files that will be deleted"
	@echo "if you run 'make libclean'"
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@echo ""

libclean:
	@echo ""
	@echo "Cleanup of old shared library files..."
	@echo ""
	@echo "  This is a list of files that will be deleted..."
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@echo ""
	@echo ""
	@echo "Press cntl-c to stop or enter to continue and delete these files..."
	@read select
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   ...Deleting $$file"; \
             rm -f $$file; \
          fi; \
        done


clean:
	/bin/rm -rf $(CLEANFILES)

nprobes: $(nprobe_OBJECTS) $(nprobe_DEPENDENCIES)
	cd plugins;make
#	$(CC) -static *.o plugins/*.o -o nprobes  -lpcap -lpthread -ldl $(LIBS)
	$(CC)  *.o plugins/*.o -o nprobes -lpthread -ldl -lresolv -ldl -lpthread -L./private/license -llicense @NDPI_LIB@ /usr/lib/x86_64-linux-gnu/libpcap.a

# Use a different name than fastbit as it's a directory
fast_bit:
	@if test -d "./fastbit"; then \
		cd fastbit; make; \
	fi


############

TODAY=`date +"%D" | sed -e 's/\///g'`

maketar: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_*
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)/packages
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)/utils
	cp COPYING LICENSE EULA.txt nprobe_@PACKAGE_VERSION@_$(TODAY)
	cp python-config nprobe_@PACKAGE_VERSION@_$(TODAY)
	cp -r *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(TODAY)
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)
# Remove private + fastbit makefile
	cp packages/nprobe.spec.in nprobe_@PACKAGE_VERSION@_$(TODAY)/packages
	cp utils/*[ch] utils/Makefile.in nprobe_@PACKAGE_VERSION@_$(TODAY)/utils
	grep -v 'private/Makefile' configure.in | grep -v 'fastbit/Makefile' | sed -e 's/AC_CONFIG_FILES(\[plugins\/Makefile\])/echo ""/g' | sed -e 's/PLUGINS=plugins/PLUGINS=/g' > nprobe_@PACKAGE_VERSION@_$(TODAY)/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -name "svn-commit*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY) -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY).tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)


maketarpro: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_*_pro
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/fastbit
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/packages
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/utils
	cp COPYING LICENSE EULA.txt nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	cp python-config nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	cp -r pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	cp packages/nprobe.spec.in nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/packages
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	cp plugins/dbPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	cp plugins/dumpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/httpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/mysqlPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/rtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/sipPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
#	cp plugins/smtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)_pro
	cp -r fastbit/Makefile.in fastbit/*.cpp fastbit/*.[ch] fastbit/README* nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/fastbit
# Remove private + fastbit makefile
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/plugins/ntop*
	cp utils/*[ch] utils/Makefile.in nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/utils
	grep -v 'private/Makefile' configure.in > nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_pro/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_pro -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_pro.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_pro

maketarproplugins: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_*_proplugin
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/fastbit
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/bgp
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/packages
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/utils
	cp COPYING LICENSE EULA.txt nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	cp python-config nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	cp packages/nprobe.spec.in nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/packages
	cp bgp/bgp_probe_client.pl bgp/README nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/bgp
	cp -r pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	cp utils/*[ch] utils/Makefile.in nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/utils
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/bgpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/patricia.[ch] nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/dbPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/dumpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
#	cp plugins/httpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/mysqlPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/rtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/sipPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp plugins/smtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins
	cp -r fastbit/Makefile.in fastbit/*.cpp fastbit/*.[ch] fastbit/README* nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/fastbit
# Remove private + fastbit makefile
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/plugins/ntop*
	grep -v 'private/Makefile' configure.in > nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_proplugins

maketarfranz: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_*_franz
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_franz
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/packages
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/utils
	cp python-config nprobe_@PACKAGE_VERSION@_$(TODAY)_franz
	cp utils/*[ch] utils/Makefile.in nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/utils
	cp COPYING LICENSE EULA.txt nprobe_@PACKAGE_VERSION@_$(TODAY)_franz
	cp packages/nprobe.spec.in nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/packages
	cp -r pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(TODAY)_franz
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp plugins/dbPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp plugins/dumpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp plugins/httpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp plugins/mysqlPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp plugins/rtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp plugins/sipPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp plugins/smtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp plugins/gtpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp plugins/radiusPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)_franz
# Remove private + fastbit makefile
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/plugins/ntop*
	grep -v 'private/Makefile' configure.in | grep -v 'fastbit/Makefile' > nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_franz/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_franz -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_franz -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_franz -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_franz -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_franz -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	cd nprobe_@PACKAGE_VERSION@_$(TODAY)_franz; svn co https://svn.ntop.org/svn/ntop/trunk/nDPI/; \find . -name ".svn"|xargs /bin/rm -rf {} ';'
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_franz.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_franz

maketarnflite:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_nflite
	mkdir -p nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite/nProbe/plugins
	mkdir -p nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite/PF_RING/NFLite/kernel
	mkdir -p nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite/PF_RING/NFLite/userland
	cp plugins/README.plugins plugins/nflitePlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite/nProbe/plugins
	cp private/PF_RING/NFLite/README private/PF_RING/NFLite/Makefile nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite/PF_RING/NFLite/
	cp private/PF_RING/NFLite/kernel/Makefile private/PF_RING/NFLite/kernel/nflite_plugin.[ch] nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite/PF_RING/NFLite/kernel
	cp private/PF_RING/NFLite/userland/nflite_dump.c private/PF_RING/NFLite/userland/Makefile nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite/PF_RING/NFLite/userland
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_nflite

maketarhttp:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_http
	mkdir -p nprobe_@PACKAGE_VERSION@_$(TODAY)_http/nProbe/plugins
	cp plugins/README.plugins plugins/httpPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_http/nProbe/plugins
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_http -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_http -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_http -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_http -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_http -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_http.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_http

maketardns:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_dns
	mkdir -p nprobe_@PACKAGE_VERSION@_$(TODAY)_dns/nProbe/plugins
	cp plugins/README.plugins plugins/dnsPlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_dns/nProbe/plugins
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_dns -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_dns -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_dns -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_dns -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_dns -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_dns.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_dns

maketaroracle:
	\rm -rf nprobe_@PACKAGE_VERSION@_*_oracle
	mkdir -p nprobe_@PACKAGE_VERSION@_$(TODAY)_oracle/nProbe/plugins
	cp plugins/README.plugins plugins/oraclePlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_oracle/nProbe/plugins
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_oracle -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_oracle -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_oracle -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_oracle -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_oracle -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_oracle.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_oracle

tar: maketar maketarpro maketarproplugins maketarnflite maketarhttp maketardns maketarfranz maketaroracle

maketarcisco: @GEOIP_TARGET@
	\rm -rf nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/plugins
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/bgp
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/html
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/python
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/private
	mkdir nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/utils
	cp python-config nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	cp utils/Makefile utils/nf_reflector.c nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/utils
	cp -r pro *.c *.h third_party nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	cp  private/mongoose.[ch] nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/private
	cp -r ./html/ntop_logo.png ./html/favicon.ico ./html/white_bg.gif ./html/style.css ./html/index.html ./html/sparkline nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/html
	cp python/nprobeStats.py nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/python
	cp plugins/buildMakefile.sh nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/plugins
	cp plugins/ntopPlugin.[ch] nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/plugins
	cp plugins/nflitePlugin.c nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/plugins
	cp utils/nf_reflector.conf nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/utils/nf_reflector.conf.example
	cp README *.in autogen.sh Makefile.am configure.in nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco
	grep -v 'private/Makefile' configure.in | grep -v 'fastbit/Makefile' > nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/configure.in
	\rm -f nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco/libtool
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name "*.bak"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name "#*"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name "*~"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco -type d -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco.tgz ./nprobe_@PACKAGE_VERSION@_$(TODAY)_cisco

binarytar:
	\rm -rf nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)
	mkdir nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY) nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)/plugins
	cp .libs/nprobe .libs/libnprobe-@PACKAGE_VERSION@.so .libs/libnprobe.so nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)
	cp plugins/.libs/lib*Plugin-@PACKAGE_VERSION@.so nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)/plugins
	tar cvfz nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY).tgz nprobe_@PACKAGE_VERSION@-@PLATFORM@_$(TODAY)

install: install-recursive	

datfiles: GeoLiteCity.dat GeoIPASNum.dat GeoIPASNumv6.dat GeoLiteCityv6.dat

GeoLiteCity.dat:
	wget http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
	gunzip GeoLiteCity.dat.gz

GeoIPASNum.dat:
	wget http://www.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
	gunzip GeoIPASNum.dat.gz

GeoIPASNumv6.dat:
	wget http://www.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz
	gunzip GeoIPASNumv6.dat.gz

GeoLiteCityv6.dat:
	wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
	gunzip GeoLiteCityv6.dat.gz
