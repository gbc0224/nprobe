Summary: network probe
Name: nProbe
Version: 6.9.5
Release: 0
License: GPL
Group: Networking/Utilities
URL: http://www.ntop.org/nProbe.html
Source: nProbe-%{version}.tgz
Packager: Luca Deri <deri@ntop.org>
# Temporary location where the RPM will be built
BuildRoot:  %{_tmppath}/%{name}-%{version}-root
Requires: libpcap >= 0.8.3 glibc >= 2.3.4 
# 

%description
nprobe is a software NetFlow v5/v9/IPFIX and nFlow probe that allows to turn
a PC into a NetFlow probe. It has been designed to be compact, easy to
embed, an memory/CPU savvy.

%prep

%setup -q

%build
PATH=/usr/bin:/bin:/usr/sbin:/sbin

if [ -x ./configure ]; then
  CFLAGS="$RPM_OPT_FLAGS" ./configure
else
  CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh
fi
make
#

# Installation may be a matter of running an install make target or you
# may need to manually install files with the install command.
%install
PATH=/usr/bin:/bin:/usr/sbin:/sbin
if [ -d $RPM_BUILD_ROOT ]; then
	\rm -rf $RPM_BUILD_ROOT
fi
make DESTDIR=$RPM_BUILD_ROOT install
mkdir -p $RPM_BUILD_ROOT/usr/local/etc/nprobe
cp EULA.txt *.dat $RPM_BUILD_ROOT/usr/local/etc/nprobe
# Dependencies that we need to include as there is no package
# we can use unfortunaltely
#cp /usr/local/lib/libGeoIP.so.1 $RPM_BUILD_ROOT/usr/local/lib

#
# Cleanup
rm $RPM_BUILD_ROOT/usr/local/lib/nprobe/plugins/lib*n.so
rm $RPM_BUILD_ROOT/usr/local/lib/nprobe/plugins/lib*n.la
rm $RPM_BUILD_ROOT/usr/local/lib/libnprobe.*
#
DST=$RPM_BUILD_ROOT/usr/local/nprobe
SRC=$RPM_BUILD_DIR/%{name}-%{version}
mkdir -p $DST/conf
# Clean out our build directory
%clean
rm -fr $RPM_BUILD_ROOT

%files
/usr/local/bin/nprobe
/usr/local/lib/libnprobe-6.9.5.so
/usr/local/etc/nprobe/GeoIPASNum.dat
/usr/local/etc/nprobe/GeoIPASNumv6.dat
/usr/local/etc/nprobe/GeoLiteCity.dat
/usr/local/etc/nprobe/GeoLiteCityv6.dat
/usr/local/etc/nprobe/EULA.txt
/usr/local/lib/nprobe/plugins/librtpPlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/libsipPlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/libdbPlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/libbgpPlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/libsmtpPlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/libdumpPlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/libhttpPlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/libnflitePlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/libmysqlPlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/libdnsPlugin-6.9.5.so
/usr/local/lib/nprobe/plugins/liblogPlugin-6.9.5.so


# Set the default attributes of all of the files specified to have an
# owner and group of root and to inherit the permissions of the file
# itself.
%defattr(-, root, root)

%changelog
* Fri Jan 27 2006 Fernanda Weiden <nanda@google.com> 4.0
- Original upstream version


