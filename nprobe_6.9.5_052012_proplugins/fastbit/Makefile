INCLUDES    = -I.. -I.  -I /home/sdu/nprobe_6.9.5_052012_proplugins/nDPI/src/include/
LIBS        =  -L/usr/local/lib -L/opt/local/lib ../.libs/libnprobe.a -lfastbit -lresolv -ldl -lpthread   -lpcap  /home/sdu/nprobe_6.9.5_052012_proplugins/nDPI/src/lib/.libs/libndpi.a
CFLAGS      = -g -g -O2 -I/usr/local/include -I/opt/local/include
INSTALL_DIR = /usr/local/bin
APPS        = fbquery fbmerge fbindex

all: $(APPS)

fbquery: fbquery.cpp Makefile
	g++ $(CFLAGS) $(INCLUDES) -g fbquery.cpp -o fbquery $(LIBS)

fbmerge: fbmerge.cpp fbutils.cpp fbquery.h Makefile
	g++ $(CFLAGS) $(INCLUDES) -g fbmerge.cpp fbutils.cpp -o fbmerge $(LIBS)

fbindex: fbindex.cpp fbutils.cpp fbquery.h Makefile
	g++ $(CFLAGS) $(INCLUDES) -g fbindex.cpp fbutils.cpp -o fbindex $(LIBS)

clean:
	rm -f fbquery fbmerge fbindex *~

install: $(APPS)
	cp $(APPS) $(INSTALL_DIR)

