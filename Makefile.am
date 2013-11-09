CC=gcc
LIB=-lpcre -L./pcre-3.9/ -I./pcre-3.9/
OPT=-O2
OPT_DEBUG=-ggdb -Wall -lefence
BINDIR=/bin
DATADIR=/etc
MANDIR=/man/man1
SCRIPTS=appdefs.trig appdefs.resp appdefs.rpc
MANPAGE=amap.1
all:	pcre strip

pcre:
	cd pcre-3.9 && make

amap-lib.o:	amap-lib.c
	$(CC) $(OPT) -c -o amap-lib.o amap-lib.c $(XIPATHS) $(XDEFINES)

amap:	amap-lib.o amap.c
	@echo
	$(CC) $(OPT) -o amap amap.c amap-lib.o $(LIB) $(XLIBS) $(XLIBPATHS) $(XIPATHS) $(XDEFINES)
	test -e amap6 -o -e amap6.lnk || ln -s amap amap6

amapcrap:	amapcrap.c
	$(CC) $(OPT) -o amapcrap amapcrap.c $(XLIBS) $(XLIBPATHS) $(XIPATHS) $(XDEFINES)
	@echo

strip:	amap amapcrap
	-test -e amap.exe && strip amap.exe amapcrap.exe || echo
	-test -e amap.exe || strip amap amapcrap
	@echo

debug:	amap.c
	$(CC) $(OPT_DEBUG) -o amap amap.c $(LIB) $(XLIBS) $(XLIBPATHS) $(XIPATHS)  $(XDEFINES)
	$(CC) $(OPT_DEBUG) -o amapcrap amapcrap.c $(XLIBS) $(XLIBPATHS) $(XIPATHS) $(XDEFINES)

install:	all
	@echo Installing to $(PREFIX), change this by running ./configure --prefix=path
	-mkdir -vp $(PREFIX)$(BINDIR) 2> /dev/null
	-mkdir -vp $(PREFIX)$(DATADIR) 2> /dev/null
	-mkdir -vp $(PREFIX)$(MANDIR) 2> /dev/null
	-test -e amap.exe || cp -f amap amap6 amapcrap $(PREFIX)$(BINDIR)
	-test -e amap.exe && cp -f amap.exe amapcrap.exe $(PREFIX)$(BINDIR) || echo
	-cp -f $(SCRIPTS) $(PREFIX)$(DATADIR)
	-cp -f $(MANPAGE) $(PREFIX)$(MANDIR)
	-test $(PREFIX)$(BINDIR)/amap6 || cd $(PREFIX)$(BINDIR) && ln -s amap amap6

clean:	
	cd pcre-3.9 && make clean
	rm -f amap amapcrap amap.exe amapcrap.exe amap6 amap-lib.o Makefile.in core *~ Makefile
