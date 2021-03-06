CC       ?= gcc
LDOPTS   += -Wl,-z,now -Wl,-z,relro -pie
COPTSWARN = -Wall -Wextra -Wno-unused-parameter -Wpointer-arith -Werror
COPTSSEC  = -D_FORTIFY_SOURCE=2 -O2

LIBPCAPOPTS  = --enable-dbus=no --enable-bluetooth=no --enable-usb=no --without-libnl --disable-canusb
ifeq ($(CC), cc)
	CC = clang
endif

ifeq ($(CC), clang)
	COPTSSEC+=-fstack-protector-strong
else
	COPTSSEC+=-fstack-protector
endif

COPTSDEBUG=-g -ggdb -O0
ifeq ($(BUILD), debugaddress)
	COPTSDEBUG=-g -ggdb -O0 -fsanitize=address -fsanitize=undefined
endif
ifeq ($(BUILD), release)
	MARCH=-march=corei7
	COPTSDEBUG=-g -ggdb -O3 $(MARCH)
endif

COPTS+=$(CFLAGS) $(COPTSDEBUG) $(COPTSWARN) $(COPTSSEC) -fPIE \
	-Ideps/libpcap -I deps/libnfnetlink/include -Ideps/libnetfilter_log/include

all: pmtudd

pmtudd: libpcap.a src/*.c src/*.h Makefile
	$(CC) $(COPTS) \
		src/main.c src/utils.c src/net.c src/uevent.c \
		src/hashlimit.c src/csiphash.c src/sched.c \
		./libpcap.a \
		$(LDOPTS) \
		-o pmtudd

libpcap.a: deps/libpcap
	(cd deps/libpcap && ./configure $(LIBPCAPOPTS) && make)
	cp deps/libpcap/libpcap.a .

clean:
	rm -rf pmtudd pmtudd_*.deb

distclean: clean
	rm -f lib*.a
	-(cd deps/libpcap && make clean && make distclean)

format:
	clang-format-3.5 -i src/*.c src/*.h


# Release process
# ---------------
GITVER       := $(shell git describe --tags --always --dirty=-dev)
VERSION      := $(shell python2 -c 'print "$(GITVER)"[1:].partition("-")[0]')
ITERATION    := $(shell python2 -c 'print ("$(GITVER)"[1:].partition("-")[2] or "0")')
NEXT_VERSION := v0.$(shell python2 -c 'print int("$(GITVER)"[1:].partition("-")[0][2:]) + 1')

.PHONY: release

release:
	@echo "[*] Curr version: $(VERSION)-$(ITERATION)"
	@echo "[*] Next version: $(NEXT_VERSION)"
	echo "$(NEXT_VERSION)  (`date '+%Y%m%d-%H%M'`)" > RELEASE_NOTES.tmp
	git log --reverse --date=short --format="- %ad %s" tags/v$(VERSION)..HEAD >> RELEASE_NOTES.tmp
	echo "" >> RELEASE_NOTES.tmp
	cat RELEASE_NOTES >> RELEASE_NOTES.tmp
	mv RELEASE_NOTES.tmp RELEASE_NOTES
	git add RELEASE_NOTES
	git commit -m "Release $(NEXT_VERSION)"
	git tag $(NEXT_VERSION)
	@echo "[*] To push the release run:"
	@echo "git push origin master; git push origin $(NEXT_VERSION)"

# Build process
# -------------
BIN_PREFIX   ?= /usr/local/bin
PACKAGE_ROOT := $(shell pwd)/tmp/packaging


.PHONY: print-builddeps cf-package

CFDEPENDENCIES = python flex bison gcc make pkg-config

print-builddeps:
	@echo $(CFDEPENDENCIES) $(DEPENDENCIES)


cf-package:
	@echo "[*] resetting submodules"
	git submodule sync --quiet
	git submodule update --init --recursive --quiet
	@echo "[*] rebuilding"
	-$(MAKE) clean
	-$(MAKE) distclean
	$(MAKE) pmtudd BUILD=release CC=gcc
	-mkdir -p $(PACKAGE_ROOT)/$(BIN_PREFIX)
	cp pmtudd $(PACKAGE_ROOT)/$(BIN_PREFIX)

	fakeroot fpm -C $(PACKAGE_ROOT) \
		-s dir \
		-t deb \
		--deb-compression bzip2 \
		-v $(VERSION) \
		--iteration $(ITERATION) \
		-n pmtudd \
		.
	rm -rf $(PACKAGE_ROOT)
