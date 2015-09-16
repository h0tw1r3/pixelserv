DISTNAME   = pixelserv
SRCS       = $(DISTNAME).c
VERSION   := $(shell git describe --tags)

OPTS      := -O2 -DDO_COUNT -DTEXT_REPLY -DREAD_FILE -DREAD_GIF -DNULLSERV_REPLIES -DSSL_RESP
TEST_OPTS := -DTEST -DVERBOSE
TINY_OPTS := -Os -DTINY
DEBUG_OPT := -DHEX_DUMP

CC        := gcc
CFLAGS    += -s -Wall -ffunction-sections -fdata-sections -fno-strict-aliasing -DBUILD_USER="$(USER)" -DVERSION="$(VERSION)"
LDFLAGS   += -Wl,--gc-sections
STRIP     := strip -s

MIPTOOLS  := /opt/brcm/hndtools-mipsel-uclibc/bin:/opt/brcm/hndtools-mipsel-linux/bin
MIPREFIX  := mipsel-uclibc-
MIPSCC    := $(MIPREFIX)$(CC)
MIPSSTRIP := $(MIPREFIX)$(STRIP) -R .note -R .comment -R .gnu.version -R .gnu.version_r

ARMTOOLS  := /usr/local/x-tools/arm-unknown-linux-gnueabihf/bin/
ARMPREFIX := arm-unknown-linux-gnueabihf-
ARMCC     := $(ARMPREFIX)$(CC)
ARMSTRIP  := $(ARMPREFIX)$(STRIP) -R .note -R .comment -R .gnu.version -R .gnu.version_r

all: x86 x86_64 mips arm
	@echo "Builds in dist folder."

dist:
	@mkdir dist

compress: dist
	upx dist/$(DISTNAME).*

arm: dist
	PATH=$(ARMTOOLS):$(PATH) $(ARMCC) $(CFLAGS) $(LDFLAGS) $(OPTS) $(SRCS) -o dist/$(DISTNAME).$@
	PATH=$(ARMTOOLS):$(PATH) $(ARMCC) $(CFLAGS) $(LDFLAGS) $(TINY_OPTS) $(SRCS) -o dist/$(DISTNAME).tiny.$@
	PATH=$(ARMTOOLS):$(PATH) $(ARMSTRIP) dist/$(DISTNAME).$@
	PATH=$(ARMTOOLS):$(PATH) $(ARMSTRIP) dist/$(DISTNAME).tiny.$@

mips: dist
	PATH=$(MIPTOOLS):$(PATH) $(MIPSCC) $(CFLAGS) $(LDFLAGS) $(OPTS) $(SRCS) -o dist/$(DISTNAME).$@
	PATH=$(MIPTOOLS):$(PATH) $(MIPSCC) $(CFLAGS) $(LDFLAGS) $(TINY_OPTS) $(SRCS) -o dist/$(DISTNAME).tiny.$@
	PATH=$(MIPTOOLS):$(PATH) $(MIPSSTRIP) dist/$(DISTNAME).$@
	PATH=$(MIPTOOLS):$(PATH) $(MIPSSTRIP) dist/$(DISTNAME).tiny.$@

x86: dist
	$(CC) -m32 $(CFLAGS) $(LDFLAGS) $(OPTS) $(SRCS) -o dist/$(DISTNAME).$@
	$(STRIP) dist/$(DISTNAME).$@

x86_64: dist
	$(CC) -m64 $(CFLAGS) $(LDFLAGS) $(OPTS) $(SRCS) -o dist/$(DISTNAME).$@
	$(STRIP) dist/$(DISTNAME).$@
