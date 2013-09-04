#!/bin/sh

SRC=pixelserv.c
OPTS="-DDO_COUNT -DIF_MODE -DTEXT_REPLY -DDROP_ROOT -DVERBOSE -DREAD_FILE -DREAD_GIF -DNULLSERV_REPLIES -DSSL_RESP"
TEST_OPTS="-DTEST -DHEX_DUMP"

CC="gcc" # -m32" 
CFLAGS="-Os -s -Wall -ffunction-sections -fdata-sections -fno-strict-aliasing"
LDFLAGS="-Wl,--gc-sections"
STRIP="strip -s -R .note -R .comment -R .gnu.version -R .gnu.version_r"
BIN=pixelserv.host
$CC $CFLAGS $OPTS $SRC -o $BIN
$STRIP $BIN
ls -laF $BIN

# use Linksys Tomato toolchain (or teddy_bear tomatousb K26, Tornado dd-wrt)
export PATH=/opt/brcm/hndtools-mipsel-uclibc/bin:/opt/brcm/hndtools-mipsel-linux/bin:$PATH
CC="mipsel-uclibc-gcc -mips32"
CFLAGS="-Os -s -Wall -ffunction-sections -fdata-sections"
LDFLAGS="-Wl,--gc-sections"
STRIP="mipsel-uclibc-strip -s -R .note -R .comment -R .gnu.version -R .gnu.version_r"

#tomato
# -DIF_MODE "-i br0" responsible for failures when gui changes made
# -DVERBOSE"
BIN=pixelserv
$CC $CFLAGS $LDFLAGS $OPTS $SRC -o $BIN
$STRIP $BIN
ls -laF $BIN

OPTS="-O3 -DTINY"
BIN=pixelserv.tiny
$CC $CFLAGS $LDFLAGS $OPTS $SRC -o $BIN
$STRIP $BIN
ls -laF $BIN

