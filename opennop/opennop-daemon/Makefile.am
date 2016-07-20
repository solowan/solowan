# -*- Makefile -*-

GIT_VERSION := $(shell git describe --abbrev=6 --dirty --always)
AM_CPPFLAGS = ${libnfnetlink_CFLAGS} ${libnetfilter_queue_CFLAGS} \
              ${libnl_CPPFLAGS} -Iinclude -Ilib
#AM_CFLAGS   = -Wall -Wcast-align -Wcast-qual -DVERSION=\"$(GIT_VERSION)\"
AM_CFLAGS   = -Wall -O9 -Wcast-align -Wcast-qual -DVERSION=\"$(GIT_VERSION)\"

AM_LDFLAGS = $(LIBCONFIG_LIBS)

bin_PROGRAMS = opennop/opennop
sbin_PROGRAMS = opennopd/opennopd

opennop_opennop_SOURCES = \
	opennop/opennop.c
opennop_opennop_LDADD = -lutil -lreadline -lpthread -llog4c

opennopd_opennopd_SOURCES = \
	lib/quicklz.c lib/hash.c lib/01dedup.c lib/as.c lib/debugd.c \
	lib/solowan_rolling.c lib/uncomp.c lib/MurmurHash3.c lib/dedup_common.c \
	opennopd/compression.c opennopd/deduplication.c opennopd/csum.c \
	opennopd/help.c opennopd/logger.c opennopd/version.c \
	opennopd/opennopd.c opennopd/packet.c opennopd/queuemanager.c \
	opennopd/sessionmanager.c opennopd/signals.c opennopd/tcpoptions.c \
	opennopd/subsystems/fetcher.c opennopd/subsystems/healthagent.c \
	opennopd/subsystems/sessioncleanup.c opennopd/subsystems/counters.c  \
	opennopd/subsystems/worker.c opennopd/subsystems/memorymanager.c \
	opennopd/subsystems/climanager.c opennopd/subsystems/clicommands.c \
	opennopd/configure.c
	
opennopd_opennopd_LDADD = \
	-lcrypt -ldl -lpthread ${libnetfilter_queue_LIBS}
