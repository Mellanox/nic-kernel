# SPDX-License-Identifier: GPL-2.0

CFLAGS += -Wall -Wl,--no-as-needed -O2 -g
CFLAGS += -I../../../../../usr/include/ $(KHDR_INCLUDES)
# Additional include paths needed by kselftest.h
CFLAGS += -I../../

# xskxceiver needs a working bpftool to generate its skeleton
BPFTOOL ?= bpftool
HAS_BPFTOOL := $(shell $(BPFTOOL) version >/dev/null 2>&1 && echo y)
ifeq ($(HAS_BPFTOOL),y)
COND_GEN_FILES += xskxceiver
else
$(warning excluding xskxceiver, bpftool not installed or not working)
endif

TEST_FILES := \
	../../../../net/ynl \
	../../../../../Documentation/netlink/specs \
	ksft_setup_loopback.sh \
# end of TEST_FILES

TEST_GEN_FILES := \
	$(patsubst %.c,%.o,$(wildcard *.bpf.c)) \
	$(COND_GEN_FILES) \
	csum \
	gro \
	xdp_helper \
# end of TEST_GEN_FILES

TEST_INCLUDES := $(wildcard py/*.py sh/*.sh)

include ../../lib.mk

# gro optionally needs OpenSSL for PSP.
PKG_CONFIG ?= pkg-config
LIBCRYPTO_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto 2>/dev/null)
LIBCRYPTO_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto 2>/dev/null || \
		    echo -lcrypto)
HAVE_OPENSSL := $(shell echo 'int main(void) { return 0; }' | \
		  $(CC) -x c - -include openssl/evp.h $(LIBCRYPTO_CFLAGS) \
		  $(LIBCRYPTO_LIBS) -o /dev/null >/dev/null 2>&1 && echo 1)

ifeq ($(HAVE_OPENSSL),1)
$(OUTPUT)/gro: CFLAGS += -DHAVE_OPENSSL $(LIBCRYPTO_CFLAGS)
$(OUTPUT)/gro: LDLIBS += $(LIBCRYPTO_LIBS)
else
$(warning libcrypto not found, gro will be built without PSP support)
endif

BPF_PROG_DIRS := xsk
include ../bpf.mk

# AF_XDP test engine used by net/test_xsk.sh.
XSK_SRCS := $(filter-out %.bpf.c,$(wildcard xsk/*.c)) \
	$(top_srcdir)/tools/lib/find_bit.c

$(OUTPUT)/xskxceiver: $(XSK_SRCS) $(wildcard xsk/*.h) \
		      $(OUTPUT)/xsk_xdp_progs.skel.h $(BPFOBJ)
	$(call msg,CC,,$@)
	$(Q)$(CC) -I$(top_srcdir)/tools/include $(CFLAGS) -I$(OUTPUT) \
		-I$(SCRATCH_DIR)/include \
		$(XSK_SRCS) $(BPFOBJ) $(LDLIBS) -lelf -lz -lpthread -o $@

# TEST_GEN_FILES lacks xskxceiver when bpftool fails; clean it anyway.
EXTRA_CLEAN += $(OUTPUT)/xskxceiver
