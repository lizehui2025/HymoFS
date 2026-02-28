# make -C $KDIR ARCH=arm64 M=$(pwd) modules
# For ddk: ddk build android14-6.1  (KDIR set by container)

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

obj-m += hymofs_lkm.o
hymofs_lkm-objs := hymofs_core.o hymofs_tracepoint.o hymofs_ftrace.o

ccflags-y += -gz=none
# Ftrace: always compile (headers need types); runtime __symbol_get, fallback to kprobes if unavailable.
# CONFIG_FUNCTION_TRACER: ftrace_func_t typedef in ftrace.h (pulled in via kprobes.h).
ccflags-y += -DCONFIG_DYNAMIC_FTRACE=1 -DCONFIG_FUNCTION_TRACER=1
# Do NOT add -fno-sanitize=cfi here: init/exit must have kernel-expected CFI type for
# do_one_initcall. Use HYMO_NOCFI only on functions that make indirect calls to resolved symbols.

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) ARCH=arm64 modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean 2>/dev/null || true
	rm -rf .tmp_versions
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: all clean
