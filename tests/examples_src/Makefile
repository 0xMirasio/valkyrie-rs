CC      ?= gcc
CFLAGS  ?= -O3 -fPIC
LDFLAGS ?= -static -fno-stack-protector

BUILD_DIR := build

ARCHES := 32 64
CFLAGS_32 := -m32
CFLAGS_64 := -m64

TARGETS := io #common

SRC_io := io/io.c
#SRC_common := common/common.c

ALL_BINS := $(foreach t,$(TARGETS),$(foreach a,$(ARCHES),$(BUILD_DIR)/$(t)_linux_$(a)))

.PHONY: all init clean io common

all: $(ALL_BINS)

init:
	@mkdir -p $(BUILD_DIR)

io: $(BUILD_DIR)/io_linux_32 $(BUILD_DIR)/io_linux_64
#common: $(BUILD_DIR)/common_linux_32 $(BUILD_DIR)/common_linux_64

define build_rule
$(BUILD_DIR)/$(1)_linux_$(2): $$(SRC_$(1)) | init
	$$(CC) $$(CFLAGS) $$(CFLAGS_$(2)) -o $$@ $$< $$(LDFLAGS) $$(LDFLAGS_$(2))
endef

$(foreach t,$(TARGETS),$(foreach a,$(ARCHES),$(eval $(call build_rule,$(t),$(a)))))

clean:
	rm -rf $(BUILD_DIR)
