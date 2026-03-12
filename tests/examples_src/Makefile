CC      ?= gcc
CFLAGS  ?= -O3 -fPIC
LDFLAGS ?= -static -fno-stack-protector
LDFLAGS_DYNAMIC ?= -fno-stack-protector -no-pie

BUILD_DIR := build

ARCHES := 32 64
CFLAGS_32 := -m32
CFLAGS_64 := -m64

TARGETS := io common memory

SRC_io := io/io.c
SRC_common := common/common.c
SRC_memory := memory/memory.c

ALL_BINS := $(foreach t,$(TARGETS),$(foreach a,$(ARCHES),$(BUILD_DIR)/$(t)_linux_$(a)_static)) \
	$(BUILD_DIR)/common_linux_32 \
	$(BUILD_DIR)/common_linux_64

.PHONY: all init clean io common memory
all: $(ALL_BINS)

init:
	@mkdir -p $(BUILD_DIR)

io: $(BUILD_DIR)/io_linux_32_static $(BUILD_DIR)/io_linux_64_static
common: $(BUILD_DIR)/common_linux_32_static $(BUILD_DIR)/common_linux_64_static \
	$(BUILD_DIR)/common_linux_32 $(BUILD_DIR)/common_linux_64
memory: $(BUILD_DIR)/memory_linux_32_static $(BUILD_DIR)/memory_linux_64_static

define build_rule
$(BUILD_DIR)/$(1)_linux_$(2)_static: $$(SRC_$(1)) | init
	$$(CC) $$(CFLAGS) $$(CFLAGS_$(2)) -o $$@ $$< $$(LDFLAGS) $$(LDFLAGS_$(2))
endef

define build_dynamic_rule
$(BUILD_DIR)/$(1)_linux_$(2): $$(SRC_$(1)) | init
	$$(CC) $$(CFLAGS) $$(CFLAGS_$(2)) -o $$@ $$< $$(LDFLAGS_DYNAMIC) $$(LDFLAGS_DYNAMIC_$(2))
endef

$(foreach t,$(TARGETS),$(foreach a,$(ARCHES),$(eval $(call build_rule,$(t),$(a)))))
$(foreach a,$(ARCHES),$(eval $(call build_dynamic_rule,common,$(a))))

clean:
	rm -rf $(BUILD_DIR)
