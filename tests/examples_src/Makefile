CC      ?= gcc
CFLAGS  ?= -O3 -fPIC
LDFLAGS_DYNAMIC ?= -fno-stack-protector -no-pie
LDFLAGS_STATIC ?= -static -fno-stack-protector

BUILD_DIR := build

ARCHES := 32 64
CFLAGS_32 := -m32
CFLAGS_64 := -m64

TARGETS := io common memory network

SRC_io := io/io.c
SRC_common := common/common.c
SRC_memory := memory/memory.c
SRC_network := network/network.c

ALL_BINS := $(foreach t,$(TARGETS),$(foreach a,$(ARCHES),$(BUILD_DIR)/$(t)_linux_$(a))) \
	$(BUILD_DIR)/loader_common_linux_32_static \
	$(BUILD_DIR)/loader_common_linux_64_static

.PHONY: all init clean io common memory network loader-static
all: $(ALL_BINS)

init:
	@mkdir -p $(BUILD_DIR)

io: $(BUILD_DIR)/io_linux_32 $(BUILD_DIR)/io_linux_64
common: $(BUILD_DIR)/common_linux_32 $(BUILD_DIR)/common_linux_64
memory: $(BUILD_DIR)/memory_linux_32 $(BUILD_DIR)/memory_linux_64
network: $(BUILD_DIR)/network_linux_32 $(BUILD_DIR)/network_linux_64
loader-static: $(BUILD_DIR)/loader_common_linux_32_static $(BUILD_DIR)/loader_common_linux_64_static

define build_dynamic_rule
$(BUILD_DIR)/$(1)_linux_$(2): $$(SRC_$(1)) | init
	$$(CC) $$(CFLAGS) $$(CFLAGS_$(2)) -o $$@ $$< $$(LDFLAGS_DYNAMIC) $$(LDFLAGS_DYNAMIC_$(2))
endef

$(foreach t,$(TARGETS),$(foreach a,$(ARCHES),$(eval $(call build_dynamic_rule,$(t),$(a)))))

$(BUILD_DIR)/loader_common_linux_32_static: $(SRC_common) | init
	$(CC) $(CFLAGS) $(CFLAGS_32) -o $@ $< $(LDFLAGS_STATIC) $(LDFLAGS_STATIC_32)

$(BUILD_DIR)/loader_common_linux_64_static: $(SRC_common) | init
	$(CC) $(CFLAGS) $(CFLAGS_64) -o $@ $< $(LDFLAGS_STATIC) $(LDFLAGS_STATIC_64)

clean:
	rm -rf $(BUILD_DIR)
