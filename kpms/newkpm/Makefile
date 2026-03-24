ifeq ($(origin KP_DIR), undefined)
ifneq ($(wildcard ../../KernelPatch/kernel/include/compiler.h),)
    KP_DIR := ../../KernelPatch
else ifneq ($(wildcard ../../kernel/include/compiler.h),)
    KP_DIR := ../..
else
    $(error Unable to locate KernelPatch. Please set KP_DIR=/path/to/KernelPatch)
endif
endif

ifeq ($(origin TARGET_COMPILE), undefined)
    $(error TARGET_COMPILE not set)
endif

ifeq ($(origin CC), command line)
else
    CC := $(TARGET_COMPILE)gcc
endif

ifeq ($(origin LD), command line)
else
    LD := $(TARGET_COMPILE)ld
endif

ifeq ($(origin READELF), command line)
else
    READELF := $(TARGET_COMPILE)readelf
endif

CFLAGS += -std=gnu11
CFLAGS += -D__KERNEL__ -DMODULE
CFLAGS += -fno-pic -fno-pie -fno-stack-protector -fno-common -fno-strict-aliasing

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include linux/include/uapi
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := amem_kpm.o

all: amem_kpm.kpm

amem_kpm.kpm: $(objs)
	$(LD) -r -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean print-vars check-relocs
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f

print-vars:
	@echo KP_DIR=$(KP_DIR)
	@echo CC=$(CC)
	@echo LD=$(LD)
	@echo READELF=$(READELF)

check-relocs: amem_kpm.kpm
	$(READELF) -r $<
