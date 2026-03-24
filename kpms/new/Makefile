ifndef KP_DIR
    KP_DIR = ../../KernelPatch
endif

ifndef CC
    ifndef TARGET_COMPILE
        $(error TARGET_COMPILE or CC not set)
    endif
    CC = $(TARGET_COMPILE)gcc
endif

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := amem_kpm.o

all: amem_kpm.kpm

amem_kpm.kpm: $(objs)
	$(CC) -r -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
