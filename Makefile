UNAME := $(shell uname -s)
BUILD := build

# ---------------------------------------------------------------- ios (arm64e)
IOS_CC     := xcrun --sdk iphoneos clang
IOS_MIN    := -miphoneos-version-min=17.0
IOS_CFLAGS := -arch arm64e $(IOS_MIN) -I. \
              -O2 -Wall -Wextra -Wstrict-prototypes -Werror=return-type \
              -fno-stack-protector -fPIC -fblocks -DMELA_TARGET_IOS27
IOS_LDFLAGS:= -arch arm64e -framework Foundation -framework IOKit \
              -framework CoreFoundation -Wl,-dead_strip

IOS_SRC := krw/kbase.c krw/krw.c krw/pac.c krw/virt.c krw/leak.c \
           krw/offsets.c krw/task.c krw/allproc.c krw/sandbox.c \
           krw/amfi.c krw/probe.c krw/patch.c krw/image.c krw/exploit.c \
           krw/trust.c krw/hash.c krw/cdhash.c krw/walk_read.c \
           rootfs/remount.c rootfs/resign.c rootfs/snapshot.c \
           rootfs/persist.c rootfs/install.c loader/run.c loader/daemon.c \
           loader/selftest.c loader/report.c
IOS_M := loader/main.m
IOS_OUT := $(BUILD)/melatonind

# ---------------------------------------------------------------- host sim
SIM_CC     ?= cc
SIM_CFLAGS := -std=gnu11 -O2 -Wall -Wextra -I. -D_DEFAULT_SOURCE -DMELA_HOST_SIM
SIM_SRC := krw/kbase.c krw/krw.c krw/pac.c krw/virt.c krw/leak.c \
           krw/offsets.c krw/task.c krw/allproc.c krw/sandbox.c \
           krw/amfi.c krw/probe.c krw/patch.c krw/image.c krw/exploit.c \
           krw/trust.c krw/hash.c krw/cdhash.c krw/walk_read.c \
           rootfs/snapshot.c rootfs/persist.c rootfs/install.c \
           loader/run.c loader/daemon.c loader/selftest.c loader/report.c \
           sim/sim.c sim/stubs.c sim/verify.c sim/main.c
SIM_OUT := $(BUILD)/melatonin-sim

ifeq ($(UNAME),Darwin)
all: ios
else
all: sim
endif

ios: $(IOS_OUT)

$(IOS_OUT): $(IOS_SRC) $(IOS_M)
	@mkdir -p $(BUILD)
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_SRC) $(IOS_M) $(IOS_LDFLAGS) -o $@

sim: $(SIM_OUT)

$(SIM_OUT): $(SIM_SRC)
	@mkdir -p $(BUILD)
	$(SIM_CC) $(SIM_CFLAGS) -o $@ $(SIM_SRC)

# ---------------------------------------------------------------- app bundle
APP := $(BUILD)/Melatonin.app

app: $(APP)

# unsigned bundle for LiveContainer, cross-compiled on linux. livecontainer
# re-signs guest apps with its own identity, so no developer certificate is
# needed to get melatonin's own UI running on the phone.
LINUX_APP  := $(BUILD)/Melatonin-linux.app
THEOS      ?= $(HOME)/theos
IOS_SDK    ?= $(THEOS)/sdks/iPhoneOS16.5.sdk
IOS_CC_LIN ?= $(THEOS)/toolchain/linux/iphone/bin/clang

app-linux: $(LINUX_APP)

$(LINUX_APP): $(IOS_SRC) app/main.m app/Info.plist
	@mkdir -p $(LINUX_APP)
	$(IOS_CC_LIN) -target arm64-apple-ios17.0 -isysroot $(IOS_SDK) -I. \
		-O2 -Wall -Wextra -fblocks -fobjc-arc \
		-Wno-deprecated-declarations \
		-framework UIKit -framework Foundation -framework IOKit \
		-framework CoreFoundation $(IOS_SRC) app/main.m \
		-o $(LINUX_APP)/Melatonin
	cp app/Info.plist $(LINUX_APP)/Info.plist
	ldid -S $(LINUX_APP)/Melatonin
	@echo "unsigned bundle: $(LINUX_APP)"

$(APP): $(IOS_SRC) app/main.m app/Info.plist app/entitlements.plist
	@mkdir -p $(APP)
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_SRC) app/main.m $(IOS_LDFLAGS) \
		-framework UIKit -o $(APP)/Melatonin
	cp app/Info.plist $(APP)/Info.plist
	@if command -v ldid >/dev/null 2>&1; then \
		ldid -Sapp/entitlements.plist $(APP)/Melatonin; \
	else \
		echo "ldid not found: bundle left unsigned"; \
	fi
	@echo "bundle: $(APP)"

run: $(SIM_OUT)
	./$(SIM_OUT)

test: $(SIM_OUT)
	./$(SIM_OUT)

image-test: $(SIM_OUT)
	./$(SIM_OUT) --dump $(BUILD)/kernel.img
	./$(SIM_OUT) --image $(BUILD)/kernel.img probe
	cp $(BUILD)/kernel.img $(BUILD)/kernel-run.img
	./$(SIM_OUT) --image $(BUILD)/kernel-run.img

cli-test: $(SIM_OUT)
	@mkdir -p $(BUILD)/Demo.app
	@printf '%s' '<?xml version="1.0"?><plist><dict/></plist>' > $(BUILD)/Demo.app/Info.plist
	@printf '\317\372\355\376\000\000\000\000' > $(BUILD)/Demo.app/Demo
	./$(SIM_OUT) --trust $(BUILD)/Demo.app
	./$(SIM_OUT) --install $(BUILD)/Demo.app
	@test -f /tmp/melatonin-root/Applications/Demo.app/Info.plist
	@echo "cli-test: ok"

# ---------------------------------------------------------------- tools
TOOLS := $(BUILD)/koff $(BUILD)/mkfixture $(BUILD)/aa_model $(BUILD)/kdiff $(BUILD)/mkdiffpair

tools: $(TOOLS)

$(BUILD)/koff: tools/koff.c
	@mkdir -p $(BUILD)
	$(SIM_CC) -std=gnu11 -O2 -Wall -Wextra -o $@ $<

$(BUILD)/mkfixture: tools/mkfixture.c
	@mkdir -p $(BUILD)
	$(SIM_CC) -std=gnu11 -O2 -Wall -Wextra -o $@ $<

$(BUILD)/aa_model: tools/aa_model.c
	@mkdir -p $(BUILD)
	$(SIM_CC) -std=gnu11 -O2 -Wall -Wextra -o $@ $< -lm

$(BUILD)/kdiff: tools/kdiff.c
	@mkdir -p $(BUILD)
	$(SIM_CC) -std=gnu11 -O2 -Wall -Wextra -o $@ $<

$(BUILD)/mkdiffpair: tools/mkdiffpair.c
	@mkdir -p $(BUILD)
	$(SIM_CC) -std=gnu11 -O2 -Wall -Wextra -o $@ $<

aa-model: $(BUILD)/aa_model
	$(BUILD)/aa_model

diff-test: $(BUILD)/kdiff $(BUILD)/mkdiffpair
	$(BUILD)/mkdiffpair $(BUILD)/old.kc $(BUILD)/new.kc
	@echo "--- kdiff ---"
	-@$(BUILD)/kdiff $(BUILD)/old.kc $(BUILD)/new.kc --top 6
	@echo "--- json ---"
	-@$(BUILD)/kdiff $(BUILD)/old.kc $(BUILD)/new.kc --json --top 3
	@echo "--- guards ---"
	-@$(BUILD)/kdiff $(BUILD)/old.kc $(BUILD)/new.kc --guards --top 3
	@echo "--- identity ---"
	@$(BUILD)/kdiff $(BUILD)/old.kc $(BUILD)/old.kc --top 3; echo "identical rc=$$? (0 = no changes, expected)"
	@echo "--- exit codes ---"
	@$(BUILD)/kdiff $(BUILD)/old.kc $(BUILD)/new.kc --top 1 >/dev/null; echo "changed rc=$$? (1, expected)"

tool-test: $(TOOLS)
	$(BUILD)/mkfixture $(BUILD)/fixture.kc
	$(BUILD)/koff $(BUILD)/fixture.kc
	$(BUILD)/koff $(BUILD)/fixture.kc --emit json
	@echo "--- header ---"
	@$(BUILD)/koff $(BUILD)/fixture.kc --emit header
	@echo "--- aa model ---"
	@$(BUILD)/aa_model

clean:
	rm -rf $(BUILD)

help:
	@echo "melatonin"
	@echo
	@echo "  make            host simulator (Linux/macOS)"
	@echo "  make run        build and run the full pipeline"
	@echo "  make test       assertions; non-zero on failure"
	@echo "  make ios        build/melatonind (needs xcrun + ldid)"
	@echo "  make app        build/Melatonin.app"
	@echo "  make app-linux  unsigned bundle for LiveContainer (theos sdk)"
	@echo "  make tools      koff, kdiff and the rest"
	@echo "  make tool-test  kernelcache parser + arithmetic model"
	@echo "  make diff-test  synthetic kernelcache pair through kdiff"
	@echo "  make image-test dump kernel RAM, then replay from the file"
	@echo "  make cli-test   trust + install a demo bundle"
	@echo "  make clean      remove build/"
	@echo
	@echo "  tools/pull_kc.sh <build>   kernelcache + kext map from an IPSW"
	@echo "  tools/device.sh            read the build off a connected phone"

.PHONY: all ios sim run test image-test cli-test tools tool-test aa-model diff-test app app-linux clean help
