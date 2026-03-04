# Build pam_rosec.so — the PAM module for rosec auto-unlock.
#
# Usage:
#   make                    # build pam_rosec.so
#   make test               # build + run test suite
#   make install            # install to /usr/lib/security/ + /etc/pam.d/
#   make DESTDIR=/pkg install  # for PKGBUILD packaging
#
# Override the helper path at compile time:
#   make ROSEC_PAM_UNLOCK_PATH=/usr/local/lib/rosec/rosec-pam-unlock

CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
LDFLAGS ?=
DESTDIR ?=
PREFIX ?= /usr

ROSEC_PAM_UNLOCK_PATH ?= /usr/lib/rosec/rosec-pam-unlock

PAM_MODULE_DIR = $(PREFIX)/lib/security
PAM_CONFIG_DIR = /etc/pam.d

.PHONY: all clean install test

all: pam_rosec.so

# ── Main PAM module ─────────────────────────────────────────────────

pam_rosec.so: pam_rosec.c
	$(CC) -shared -fPIC $(CFLAGS) $(LDFLAGS) \
		-DROSEC_PAM_UNLOCK_PATH='"$(ROSEC_PAM_UNLOCK_PATH)"' \
		-o $@ $< -lpam

# ── Test infrastructure ─────────────────────────────────────────────

# Mock auth module (simulates pam_unix — prompts for password, sets PAM_AUTHTOK)
pam_mock_auth.so: mock_pam_auth.c
	$(CC) -shared -fPIC $(CFLAGS) $(LDFLAGS) -o $@ $< -lpam

# Mock unlock helper (writes received password to file for verification)
mock_unlock_helper: mock_unlock_helper.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# Build pam_rosec.so for tests with the mock helper path baked in
pam_rosec_test.so: pam_rosec.c mock_unlock_helper
	$(CC) -shared -fPIC $(CFLAGS) $(LDFLAGS) \
		-DROSEC_PAM_UNLOCK_PATH='"$(CURDIR)/mock_unlock_helper"' \
		-o pam_rosec.so $< -lpam

# Test binary
test_pam_rosec: test_pam_rosec.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpam

# Run the test suite
test: pam_rosec_test.so pam_mock_auth.so mock_unlock_helper test_pam_rosec
	@echo ""
	@echo "Running pam_rosec test suite..."
	@echo ""
	./test_pam_rosec

# ── Install ─────────────────────────────────────────────────────────

install: pam_rosec.so
	install -Dm755 pam_rosec.so "$(DESTDIR)$(PAM_MODULE_DIR)/pam_rosec.so"
	install -Dm644 rosec "$(DESTDIR)$(PAM_CONFIG_DIR)/rosec"

# ── Clean ───────────────────────────────────────────────────────────

clean:
	rm -f pam_rosec.so pam_mock_auth.so mock_unlock_helper test_pam_rosec
	rm -rf /tmp/pam_rosec_test.*
