# bench-e2e peer echo-server.
#
# Deployed to the peer host (a second EC2 instance in the same
# placement group) via scripts/bench-nightly.sh. The dev-host build
# here is a smoke-check only — real nightly runs rebuild on the peer
# host so the binary is linked against that host's libc.

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

echo-server: echo-server.c
	$(CC) $(CFLAGS) -o $@ $< -lpthread

clean:
	rm -f echo-server

.PHONY: clean
