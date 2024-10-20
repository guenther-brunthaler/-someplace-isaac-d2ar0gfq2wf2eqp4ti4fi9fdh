.POSIX:

# You may redefine these settings via the "make" command line or export them
# as environment variables and (in the latter case only) also
# "export MAKEFLAGS=e". Or just edit this file.

CFLAGS = -D NDEBUG -O
LDFLAGS = -s

# No need to redefine these.
TARGETS = isaac

.PHONY: all clean

all: $(TARGETS)

clean:
	-rm $(TARGETS)
