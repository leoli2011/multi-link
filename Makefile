DIR = $(shell pwd)

PROGRAM=multilink

obj-y += multilink.o ml_netlink.o

MULTILINK_DEBUG=0

ifeq ($(MULTILINK_DEBUG), 1)
	CFLAGS += -g -O0 -Wall -Werror -DTEST_ENVIRONMENT
else
	CFLAGS += -g -O2 -Wall -Werror -DMODEM_ENVIRONMENT
endif

LIBS += -lnl-3 -lnl-route-3 -lnl-cli-3
#CFLAGS += -I/usr/include/libnl3
#LIBS_INCLUDE += -L./  -L/usr/lib/x86_64-linux-gnu/

.PHONY: all clean

all:$(PROGRAM) $(TEST) $(LOGGER)

$(PROGRAM):$(obj-y)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(obj-y) $(LIBS) $(LIBS_INCLUDE)

clean:
	rm -f *.o $(PROGRAM)
