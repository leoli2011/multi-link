DIR = $(shell pwd)

PROGRAM=multilink

obj-y += multilink.o #cm_ubus.o cm_timer.o cm_utils.o
#obj-logger += redis_logger.o redis_thread.o
#obj-lib += libfunc_utils.o
#thread.o


LIBS += #-lctnl -lubus -lubox -lfutils -luci -lm
LIBS_LOGGER += #-lblobmsg_json -ljson-c -lhiredis -lubus  -lubox -lfutils -lpthread -levent
LIBS_INCLUDE += -L./
CFLAGS += -g -Wall -Werror


.PHONY: all clean

all:$(PROGRAM) $(TEST) $(LOGGER)

$(PROGRAM):$(obj-y)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(obj-y) $(LIBS) $(LIBS_INCLUDE)

#$(LOGGER):$(obj-logger)
#	$(CC) $(CFLAGS) -o $(LOGGER) $(obj-logger) $(LIBS_LOGGER) $(LIBS_INCLUDE)

#$(LIBOBJ):$(obj-lib)
#	$(CC) $(CFLAGS) -o $(LIBOBJ) -shared -fPIC $(obj-lib) $(LIBS_INCLUDE) -lubox


#$(TEST):test_ubuss.o
#	$(CC) $(CFLAGS) -o $(TEST) test_ubuss.o $(LIBS) $(LIBS_INCLUDE)

clean:
	rm -f *.o $(PROGRAM)
