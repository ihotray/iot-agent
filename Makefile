PROG ?= iot-agent
DEFS ?= -liot-base -liot-json -llua
EXTRA_CFLAGS ?= -Wall -Werror
CFLAGS += $(DEFS) $(EXTRA_CFLAGS)

SRCS = main.c rpc.c mqtt.c agent.c

all: $(PROG)

$(PROG):
	$(CC) $(SRCS) $(CFLAGS) -o $@


clean:
	rm -rf $(PROG) *.o
