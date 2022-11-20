include ./Makefile.inc

SOURCES=$(wildcard src/*.c src/negotiation/*.c src/auth/*.c src/request/*.c src/mgmt/*.c src/logging/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c)


OUTPUT_FOLDER=./bin
OUTPUT_FILE=$(OUTPUT_FOLDER)/socks5v
OUTPUT_CLIENT_FILE=$(OUTPUT_FOLDER)/client

all:
	mkdir -p $(OUTPUT_FOLDER)
	$(CC) $(CFLAGS) $(LDFLAGS) $(CLIENT_SOURCES) -o $(OUTPUT_CLIENT_FILE)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES) -o $(OUTPUT_FILE)

mac:
	mkdir -p $(OUTPUT_FOLDER)
	$(CC) $(CFLAGSMAC) $(LDFLAGS) $(CLIENT_SOURCES) -o $(OUTPUT_CLIENT_FILE)
	$(CC) $(CFLAGSMAC) $(LDFLAGS) $(SOURCES) -o $(OUTPUT_FILE)

clean:
	rm -rf $(OUTPUT_FOLDER)

check:
	mkdir -p check
	cppcheck --quiet --enable=all --force --inconclusive . 2> ./check/cppout.txt

	pvs-studio-analyzer trace -- make
	pvs-studio-analyzer analyze
	plog-converter -a '64:1,2,3;GA:1,2,3;OP:1,2,3' -t tasklist -o ./check/report.tasks ./PVS-Studio.log

	rm PVS-Studio.log
	mv strace_out check

.PHONY: all clean check