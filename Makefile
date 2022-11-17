include ./Makefile.inc

SOURCES=$(wildcard src/*.c src/negotiation/*.c src/auth/*.c src/request/*.c)
OUTPUT_FOLDER=./bin
OUTPUT_FILE=$(OUTPUT_FOLDER)/socks5v

all:
	mkdir -p $(OUTPUT_FOLDER)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES) -o $(OUTPUT_FILE)

mac:
	mkdir -p $(OUTPUT_FOLDER)
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