include ./Makefile.inc

SOURCES=$(wildcard src/*.c)
OUTPUT_FOLDER=./bin
OUTPUT_FILE=$(OUTPUT_FOLDER)/tornado

all:
	mkdir -p $(OUTPUT_FOLDER)
	$(GCC) $(GCCFLAGS) $(SOURCES) -o $(OUTPUT_FILE)

clean:
	rm -rf $(OUTPUT_FOLDER)

.PHONY: all clean