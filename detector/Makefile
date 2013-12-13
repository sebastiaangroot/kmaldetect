SRC=detector.c sigloader.c parser.c sequencer.c util.c logger.c
INC=include/
CFLAGS=-Wall
CC=gcc
OUTPUT=detector

all:
	$(CC) $(SRC) -o $(OUTPUT) -I$(INC) $(CFLAGS)

debug:
	$(CC) $(SRC) -o $(OUTPUT) -I$(INC) $(CFLAGS) -ggdb

clean:
	rm -f $(OUTPUT)
