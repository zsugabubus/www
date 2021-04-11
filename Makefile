TARGET := www

CFLAGS += -std=c11 -O2 -pthread -Wall -Wextra

all : $(TARGET)

$(TARGET) : $(TARGET).c Makefile
	$(CC) -o $@ $< $(CFLAGS)

.PHONY : all
