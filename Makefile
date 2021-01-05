TARGET := www

CFLAGS += -std=c11 -O2 -pthread

all : $(TARGET)

$(TARGET) : $(TARGET).c Makefile
	$(CC) -o $@ $< $(CFLAGS)

.PHONY : all
