TARGET := www

CFLAGS += -std=c11 -O0 -pthread -Wall -Wextra -g

all : $(TARGET)

$(TARGET) : $(TARGET).c Makefile
	$(CC) -o $@ $< $(CFLAGS)

check:
	timeout 1s ./$(TARGET) $(TARGET).c 0:12000 & \
	curl -s http://0:12000 | md5sum | sed 's/-/$(TARGET).c/' | md5sum -c -

	timeout 1s ./$(TARGET) - 0:12001 -- cat $(TARGET).c & \
	curl -s http://0:12001 | md5sum | sed 's/-/$(TARGET).c/' | md5sum -c -

	timeout 1s ./$(TARGET) . 0:12002 & \
	curl -s http://0:12002/$(TARGET).c | md5sum | sed 's/-/$(TARGET).c/' | md5sum -c -

	timeout 2s ./$(TARGET) - 127.1:12003 'yes | sed 21212q' & \
	curl -s http://127.1:12003 | md5sum | grep bce38ecd5a06eba70cf3e47da823a4a3

	timeout 1s ./$(TARGET) $(TARGET).c 127.1:12004 'echo $$*' & \
	curl -s 'http://127.1:12004////%21h%65lp%21///..///..?me' --path-as-is -X POTATO | md5sum | grep "$$(echo POTATO !help! me | md5sum)"

	timeout 1s ./$(TARGET) .git 0:12005 -- pwd & \
	curl -s http://0:12005 | grep '.git$$'

	timeout 1s ./$(TARGET) .git 0:12006 & \
	curl -s http://0:12006 | grep HEAD

	GIT_HTTP_EXPORT_ALL=1 GIT_PROJECT_ROOT=$$PWD timeout 1s ./$(TARGET) . 0:12007 --- git http-backend & \
	curl -s http://0:12007/HEAD | grep ref:

.PHONY : all check
