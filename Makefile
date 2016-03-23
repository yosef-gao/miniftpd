.PHONY:clean
GG=gcc
CFLAGS=-Wall -g
BIN=miniftpd
OBJS=main.o sysutil.o common.o session.o ftpproto.o privparent.o

$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(BIN)
   
   
