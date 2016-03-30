.PHONY:clean
GG=gcc
CFLAGS=-Wall -g
BIN=miniftpd
OBJS=main.o sysutil.o common.o session.o ftpproto.o privparent.o strutil.o parseconf.o tunable.o privsock.o
LIBS=-lcrypt

$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(BIN)
   
   
