CC=gcc  #compiler
CFLAGS = -Wall
LDFLAGS = -L/usr/lib -lssl -lcrypto
SERVER_OBJFILES =  server.o util.o
CLIENT_OBJFILES = client.o util.o
CLIENT_TARGET = client  
SERVER_TARGET = server
all:$(CLIENT_TARGET) $(SERVER_TARGET)

$(SERVER_TARGET): $(SERVER_OBJFILES)
	$(CC) $(CFLAGS) -o $(SERVER_TARGET) $(SERVER_OBJFILES) $(LDFLAGS)

$(CLIENT_TARGET):$(CLIENT_OBJFILES)
	$(CC) $(CFLAGS) -o $(CLIENT_TARGET) $(CLIENT_OBJFILES) $(LDFLAGS)
 
clean:
	rm -rf $(SERVER_OBJFILES) $(SERVER_TARGET) $(CLIENT_OBJFILES) $(CLIENT_TARGET) *~	