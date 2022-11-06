#include "util.h"
#define FAIL    -1

int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;

    //Only root user have the permision to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    // Initialize the SSL library
     SSL_library_init();

    //Initialize SSL 
    ctx = InitServerCTX();

    //Load certs
    LoadCertificates(ctx, "mycert.pem", "mycert.pem");

    //Create server socket 
    portnum = Argc[1];
    server = OpenListener(atoi(portnum));


    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

		//Accept connection as usual 
        int client = accept(server, (struct sockaddr*)&addr, &len);

        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		//Get new SSL state with context 
        ssl = SSL_new(ctx);
		//Set connection socket to SSL state 
        SSL_set_fd(ssl, client);
		//Service connection
        Servlet(ssl);
    }
		//Close server socket 
        close(server); 
		//Release context 
        SSL_CTX_free(ctx);
}
