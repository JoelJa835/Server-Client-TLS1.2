#include "util.h"
#define FAIL    -1

int main(int count, char *strings[]){
    int server;
    SSL_CTX *ctx;
    SSL *ssl;
    char *hostname, *portnum;
    char buf[2048];
    char acClientRequest[2048] = {0};
    int bytes;
    
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }

    hostname=strings[1];
    portnum=strings[2];
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));

    //Create new SSL connection state 
    ssl = SSL_new(ctx); 
	//Attach the socket descriptor 
    SSL_set_fd(ssl, server);    
    //Perform the connection 

    //Connection fail
    if ( SSL_connect(ssl) == FAIL )   
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <\\Body>";
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);

		//Construct reply 
        sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));

   		//Get any certs 
        ShowCerts(ssl);

        //Encrypt & send message 
        SSL_write(ssl,acClientRequest, strlen(acClientRequest));

        //Get reply & decrypt
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
	    //Release connection state 
        SSL_free(ssl); 
    }
		//Close socket
        close(server);
		//Release context 
        SSL_CTX_free(ctx);

    return 0;
}
