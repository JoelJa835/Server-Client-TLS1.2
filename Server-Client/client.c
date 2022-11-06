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

    //create new SSL connection state 
    ssl = SSL_new(ctx); 
	//attach the socket descriptor 
    SSL_set_fd(ssl, server);    
    //perform the connection 

    //connection fail
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

		//construct reply 
        sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));

   		// get any certs 
        ShowCerts(ssl);

        //encrypt & send message 
        SSL_write(ssl,acClientRequest, strlen(acClientRequest));

        //get reply & decrypt
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
	    //release connection state 
        SSL_free(ssl); 
    }
		//close socket
        close(server);
		// release context 
        SSL_CTX_free(ctx);

    return 0;
}
