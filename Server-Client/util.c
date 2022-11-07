#include "util.h"
#define FAIL    -1


int OpenConnection(const char *hostname, int port){
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        exit(EXIT_FAILURE);
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    //Define the type of addresses sd can communicate with
    addr.sin_family = AF_INET;
    //Convert the unsigned short integer hostshort from host byte order to network byte order. 
    addr.sin_port = htons(port);

    //Interpret host->h_addr as a pointer to a long
    //The additional star in *(...) dereferences what is now a long for assignment. 
    //This effectively copies all four bytes of the original char array into the single long value 

    //addr.sin_addr.s_addr = *(long*)(host->h_addr);

    //Might brake in little-endian systems so memcpy should be better
    memcpy(&(addr.sin_addr.s_addr), host->h_addr, 4);

    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        exit(EXIT_FAILURE);
    }
    return sd;
}
//Wasn't  needed  in the end 
X509* accessCertificate(X509 *cert, char * path){

    FILE *fp = fopen(path, "r");
    if (!fp) {
	    fprintf(stderr, "Unable to open: %s\n", path);
        exit(1);
    }

    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
	    fprintf(stderr, "Unable to parse certificate in: %s\n", path);
	    fclose(fp);
        exit(1);
    }
    return cert;
}

SSL_CTX* InitServerCTX(void){
    const SSL_METHOD *method;
    SSL_CTX *ctx;
	//Load & register all cryptos, etc.
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

	//Load all error messages 
    SSL_load_error_strings();

    //TLSv1_2_server_method is deprecated
    //method = TLSv1_2_server_method();

    //Create new server-method instance 
    method = TLS_server_method();
	//Create new context from method 
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

SSL_CTX* InitCTX(void){
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    //Load cryptos, et.al. 
	OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
     
    //Bring in and register error messages 
    SSL_load_error_strings();   

    //TLSv1_2_client_method is deprecated 
    //method = TLSv1_2_client_method();

    //Create new client-method instance
    method = TLS_client_method();
    //Create new context 
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}


// Create the SSL socket and intialize the socket address structure
int OpenListener(int port){
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    //Define the type of addresses sd can communicate with
    addr.sin_family = AF_INET;
    //Convert the unsigned short integer hostshort from host byte order to network byte order.
    addr.sin_port = htons(port);
    //Accept connections from any internet address
    addr.sin_addr.s_addr = INADDR_ANY;

    if (sd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }
    if (listen(sd, 10) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return sd;
}

//Check if user is root user or not
int isRoot(){
    if (getuid() != 0)
        return 0;
    else
        return 1;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile){

    //The certificates available via CertFile and KeyFile are trusted.
    if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
        ERR_print_errors_fp(stderr);

    //Specifies that the default locations from which CA certificates are loaded should be used
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);

    //Set the local certificate from CertFile 
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    //Set the private key from KeyFile (may be the same as CertFile) 
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    //Verify private key 
    if ( !SSL_CTX_check_private_key(ctx) ){
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }

}

void ShowCerts(SSL* ssl){
	X509 *cert;
    char *issuer;
    char *subject;

    //Get certificates (if available)
    cert = SSL_get_peer_certificate(ssl);
	
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        
        subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        printf("Subject: %s\n", subject);
       	
        issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        printf("Issuer: %s\n", issuer);

        OPENSSL_free(issuer);
        OPENSSL_free(subject);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

//Serve the connection -- threadable 
void Servlet(SSL* ssl) {
    char buf[2048] = {0};
    int sd, bytes;
    const char* ServerResponse="<\\Body>\
                               <Name>sousi.com</Name>\
                 <year>1.5</year>\
                 <BlogType>Embedded and c\\c++<\\BlogType>\
                 <Author>John Johny<Author>\
                 <\\Body>";
    const char *cpValidMessage = "<Body>\
                               <UserName>sousi<UserName>\
                 <Password>123<Password>\
                 <\\Body>";

	//Do SSL-protocol accept 
    if ( SSL_accept(ssl) == FAIL )
        ERR_print_errors_fp(stderr);
    //else print "Invalid Message"
    else{
        //Get any certificates 
        ShowCerts(ssl);       
        //Get request
        bytes = SSL_read(ssl, buf, sizeof(buf));  

        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);
        if ( bytes > 0 ){
            if(strcmp(cpValidMessage,buf) == 0){   
                //Send reply
                SSL_write(ssl, ServerResponse, strlen(ServerResponse)); 
            }
            else{
                //Send reply for invalid message
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message"));
            }
        }
        else{
            ERR_print_errors_fp(stderr);
        }
    }
  
	//Get socket connection 
    sd = SSL_get_fd(ssl);
	//Release SSL state 
    SSL_free(ssl);
    //Close connection 
    close(sd);
}