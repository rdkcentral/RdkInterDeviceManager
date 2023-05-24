/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 Sky
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <net/if.h>
#include <sys/ioctl.h>
#include "Idm_TCP_apis.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#define MAX_TCP_CLIENTS 30
#define SSL_CERTIFICATE "/tmp/idm_xpki_cert"
#define SSL_KEY         "/tmp/idm_xpki_key"
#define SSL_CA_CERTIFICATE "/tmp/idm_UPnP_CA"

bool ssl_lib_init = false;
bool TCP_server_started = false;

typedef int (*callback_recv)( connection_info_t* conn_info, void *payload);

typedef struct tcp_server_threadargs
{
    callback_recv cb;
    int port;
    char interface[INTF_SIZE];
} TcpServerThreadArgs;

SSL_CTX* init_ctx(void)
{
    SSL_CTX *ctx = NULL;
    ctx = SSL_CTX_new(SSLv23_method());
    return ctx;
}

int load_certificate(SSL_CTX* ctx)
{
    if ( SSL_CTX_use_certificate_file(ctx, SSL_CERTIFICATE, SSL_FILETYPE_PEM) <= 0 )
    {
        CcspTraceError(("(%s:%d) Error in loading certificate\n", __FUNCTION__, __LINE__));
        return -1;
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx, SSL_KEY, SSL_FILETYPE_PEM) <= 0 )
    {
        CcspTraceError(("(%s:%d) Error in loading private key file\n", __FUNCTION__, __LINE__));
        return -1;
    }
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        CcspTraceError(("(%s:%d) Error in verifying privat key with certificate file\n", __FUNCTION__, __LINE__));
    }
    /* Load CA certificate for certificate verification */
    if(! SSL_CTX_load_verify_locations(ctx, SSL_CA_CERTIFICATE, NULL))
    {
        CcspTraceError(("(%s:%d) Error in loading CA certificate\n", __FUNCTION__, __LINE__));
        return -1;
    }

    CcspTraceInfo(("(%s:%d)Certificate , private key & CA loaded successfully\n", __FUNCTION__, __LINE__));
    return 0;
}


/* Callback function will be invoked after client certificate validation. 
  Verifiation result will be in "preverify_ok"
*/
static int client_cert_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    struct http_ctx *ctx;
    X509 *cert;
    int err, depth;
    char buf[256];
    X509_NAME *name;
    const char *err_str;
    SSL *ssl;

    CcspTraceInfo(("(%s:%d)SSL Client cert verification status : %d\n", __FUNCTION__, __LINE__, preverify_ok));

    if(!preverify_ok)
    {
        // Get error code and convert it to  error string
        CcspTraceError(("(%s:%d)SSL Client cert verification failed: %d\n", __FUNCTION__, __LINE__, preverify_ok));
        CcspTraceError(("(%s:%d)Terminating SSL handshake: %d\n", __FUNCTION__, __LINE__));
        err = X509_STORE_CTX_get_error(x509_ctx);
        if(err != X509_V_OK)
        {
            err_str = X509_verify_cert_error_string(err);
            CcspTraceError(("(%s:%d) Error is :%s\n", __FUNCTION__, __LINE__,err_str));
        }
    } 
    else
    {
        //At this point preverify_ok is 1. But do additional check and reset it
        // do an additional check for subject name which may not be found by default validation
        cert = X509_STORE_CTX_get_current_cert(x509_ctx);
        if(cert == NULL)
        {

            CcspTraceError(("(%s:%d)SSL Client certificate is unavailable \n", __FUNCTION__, __LINE__));
            // set preverify_ok and return it such that ssl handshake will be terminated
            preverify_ok = 0;
            CcspTraceError(("(%s:%d)Terminating SSL handshake \n", __FUNCTION__, __LINE__));
            return preverify_ok;
        }
        name = X509_get_subject_name(cert);
        if(!name)
        {
            CcspTraceError(("(%s:%d)SSL Client certificate subject name invalid \n", __FUNCTION__, __LINE__));
            // set preverify_ok and return it such that ssl handshake will be terminated
            CcspTraceError(("(%s:%d)Terminating SSL handshake \n", __FUNCTION__, __LINE__));
            preverify_ok = 0;
        }
    }

    // if preverify_ok == 0, ssl handshake will automatically get terminated
    return preverify_ok;
}

void tcp_server_thread(void *arg)
{
    struct sockaddr_in servaddr;
    int master_sock_fd = -1;
    int rc = 0, sd = 0, i;
    fd_set rset;
    int max_fd = 0;
    int c_fd = 0;
    int client_socket[MAX_TCP_CLIENTS];
    int optval = 1;
    payload_t buffer;
    SSL_CTX *ctx = NULL;
    SSL *ssl[MAX_TCP_CLIENTS] = {NULL};
    int      fd = -1;
    struct  ifreq ifr;
    char interface[INTF_SIZE];
    TcpServerThreadArgs *ta = arg;
    int port_no = ta->port;
    callback_recv rcv_cb = ta->cb;
    strncpy_s(interface, sizeof(interface), ta->interface, INTF_SIZE);

    if (( fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        CcspTraceInfo(("%s %d Socket creation failed : %s", __FUNCTION__, __LINE__, strerror(errno)));
        return;
    }

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, ta->interface);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
    {
        CcspTraceInfo(("%s %d Failed to get ip %s \n", __FUNCTION__, __LINE__, strerror(errno)));
        close(fd);
        return;
    }
    close(fd);

    CcspTraceInfo(("%s %d -TCP server thread started\n", __FUNCTION__, __LINE__));
    pthread_detach(pthread_self());

    //initialise all client_socket[] to 0 so not checked
    for (i = 0; i < MAX_TCP_CLIENTS; i++)
    {
        client_socket[i] = 0;
    }

    master_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(master_sock_fd < 0)
    {
        CcspTraceInfo(("\nIDM Server socket open failed\n"));
        rc = EINVAL;
        return 0;
    }

    if( setsockopt(master_sock_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) )
    {
        CcspTraceError(("server socket SO_REUSEADDR flag set failed : %s", strerror(errno)));
        close(master_sock_fd);
        return 0;
    }

#ifndef IDM_DEBUG
    if (!ssl_lib_init) {
        ssl_lib_init = true;
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
    }
    if ((ctx = init_ctx()) == NULL) {
        CcspTraceError(("(%s:%d) SSL ctx creation failed!!\n", __FUNCTION__, __LINE__));
        return;
    }
    if (load_certificate(ctx) == -1) {
        CcspTraceError(("(%s:%d) Can't use certificate now!!\n", __FUNCTION__, __LINE__));
        SSL_CTX_free(ctx);
        close(master_sock_fd);
        return;
    }
#endif
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    servaddr.sin_port = htons(port_no);

    rc = bind(master_sock_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if(rc < 0)
    {
        CcspTraceInfo(("\nIDM Server socket bind failed\n"));
        SSL_CTX_free(ctx);
        close(master_sock_fd);
        return;
    }

    rc = listen(master_sock_fd, MAX_TCP_CLIENTS);

    if(rc < 0)
    {
        CcspTraceInfo(("\nIDM server socket listen failed\n"));
        SSL_CTX_free(ctx);
        close(master_sock_fd);
        return;
    }

    while(TRUE)
    {
        FD_ZERO(&rset);
        FD_SET(master_sock_fd, &rset);
        max_fd = master_sock_fd;
        //add child sockets to set
        for ( i = 0 ; i < MAX_TCP_CLIENTS ; i++)
        {
            //socket descriptor
            sd = client_socket[i];

            //if valid socket descriptor then add to read list
            if(sd > 0)
                FD_SET( sd , &rset);

            //highest file descriptor number, need it for the select function
            if(sd > max_fd)
                max_fd = sd;
        }

        select( max_fd + 1 , &rset , NULL , NULL , NULL);
        if(FD_ISSET(master_sock_fd, &rset))
        {
            c_fd = accept(master_sock_fd, NULL, NULL);
            if(c_fd < 0){
                perror("idm : AF_INET accept failed");
            }
            CcspTraceInfo(("New Client Connected Successfully with socket id  = %d\n", c_fd));
            //Save the new client FD in a vacant slot of client FD array
            for(i = 0; i< MAX_TCP_CLIENTS; i++)
            {
                if(client_socket[i] == 0)
                {
                    client_socket[i] = c_fd;
                    c_fd = 0;
                    break;
                }
            }
            //No space left to hold the new connection, if you want increase MAX_CLIENTS
            if(c_fd != 0)
            {
                //close(c_fd);
                CcspTraceInfo(("\nNo space left = %d\n", c_fd));
            }
#ifndef IDM_DEBUG
            ssl[i] = SSL_new(ctx);
            if (ssl[i] != NULL) {
                SSL_set_fd(ssl[i], client_socket[i]);
                /* Acting as SSL socker server mode. By default server certificate will be validated by client
                 Forcefully request client certificate */
                CcspTraceInfo(("(%s:%d)requesting client's certificate\n", __FUNCTION__, __LINE__));
                /* 1.Set client certificate validation
                   2.Log error code in callback
                   3.Do additional check in callback and forcefully terminate the handshake if required */
                SSL_set_verify(ssl[i], SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, client_cert_verify_cb);
                /* 1. Start handshake with mutual certificate authentication
                   2. callback will be called during handshake */
                if (SSL_accept(ssl[i]) <= 0) 
                {
                    CcspTraceError(("(%s:%d)SSL handshake failed\n", __FUNCTION__, __LINE__));
                    //For logging purpose
                    X509 *peer_cert = SSL_get_peer_certificate(ssl[i]);
                    if(peer_cert == NULL)
                    {
                        CcspTraceError(("(%s:%d)Peer certificate not present\n", __FUNCTION__, __LINE__));
                    }
                    else
                    {
                        free(peer_cert);
                    }
                    // free the resources
                    SSL_free(ssl[i]);
                    ssl[i] = NULL;
                    client_socket[i] = 0;
                }
                else
                {
                    // At this point both client and server certificates are validated
                    CcspTraceInfo(("(%s:%d)SSL Mutual authentication succeeded..\n", __FUNCTION__, __LINE__));
                    CcspTraceInfo(("(%s:%d)SSL Connection Accepted..\n", __FUNCTION__, __LINE__));
                }
            } else {
                CcspTraceError(("(%s:%d) SSL session creation failed for client (%d)\n", __FUNCTION__, __LINE__, c_fd));
            }
#endif
        }
        //else its some IO operation on some other socket
        for (i = 0; i < MAX_TCP_CLIENTS; i++)
        {
            sd = client_socket[i];
            if (FD_ISSET(sd , &rset))
            {
                int ret;
                //Check if it was for closing , and also read the
                //incoming message
                memset((void *)&buffer, 0, sizeof(payload_t));
#ifndef IDM_DEBUG
                ret = SSL_read(ssl[i], (void *)&buffer, sizeof(payload_t));
                usleep(150000);
#else
                ret = read( sd , (void *)&buffer, sizeof(payload_t));
#endif

                if (ret <= 0)
                {
                    if (ret == 0)
                    {
                        //Somebody disconnected
                        //Close the socket and mark as 0 in list for reuse
                        CcspTraceInfo(("(%s:%d) Client socket(%d) closed\n", __FUNCTION__, __LINE__, sd));
#ifndef IDM_DEBUG
                        SSL_free(ssl[i]);
                        ssl[i] = NULL;
#endif
                        close(sd);
                        client_socket[i] = 0;
                    } else {
                        CcspTraceError(("(%s:%d) SSL Read failed\n", __FUNCTION__, __LINE__));
                    }
                }
                //Echo back the message that came in
                else
                {
                    connection_info_t client_info;
                    client_info.conn = sd;
#ifndef IDM_DEBUG
                    client_info.enc.ssl = ssl[i];
#endif
                    rcv_cb(&client_info, (void *)&buffer);
                }
            }
        }
    }
    pthread_exit(NULL);
}

int open_remote_connection(connection_config_t* connectionConf, int (*connection_cb)(device_info_t* Device, connection_info_t* conn_info, uint encryption_status), int (*rcv_message_cb)( connection_info_t* conn_info, void *payload))
{
    CcspTraceInfo(("%s %d -  \n", __FUNCTION__, __LINE__));
    struct sockaddr_in servaddr;
    int client_sockfd;
    bool enc_status = false;
    TcpServerThreadArgs ta;

    memset (&ta,'\0',sizeof(TcpServerThreadArgs));

    strncpy_s(ta.interface, sizeof(ta.interface), connectionConf->interface, INTF_SIZE);
    ta.port = connectionConf->port;
    ta.cb = rcv_message_cb;

    /* start tcp server */
    if(!TCP_server_started)
    {
        pthread_t                server_thread;
        int                      iErrorCode     = 0;

        iErrorCode = pthread_create( &server_thread, NULL, &tcp_server_thread, &ta);
        if( 0 != iErrorCode )
        {
            CcspTraceInfo(("%s %d - Failed to start tcp_server_thread Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
            return -1;
        }
        else
        {
            TCP_server_started = true;
            CcspTraceInfo(("%s %d - IDM tcp_server_thread Started Successfully\n", __FUNCTION__, __LINE__ ));
        }
    }

    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd == -1)
    {
        CcspTraceInfo(("IDM Client socket creation failed...\n"));
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(connectionConf->device->ipv4_addr);
    servaddr.sin_port = htons(connectionConf->port);

    CcspTraceInfo(("waiting to connect to the IDM server..\n"));
    while (1)
    {
        // Wait indefinitely untill other end idm server accepts the connection
        if (connect(client_sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0)
        {
            sleep(1);
        }
        else {
            CcspTraceInfo(("IDM Client connected to the IDM server.. %d\n",client_sockfd));
            break;
        }
    }
    //TODO: check for dynamic allocation
    connection_info_t conn_info;
    conn_info.conn = client_sockfd;
#ifndef IDM_DEBUG
    const char *err_str;
    int err;
    conn_info.enc.ctx = NULL;
    conn_info.enc.ssl = NULL;
    int server_cert_status = 0;

    // Client encryption
    conn_info.enc.ssl = NULL;
    if (!ssl_lib_init) {
        ssl_lib_init = true;
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
    }
    if ((conn_info.enc.ctx = init_ctx()) == NULL) {
        CcspTraceError(("(%s:%d) SSL ctx creation failed!!\n", __FUNCTION__, __LINE__));
        return -1;
    }
    // when SSL connect is called , server will ask client certificate
    // Prepare client certificate
    if (load_certificate(conn_info.enc.ctx) == -1) {
        CcspTraceError(("(%s:%d) Can't use certificate now!!\n", __FUNCTION__, __LINE__));
        SSL_CTX_free(conn_info.enc.ctx);
        return -1;
    }
    if ((conn_info.enc.ssl = SSL_new(conn_info.enc.ctx)) == NULL) {
        CcspTraceError(("(%s:%d) SSL session creation failed!!\n", __FUNCTION__, __LINE__));
        SSL_CTX_free(conn_info.enc.ctx);
        return -1;
    }
    SSL_set_fd(conn_info.enc.ssl, client_sockfd);
    if (SSL_connect(conn_info.enc.ssl) > 0) {
        CcspTraceInfo(("SSL connect: Mutual authentication succeeded..\n"));
        enc_status = true;
    }
    else
    {
        CcspTraceInfo(("SSL connect failed\n"));
        CcspTraceInfo(("Encryption status is set to false\n"));
        // Find out the reason if this is peer certificate issue
        X509 *peer_cert = NULL;
        if((peer_cert = SSL_get_peer_certificate(conn_info.enc.ssl)) != NULL) 
        {
            CcspTraceInfo(("(%s:%d)Server certificate received\n", __FUNCTION__, __LINE__));
            // parse the certificate for any error
            if ((server_cert_status = SSL_get_verify_result(conn_info.enc.ssl) != X509_V_OK)) 
            {
                err_str = X509_verify_cert_error_string(server_cert_status);
                CcspTraceInfo(("(%s:%d)Server certificate Error:%s\n", __FUNCTION__, __LINE__, err_str));
            }
            free(peer_cert);
        }
        else
        {
            CcspTraceInfo(("(%s:%d)Server certificate is unavailable\n", __FUNCTION__, __LINE__));
        }
        // free resources
        SSL_CTX_free(conn_info.enc.ctx);
        SSL_free(conn_info.enc.ssl);
        conn_info.enc.ssl = NULL;
        client_sockfd = 0;
    }
#else
    CcspTraceError(("(%s:%d) Refactor Disabled. Continue Connection without encryption\n", __FUNCTION__, __LINE__));
    enc_status = true;
#endif
    connection_cb(connectionConf->device, &conn_info, enc_status);
    return 0;
}

int getFile_to_remote(connection_info_t* conn_info,void *payload)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    FILE* fptr;
    payload_t *Data;
    char* buffer;
    int bytes = 0;
    size_t length;

#ifndef IDM_DEBUG
    if(conn_info->enc.ssl == NULL){
        CcspTraceError(("(%s:%d) SSL CTX is NULL, Data send failed\n", __FUNCTION__, __LINE__));
        return FT_ERROR;
    }
#endif
    Data = (payload_t*)payload;
    fptr = fopen(Data->param_name,"rb");
    CcspTraceInfo(("Inside %s:%d file name=%s\n",__FUNCTION__,__LINE__,Data->param_name));
    if(!fptr)
    {
        CcspTraceError(("%s:%d file not present\n",__FUNCTION__,__LINE__));
        strncpy_s(Data->param_value,sizeof(Data->param_value),FT_INVALID_FILE_NAME,strlen(FT_INVALID_FILE_NAME));
#ifndef IDM_DEBUG
        if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
        {
            CcspTraceError(("%s:%d invalid file name information is sent to peer device\n",__FUNCTION__,__LINE__));
        }
#else
        if(send(conn_info->conn, Data, sizeof(payload_t), 0)<0){
            CcspTraceError(("%s %d - send failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
            return FT_ERROR;
        }
#endif
        return FT_INVALID_SRC_PATH;
    }
    fseek (fptr, 0, SEEK_END);
    length = ftell (fptr);
    CcspTraceDebug(("length of the file=%zu\n",length));
    fseek (fptr, 0, SEEK_SET);
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
    {
        CcspTraceError(("(%s:%d) idmDmlInfo is null\n",__FUNCTION__, __LINE__));
	fclose(fptr);
        return FT_ERROR;
    }
    if(length > (pidmDmlInfo->stRemoteInfo.max_file_size))
    {
        fclose(fptr);
        strncpy_s(Data->param_value,sizeof(Data->param_value),FT_FILE_SIZE_EXCEED,strlen(FT_FILE_SIZE_EXCEED));
#ifndef IDM_DEBUG
        if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
        {
            CcspTraceError(("%s:%d file size is more than the configured value and information is sent to peer device\n",__FUNCTION__,__LINE__));
        }
#else
        if(send(conn_info->conn, Data, sizeof(payload_t), 0)<0){
            CcspTraceError(("%s %d - send failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return FT_ERROR;
        }
#endif
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return FT_INVALID_FILE_SIZE;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    buffer = (char*)malloc (256);
    if(buffer)
    {
        memset(buffer,0,256);
        sprintf(buffer,"%zu",length);
        strncpy_s(Data->param_value,sizeof(Data->param_value),buffer,strlen(buffer));
#ifndef IDM_DEBUG
        if(conn_info->enc.ssl == NULL){
            CcspTraceError(("(%s:%d) SSL CTX is NULL, Data send failed\n", __FUNCTION__, __LINE__));
            free(buffer);
            fclose(fptr);
            return FT_ERROR;
        }
        if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
        {
            free(buffer);
            buffer =(char*)malloc (length);
            if(buffer)
            {
                if(1 != fread (buffer, length, 1, fptr)) {
                    CcspTraceError(("fread failed \n"));
                    fclose(fptr);
                    return ANSC_STATUS_FAILURE;
                }
                if((bytes = SSL_write(conn_info->enc.ssl, buffer,length)) <= 0)
                {
                    CcspTraceError(("file data is not transformed\n"));
                }
                CcspTraceDebug(("bytes written = %d and length=%d\n",bytes,(int)length));
            }
            else
            {
                fclose(fptr);
                CcspTraceError(("malloc failed to allocate memory\n"));
                return FT_ERROR;
            }
        }
        else
        {
            CcspTraceError(("length data is not transformed\n"));
        }
#else
        if(send(conn_info->conn, Data, sizeof(payload_t), 0)<0){
            CcspTraceError(("%s %d - send failed failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
            free(buffer);
            fclose(fptr);
            return FT_ERROR;
        }
        free(buffer);
        buffer =(char*)malloc (length);
        if(buffer)
        {
            if(1 != fread (buffer,length, 1,fptr)) {
                 CcspTraceError(("fread failed \n"));
                 fclose(fptr);
                 return ANSC_STATUS_FAILURE;
            }
            if((bytes = send(conn_info->conn, buffer,length,0))<=0){
                CcspTraceError(("file data is not transformed through send\n"));
            }
            CcspTraceDebug(("bytes written = %d and length=%d through send\n",bytes,(int)length));
        }
        else
        {
            fclose(fptr);
            CcspTraceError(("malloc failed to allocate memory\n"));
            return FT_ERROR;
        }
#endif
    }
    else
    {
        fclose(fptr);
        CcspTraceError(("malloc failed to allocate memory\n"));
        return FT_ERROR;
    }
    if(buffer)
    {
        free(buffer);
    }
    fclose(fptr);
    return FT_SUCCESS;
}

int sendFile_to_remote(connection_info_t* conn_info,void *payload,char* output_location)
{
    CcspTraceDebug(("Inside %s %d\n",__FUNCTION__,__LINE__));
    FILE* fptr;
    size_t length;
    payload_t *Data;
    int bytes = 0;
    char* buffer = NULL;
    errno_t rc = -1;
#ifndef IDM_DEBUG
    if(conn_info->enc.ssl == NULL)
    {
        CcspTraceError(("(%s:%d) SSL CTX is NULL, Data send failed\n", __FUNCTION__, __LINE__));
        return FT_ERROR;
    }
#endif
    Data = (payload_t*)payload;
    fptr = fopen(Data->param_name,"rb");
    CcspTraceInfo(("Inside %s:%d file name=%s\n",__FUNCTION__,__LINE__,Data->param_name));
    if(!fptr)
    {
        CcspTraceError(("%s:%d file not present\n",__FUNCTION__,__LINE__));
        return FT_INVALID_SRC_PATH;
    }
    fseek (fptr, 0, SEEK_END);
    length = ftell (fptr);
    CcspTraceDebug(("length of the file=%zu\n",length));
    fseek (fptr, 0, SEEK_SET);
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
    {
        CcspTraceError(("(%s:%d) idmDmlInfo is null\n",__FUNCTION__, __LINE__));
	fclose(fptr);
        return FT_ERROR;
    }
    if(length > (pidmDmlInfo->stRemoteInfo.max_file_size))
    {
        fclose(fptr);
        CcspTraceError(("%s:%d file size is more than the configured value\n",__FUNCTION__,__LINE__));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return FT_INVALID_FILE_SIZE;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    Data->file_length=(int)length;
    rc = strcpy_s(Data->param_name,sizeof(Data->param_name),output_location);
    if(rc != EOK)
    {
        ERR_CHK(rc);
	fclose(fptr);
        return ANSC_STATUS_FAILURE;
    }

    buffer =(char*)malloc (length);
    if(!buffer)
    {
        CcspTraceError(("memory is not allocated\n"));
        fclose(fptr);
        return FT_ERROR;
    }
    memset(buffer,0,length);
    if(1 != fread (buffer, length, 1, fptr)) {
        CcspTraceError(("fread failed \n"));
        free(buffer);
        fclose( fptr );
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceDebug(("%s:%d output file name = %s length=%zu length in Data=%d\n",__FUNCTION__,__LINE__,Data->param_name,length,Data->file_length));
#ifndef IDM_DEBUG
    if (conn_info->enc.ssl == NULL)
    {
        CcspTraceError(("%s:%d ssl session is null\n",__FUNCTION__,__LINE__));
        free(buffer);
        fclose(fptr);
        return FT_ERROR;
    }
    if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
    {
        // above ssl write transfers the information about file length and output file location whereas below one sends the file content
        if((bytes = SSL_write(conn_info->enc.ssl, buffer,length)) <= 0)
        {
            CcspTraceError(("file data is not transformed\n"));
        }
        CcspTraceDebug(("bytes written = %d and length=%d\n",bytes,(int)length));
    }
    else
    {
        CcspTraceError(("length data is not transformed\n"));
    }
#else
    if(conn_info->conn == NULL)
    {
        CcspTraceError(("%s:%d conn value is null\n",__FUNCTION__,__LINE__));
        free(buffer);
        fclose(fptr);
        return FT_ERROR;
    }
    if(send(conn_info->conn, Data,sizeof(payload_t), 0) > 0)
    {
        CcspTraceDebug(("bytes written = %d and length=%d\n",bytes,(int)length));
        if((bytes = send(conn_info->conn, buffer,length,0))<=0){
            CcspTraceError(("file data is not transformed through send\n"));
        }
    }
    else
    {
        CcspTraceError(("%s:%d length and file data is not transformed\n",__FUNCTION__,__LINE__));
        free(buffer);
        fclose(fptr);
        return FT_ERROR;
    }
#endif
    free(buffer);
    fclose(fptr);
    return FT_SUCCESS;
}

int send_remote_message(connection_info_t* conn_info,void *payload)
{
#ifndef IDM_DEBUG
    int val;
    if (conn_info->enc.ctx != NULL && conn_info->enc.ssl != NULL) {
        if ((val = SSL_write(conn_info->enc.ssl, payload, sizeof(payload_t))) > 0) {
            return 0;
        }
        else
        {
            CcspTraceError(("(%s:%d) Data encryption failed (Err: %d)", __FUNCTION__, __LINE__, val));
        }
    }
    else
    {
        CcspTraceError(("(%s:%d) SSL CTX is NULL, Data send failed\n", __FUNCTION__, __LINE__));
    }
#else
    if(send(conn_info->conn, payload, sizeof(payload_t), 0)<0)
    {
        CcspTraceError(("%s %d - send failed failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
        return -1;
    }
#endif
    return -1;
}

int close_remote_connection(connection_info_t* conn_info)
{
    if (conn_info->enc.ssl != NULL) {
        SSL_free(conn_info->enc.ssl);
    }
    close(conn_info->conn);
    if (conn_info->enc.ctx != NULL) {
        SSL_CTX_free(conn_info->enc.ctx);
    }
    CcspTraceInfo(("%s %d - socket closed\n", __FUNCTION__, __LINE__));
    return 1;
}

