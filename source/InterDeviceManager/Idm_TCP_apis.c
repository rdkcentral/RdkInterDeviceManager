/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
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
/*
 * Copyright [2014] [Cisco Systems, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     LICENSE-2.0" target="_blank" rel="nofollow">http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Idm_TCP_apis.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "safec_lib_common.h"
#define MAX_TCP_CLIENTS 30
#define SSL_CERTIFICATE "/tmp/idm_xpki_cert"
#define SSL_KEY         "/tmp/idm_xpki_key"

bool ssl_lib_init = false;
bool TCP_server_started = false;

typedef (*callback_recv)( connection_info_t* conn_info, void *payload);

typedef struct tcp_server_threadargs
{
    callback_recv cb;
    int port;
} TcpServerThreadArgs;

SSL_CTX* init_ctx(void)
{
    SSL_CTX *ctx = NULL;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_method());
    //SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    //SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
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
    CcspTraceInfo(("(%s:%d)Certificate & private key loaded successfully\n", __FUNCTION__, __LINE__));
    return 0;
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
    TcpServerThreadArgs *ta = arg;
    int port_no = ta->port;
    callback_recv rcv_cb = ta->cb;

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
    }
    if ((ctx = init_ctx()) == NULL) {
        CcspTraceError(("(%s:%d) SSL ctx creation failed!!\n", __FUNCTION__, __LINE__));
        return;
    }
    if (load_certificate(ctx) == -1) {
        CcspTraceError(("(%s:%d) Can't use certificate now!!\n", __FUNCTION__, __LINE__));
        return;
    }
#endif
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port_no);

    rc = bind(master_sock_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if(rc < 0)
    {
        CcspTraceInfo(("\nIDM Server socket bind failed\n"));
        return;
    }

    rc = listen(master_sock_fd, MAX_TCP_CLIENTS);

    if(rc < 0)
    {
        CcspTraceInfo(("\nIDM server socket listen failed\n"));
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
                if (SSL_accept(ssl[i]) <= 0) {
                    CcspTraceError(("(%s:%d)SSL handshake failed\n", __FUNCTION__, __LINE__));
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

    TcpServerThreadArgs ta = { rcv_message_cb,connectionConf->port};
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
    conn_info.enc.ctx = NULL;
    conn_info.enc.ssl = NULL;

    // Client encryption
    conn_info.enc.ssl = NULL;
    if (!ssl_lib_init) {
        ssl_lib_init = true;
        SSL_library_init();
    }
    if ((conn_info.enc.ctx = init_ctx()) == NULL) {
        CcspTraceError(("(%s:%d) SSL ctx creation failed!!\n", __FUNCTION__, __LINE__));
        return -1;
    }
    if ((conn_info.enc.ssl = SSL_new(conn_info.enc.ctx)) == NULL) {
        CcspTraceError(("(%s:%d) SSL session creation failed!!\n", __FUNCTION__, __LINE__));
        return -1;
    }
    SSL_set_fd(conn_info.enc.ssl, client_sockfd);
    if (SSL_connect(conn_info.enc.ssl) > 0) {
        CcspTraceInfo(("Encryption status is set to true"));
        enc_status = true;
    }
    else
    {
        CcspTraceInfo(("Encryption status is set to false"));
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

    Data = (payload_t*)payload;
    fptr = fopen(Data->param_name,"rb");
    CcspTraceInfo(("Inside %s:%d file name=%s\n",__FUNCTION__,__LINE__,Data->param_name));
    if(!fptr)
    {
        CcspTraceError(("%s:%d file not present\n",__FUNCTION__,__LINE__));
        return -1;
    }
    fseek (fptr, 0, SEEK_END);
    length = ftell (fptr);
    CcspTraceDebug(("length of the file=%zu\n",length));
    fseek (fptr, 0, SEEK_SET);
    buffer = (char*)malloc (256);
    memset(buffer,0,256);
    if(buffer){
        sprintf(buffer,"%zu",length);
        strncpy_s(Data->param_value,sizeof(Data->param_value),buffer,strlen(buffer));
#ifndef IDM_DEBUG
        if(conn_info->enc.ssl == NULL){
            CcspTraceError(("(%s:%d) SSL CTX is NULL, Data send failed\n", __FUNCTION__, __LINE__));
            return -1;
        }
        if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
        {
            free(buffer);
            buffer =(char*)malloc (length);
            fread (buffer, 1, length, fptr);
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
        if(send(conn_info->conn, Data, sizeof(payload_t), 0)<0){
            CcspTraceError(("%s %d - send failed failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
            return -1;
        }
        free(buffer);
        buffer =(char*)malloc (length);
        fread (buffer, 1, length, fptr);
        if((bytes = send(conn_info->conn, buffer,length,0))<=0){
            CcspTraceError(("file data is not transformed through send\n"));
        }
        CcspTraceDebug(("bytes written = %d and length=%d through send\n",bytes,(int)length));
#endif
    }
    if(buffer)
    {
        free(buffer);
    }
    fclose(fptr);
    return 0;
}

int sendFile_to_remote(connection_info_t* conn_info,void *payload,char* output_location)
{
    CcspTraceDebug(("Inside %s %d\n",__FUNCTION__,__LINE__));
    char* buffer;
    FILE* fptr;
    size_t length;
    payload_t *Data;
    int retry = 0,bytes = 0,push_start = 0,rc=-1,ind=-1;
    Data = (payload_t*)payload;
    fptr = fopen(Data->param_name,"rb");
    CcspTraceInfo(("Inside %s:%d file name=%s\n",__FUNCTION__,__LINE__,Data->param_name));
    if(!fptr)
    {
        CcspTraceError(("%s:%d file not present\n",__FUNCTION__,__LINE__));
        return -1;
    }
    fseek (fptr, 0, SEEK_END);
    length = ftell (fptr);
    CcspTraceDebug(("length of the file=%zu\n",length));
    fseek (fptr, 0, SEEK_SET);
    buffer = (char*)malloc (256);
    memset(buffer,0,256);
    if(buffer)
    {
        sprintf(buffer,"%zu",length);
        strncpy_s(Data->param_value,sizeof(Data->param_value),buffer,strlen(buffer));
        strcpy_s(Data->param_name,sizeof(Data->param_name),output_location);
        CcspTraceInfo(("%s:%d output file name = %s\n",__FUNCTION__,__LINE__,Data->param_name));
#ifndef IDM_DEBUG
        if (conn_info->enc.ctx != NULL && conn_info->enc.ssl != NULL)
        {
            if ((bytes = SSL_write(conn_info->enc.ssl, Data, sizeof(payload_t))) > 0)
            {
                push_start=1;
            }
            else
            {
                CcspTraceError(("%s:%d length and file data is not transformed\n",__FUNCTION__,__LINE__));
                return -1;
            }
        }
        else
        {
            CcspTraceError(("%s:%d ssl session is null\n",__FUNCTION__,__LINE__));
            return -1;
        }
#else
        if(send(conn_info->conn, Data,sizeof(payload_t), 0) > 0)
        {
            push_start=1;
        }
        else
        {
            CcspTraceError(("%s %d - send failed failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
            return -1;
        }
#endif
start:
        if(push_start == 1 && length > 0)
        {
            free(buffer);
            buffer =(char*)malloc(strlen("not found")+1);
#ifndef IDM_DEBUG
            bytes = SSL_read(conn_info->enc.ssl, buffer,strlen("not found"));
#else
            bytes = read( conn_info->conn , buffer, strlen("not found"));
#endif
            CcspTraceDebug(("%s:%d buffer=%s\n",__FUNCTION__,__LINE__,buffer));
            rc = strcmp_s("start",strlen("start"),buffer,&ind);
            ERR_CHK(rc);
            if((!ind) && (rc == EOK))
            {
                free(buffer);
                buffer =(char*)malloc(length);
                fread (buffer, 1, length, fptr);
#ifndef IDM_DEBUG
                if((bytes = SSL_write(conn_info->enc.ssl, buffer,length)) <= 0)
                {
                    CcspTraceError(("file data is not transformed\n"));
                }
#else
                if (( bytes = send(conn_info->conn,buffer,length,0) ) <= 0 )
                {
                    CcspTraceError(("file data is not transformed\n"));
                }
#endif
                CcspTraceDebug(("bytes written = %d and length=%d\n",bytes,(int)length));
            }
            else
            {
                rc = strcmp_s("not found",strlen("not found"),buffer,&ind);
                ERR_CHK(rc);
                if((!ind) && (rc == EOK))
                {
                    CcspTraceError(("not able to create destination file in the peer device\n"));
                    return -1;
                }
                CcspTraceInfo(("peer device does not given acknowledge so retry for 30 times\n"));
                if(retry < 30)
                {
                    retry++;
                    goto start;
                }
                else if(retry == 30)
                {
                    return -1;
                }
            }
        }
    }
    return 0;
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

