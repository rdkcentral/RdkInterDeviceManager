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

#define IDM_DEVICE_TCP_PORT 4444 //TODO: port no TBD
#define MAX_TCP_CLIENTS 30

bool TCP_server_started = false;

typedef (*callback_recv)( connection_info_t* conn_info, void *payload);

typedef struct tcp_server_threadargs
{
    callback_recv cb;
    int port;
} TcpServerThreadArgs;


void tcp_server_thread(void *arg)
{
    struct sockaddr_in servaddr;
    int master_sock_fd = -1;
    int rc = 0, sd = 0, i;
    fd_set rset;
    int max_fd = 0;
    int c_fd = 0;
    int client_socket[MAX_TCP_CLIENTS];
    //char buffer[1025];  //data buffer of 1K

    payload_t buffer;

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

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(IDM_DEVICE_TCP_PORT);

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
                break;
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
            if(c_fd !=0)
            {
                //close(c_fd);
                CcspTraceInfo(("\nNo space left = %d\n", c_fd));
            }
        }

        //else its some IO operation on some other socket
        for (i = 0; i < MAX_TCP_CLIENTS; i++)
        {
            sd = client_socket[i];

            if (FD_ISSET( sd , &rset))
            {
                //Check if it was for closing , and also read the
                //incoming message
                if (read( sd , (void *)&buffer, sizeof(payload_t)) == 0)
                {
                    //Somebody disconnected
                    //Close the socket and mark as 0 in list for reuse
                    close( sd );
                    client_socket[i] = 0;
                }
                //Echo back the message that came in
                else
                {
                    connection_info_t client_info;
                    client_info.conn = sd;
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
    connection_cb(connectionConf->device, &conn_info, 1);
    return 0;
}

int send_remote_message(connection_info_t* conn_info,void *payload)
{
    if(send(conn_info->conn, payload, sizeof(payload_t), 0)<0)
    {
        CcspTraceError(("%s %d - send failed failed : %s\n",  __FUNCTION__, __LINE__, strerror(errno)));
        return -1;
    }
    return 0;
}

int close_remote_connection(connection_info_t* conn_info)
{
    close(conn_info->conn);
    CcspTraceInfo(("%s %d - socket closed\n", __FUNCTION__, __LINE__));
    return 1;
}

