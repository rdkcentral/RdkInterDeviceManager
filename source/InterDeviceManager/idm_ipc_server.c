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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <arpa/inet.h>
#include "pthread.h"
#include "idm_ipc_server.h"
#include "inter_device_manager_internal.h"

static idm_server_sock_t idm_server_sock_data;

/*
 * This connection handler thread will keep waiting for new connections
 */
static void *idm_server_connection_handler(void *arg)
{

    idm_server_sock_t *fd_data = (idm_server_sock_t*) arg;
    int master_sock_fd = 0;
    int c_fd = 0;
    int max_fd = 0;
    int i = 0;
    int rc = 0;
    fd_set rset;
    char buf[SIZE];

    if(fd_data == NULL)
        return NULL;

    //Pick up the Master Fd
    master_sock_fd = fd_data->master_sock_fd;
    fd_data->server_init_ok = 1;

    while(1)
    {
        pthread_mutex_lock(&fd_data->server_fd_lock);

        FD_ZERO(&rset);
        FD_SET(master_sock_fd, &rset);
        max_fd = master_sock_fd;

        for(i=0; i < MAX_CLIENTS; i++)
	{
            c_fd = fd_data->client_fd[i];
            if(c_fd > 0) {
                FD_SET(c_fd, &rset);
                if(c_fd > max_fd) {
                    max_fd = c_fd;
                }
            }
        }
        //Release the lock before going to select
        pthread_mutex_unlock(&fd_data->server_fd_lock);
        //Wait Indefinitely for events to hit
        select( max_fd + 1 , &rset , NULL , NULL , NULL);

       	//Now we have a new connection from new client
        pthread_mutex_lock(&fd_data->server_fd_lock);
        //Check the Master Fd for any new connections
	if(FD_ISSET(master_sock_fd, &rset))
	{
            c_fd = accept(master_sock_fd, NULL, NULL);
	    if(c_fd < 0){
                perror("idm : AF_INET accept failed");
                break;
            }
	    CcspTraceInfo(("\nNew Client Connected Successfully with socket id  = %d\n", c_fd));
            //Save the new client FD in a vacant slot of client FD array
            for(i = 0; i< MAX_CLIENTS; i++)
	    {
                if(fd_data->client_fd[i] == 0)
		{
                    fd_data->client_fd[i] = c_fd;
                    c_fd = 0;
                    break;
                }
            }
            //No space left to hold the new connection, if you want increase MAX_CLIENTS
            if(c_fd !=0)
	    {
                close(c_fd);
            }
        }

       	//To handle connectiom close check all the client fd
        for(i = 0; i< MAX_CLIENTS; i++)
	{
            c_fd = fd_data->client_fd[i];
            if(FD_ISSET(c_fd, &rset))
	    {
                rc = recv(c_fd, buf, sizeof(buf), 0);
                //Socket closed
                if(rc == 0)
		{
                    close(c_fd);
                    fd_data->client_fd[i] = 0;
                }
            }
        }
        pthread_mutex_unlock(&fd_data->server_fd_lock);
    }
    return NULL;
}

/*
 * Send handler to be invoked by interested parties(components) to the other end IDM gateway
 */
void idm_server_remote_send_request_response(char *ipcdata, int reqlen)
{

    int rc;
    int i = 0;
    int c_fd = 0;
    char buf[SIZE];
    int buf_len = reqlen;

    if (ipcdata != NULL)
        strncpy(buf, ipcdata, buf_len);
    else
	return;

    //Check the slots to find out valid client connections
    for(i = 0; i  < MAX_CLIENTS; i++)
    {
        c_fd = idm_server_sock_data.client_fd[i];
        if(c_fd <= 0)
            continue;
        rc = send(c_fd, buf, buf_len, 0);
        if(rc < 0)
	{
            CcspTraceInfo(("\nRequest data send failed to client[%d]\n", c_fd));
	} else {
	    CcspTraceInfo(("\nRequest data sent to client[%d] : %s\n", c_fd, buf));
	}
    }
}

/*
 * This receive handler will block while expecting some data from connected clients sockets
 */
static void idm_server_sock_receive_data(void *arg)
{
    int i = 0;
    int c_fd = 0;
    char clibuff[SIZE];

    while (1)
    {
      pthread_mutex_lock(&idm_server_sock_data.server_fd_lock);
      for(i = 0; i< MAX_CLIENTS; i++)
      {
            c_fd = idm_server_sock_data.client_fd[i];
            if(c_fd > 0)
            {
                if (recv(c_fd, clibuff, sizeof(clibuff), 0) == -1)
                {
                        continue;
                }
                CcspTraceInfo(("\nReceived response from client socket : %d, Reply :", c_fd));
		CcspTraceInfo(("\n%s\n",clibuff));
            }
       }
       pthread_mutex_unlock(&idm_server_sock_data.server_fd_lock);
       sleep(2);
    }
}

/*
 * This function creates server socket, conection thread, receive thread handlers
 */
int idm_server_sock_init(idm_server_sock_t *fd_data)
{
    pthread_attr_t attr_handler;
    pthread_attr_t attr_receive;
    struct sockaddr_in servaddr;
    int fd = -1;
    int rc = 0;

    if(fd_data == NULL)
        return EINVAL;

    //Server already intialized, clean  all old data
    if(fd_data->server_init_ok)
    {
        idm_server_sock_delete(fd_data);
    }

    do
    {
        fd = socket(AF_INET, SOCK_STREAM, 0);

	if(fd < 0)
	{
            CcspTraceInfo(("\nIDM Server socket open failed\n"));
            rc = EINVAL;
            break;
        }

        servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(PORT);

        rc = bind(fd, (struct sockaddr *)&servaddr, sizeof(servaddr));

        if(rc < 0)
	{
            CcspTraceInfo(("\nIDM Server socket bind failed\n"));
            break;
        }

        rc = listen(fd, MAX_CLIENTS);

        if(rc < 0)
	{
            CcspTraceInfo(("\nIDM server socket listen failed\n"));
            break;
        }
        //Start creating connection thread
        pthread_attr_init(&attr_handler);
        pthread_attr_setdetachstate(&attr_handler, PTHREAD_CREATE_DETACHED);
        memset(fd_data, 0, sizeof(idm_server_sock_t));
        pthread_mutex_init(&fd_data->server_fd_lock, 0);
        //Update to master fd
        fd_data->master_sock_fd = fd;

        if (pthread_create((&fd_data->handler_thread), &attr_handler, idm_server_connection_handler, fd_data) != 0)
       	{
            rc = EINVAL;
            break;
        }
    } while(0);


    if(rc != 0)
    {
        if(fd != -1)
	{
            close(fd);
            fd_data->master_sock_fd = 0;
        }
    }
    //Start creating data receive thread on the clients fd
    pthread_attr_init(&attr_receive);
    pthread_attr_setdetachstate(&attr_receive, PTHREAD_CREATE_DETACHED);
    if(pthread_create(&fd_data->receive_thread, &attr_receive, idm_server_sock_receive_data, NULL) != 0)
    {
       CcspTraceInfo(("\nData receive thread creation failed...\n"));
    }
    return rc;
}

/*
 *This function closes all client connections and reset
 */
int idm_server_sock_delete(idm_server_sock_t *fd_data)
{
    int  i = 0;
    if(fd_data == NULL)
        return EINVAL;

    pthread_mutex_lock(&fd_data->server_fd_lock);

    if(fd_data->master_sock_fd  > 0)
    {
        close(fd_data->master_sock_fd);
        while(i < MAX_CLIENTS)
	{
            if(fd_data->client_fd[i] > 0)
	    {
                close(fd_data->client_fd[i]);
            }
            i++;
        }
    }
    //stop the server thread thats waiting for accept
    pthread_cancel(fd_data->handler_thread);
    fd_data->master_sock_fd = 0;
    fd_data->handler_thread = 0;
    fd_data->receive_thread = 0;
    fd_data->server_init_ok = 0;
    pthread_mutex_unlock(&fd_data->server_fd_lock);
    return 0;
}

/*
 * Functiom to be called from interested parties to start server
 */
int idm_start_server()
{
	int rc = 0;
	rc = idm_server_sock_init(&idm_server_sock_data);
	if (rc < 0)
	{
	   CcspTraceInfo(("\nIDM server socket opening failed!\n"));
	}

	CcspTraceInfo(("\nIDM server socket opened successfully!\n"));
	return rc;
}
