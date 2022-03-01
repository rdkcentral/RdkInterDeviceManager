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
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h> // for system()
#include "pthread.h"
#include "idm_ipc_client.h"
#include "inter_device_manager_internal.h"

int client_sockfd;

/*
 * Utility fucntion to fetch commad results
 */
static int syscmd(char *cmd, char *retBuf, int retBufSize)
{
    FILE *f;
    char *ptr = retBuf;
    int bufSize = retBufSize, bufbytes = 0, readbytes = 0;

    if ((f = popen(cmd, "r")) == NULL) {
        return -1;
    }

    while (!feof(f))
    {
        *ptr = 0;
        if (bufSize >= 128) {
            bufbytes = 128;
        } else {
            bufbytes = bufSize - 1;
        }

        fgets(ptr, bufbytes, f);
        readbytes = strlen(ptr);
        if ( readbytes == 0)
            break;
        bufSize -= readbytes;
        ptr += readbytes;
    }
    pclose(f);
    retBuf[retBufSize - 1] = 0;

    return 0;
}

/*
 * Send handler to be invoked by interested parties(components) to the other end IDM gateway
 */
void idm_client_remote_send_request_response(char *ipcdata, int size)
{
     char buff[MAX], retbuf[MAX];

     if (ipcdata != NULL) 
        strncpy(buff, ipcdata, size);

     /* For now the 'ipcdata' is a command sent by idm server to client.
      * The 'ipcdata' to be executed and the results are sent back to the server.
      * If a client want to know the status of the server, implemet the logic here.
      */
     syscmd(buff, retbuf, sizeof(retbuf));

     int rc = send(client_sockfd, retbuf, sizeof(retbuf), 0);

     if(rc < 0)
     {
        CcspTraceInfo(("\nSending data to server failed\n"));
     } else {
	CcspTraceInfo(("\nData sent to server in other end successfully!\n"));
     }
}

/*
 * Client handler thread to initiate connection with other end
 */
static void* idm_client_sock_handler(void *arg)
{
	struct sockaddr_in servaddr, cli;
        FILE *fPtr = NULL;
        char idmservip[20] = "192.168.0.1"; //To-Do
        char buff[MAX];

	if (client_sockfd != 0) {
	  CcspTraceInfo(("\nIDM Client socket already running No need to start again !!\n"));
        }

	client_sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (client_sockfd == -1)
	{
		CcspTraceInfo(("IDM Client socket creation failed...\n"));
		return NULL;
	}
	else
		CcspTraceInfo(("IDM Client Socket successfully created..\n"));

	bzero(&servaddr, sizeof(servaddr));

	servaddr.sin_family = AF_INET;

	//To-Do : For Now the IP address of the server is Hardcoded
        fPtr = fopen("/tmp/idmip.txt", "r") ;
	if ( fPtr == NULL )
        {
             CcspTraceInfo(("\nidmip.txt file failed to open.\n"));
        }
        else
        {
            while(fgets(idmservip, 20, fPtr) != NULL)
            {
                CcspTraceInfo(("\n IDM Server IP to communicate = %s\n",idmservip));
            }
            fclose(fPtr) ;
        }

	servaddr.sin_addr.s_addr = inet_addr(idmservip);
	servaddr.sin_port = htons(PORT);

	while (1)
	{
	      // Wait indefinitely untill other end idm server accepts the connection
	      if (connect(client_sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0)
	      {
		      sleep(1);
	      }
	      else {
		CcspTraceInfo(("IDM Client connected to the IDM server..\n"));
		break;
	      }
	}

        // Now the connection is established, keep waiting for data from server in recev
	while(1)
        {
	     memset(buff, 0, sizeof(buff));
	     CcspTraceInfo(("\n\nWaiting to receive data from Server : %s\n\n", buff));
             if (recv(client_sockfd, buff, sizeof(buff), 0) == -1)
             {
                 continue;
             }
             CcspTraceInfo(("\nReceived data request from Server : %s\n", buff));
             idm_client_remote_send_request_response(buff, sizeof(buff));
        }
    return NULL;
}

/*
 * Functiom to be called from interested parties to start the client
 */
void idm_start_client()
{
    pthread_attr_t attr;
    int thread_id = 0;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread_id, &attr, idm_client_sock_handler, NULL) != 0)
    {
       CcspTraceInfo(("IDM Client thread creation failed\n"));
    } else {
       CcspTraceInfo(("IDM Client started successfully!\n"));
    }
}

