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

#include <net/if.h>
#include <sys/ioctl.h>
#include "Idm_heartbeat.h"

#define DM_REMOTE_DEVICE_TABLE "Device.X_RDK_Remote.Device"

extern PIDM_DML_INFO pidmDmlInfo;
extern IDM_DML_LINK_LIST sidmDmlListInfo;
extern rbusHandle_t        rbusHandle;

ANSC_STATUS IDMMgr_UpdateDeviceList(char *mac, char *ip)
{
    int entryFount = 0;
    ANSC_STATUS returnStatus   =  ANSC_STATUS_SUCCESS;
    IDM_REMOTE_DEVICE_LINK_INFO *temp = sidmDmlListInfo.pListHead;

    while(temp!=NULL)
    {
        if(strcmp(temp->stRemoteDeviceInfo.MAC, mac) == 0)
        {
            CcspTraceInfo(("Entry found %s  \n",temp->stRemoteDeviceInfo.MAC));
            entryFount = 1;
            temp->stRemoteDeviceInfo.Last_update = time(0);
            temp->stRemoteDeviceInfo.Status = DEVICE_DETECTED;
            break;
        }
        temp=temp->next;
    }

    if(!entryFount)
    {
        CcspTraceInfo((" ADD new entry\n"));
        IDM_REMOTE_DEVICE_LINK_INFO *newNode = NULL;
        newNode = (IDM_REMOTE_DEVICE_LINK_INFO*)AnscAllocateMemory(sizeof(IDM_REMOTE_DEVICE_LINK_INFO));

        if( newNode == NULL )
        {
            return  ANSC_STATUS_FAILURE;
        }
        newNode->stRemoteDeviceInfo.Status = DEVICE_DETECTED;
        newNode->stRemoteDeviceInfo.Index = pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries;
        newNode->stRemoteDeviceInfo.Index++;
        strncpy(newNode->stRemoteDeviceInfo.MAC, mac, 17);
        strncpy(newNode->stRemoteDeviceInfo.IPv4, ip, 16);
        newNode->stRemoteDeviceInfo.Last_update = time(0);


        returnStatus = addDevice(newNode, &sidmDmlListInfo );

        if(returnStatus == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s %d - new Device entry %d added\n", __FUNCTION__, __LINE__, newNode->stRemoteDeviceInfo.Index ));
            pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries++;
        }
        // add row for table
        rbusTable_registerRow(rbusHandle, DM_REMOTE_DEVICE_TABLE, NULL, pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries);

    }
    return  returnStatus;
}


ANSC_STATUS IDMMgr_UpdateDeviceStatus()
{

    IDM_REMOTE_DEVICE_LINK_INFO *temp = sidmDmlListInfo.pListHead->next;

    while(temp!=NULL)
    {
        time_t current_time = time(0);
        if(difftime(current_time, temp->stRemoteDeviceInfo.Last_update) > 30)
        {
            temp->stRemoteDeviceInfo.Status = DEVICE_NOT_DETECTED;
        }
        temp=temp->next;
    }
    return ANSC_STATUS_SUCCESS;
}

void IDMMgr_print_status()
{

    IDM_REMOTE_DEVICE_LINK_INFO *temp = sidmDmlListInfo.pListHead;
    while(temp!=NULL)
    {
        CcspTraceInfo((" %s %d index %d MAC :%s , IPv4 : %s Status : %d \n",__FUNCTION__, __LINE__, temp->stRemoteDeviceInfo.Index, temp->stRemoteDeviceInfo.MAC,temp->stRemoteDeviceInfo.IPv4, temp->stRemoteDeviceInfo.Status));
        temp=temp->next;
    }
}

int IDMMgr_create_v4_client_socket()
{
    int     socket_client = -1;
    int     optval = 1;

    if ((socket_client = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("echo reply socket creation V4 failed : %s", strerror(errno));
        return -1;
    }

    if( setsockopt(socket_client, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) )
    {
        printf("echo reply socket V4 SO_REUSEADDR flag set failed : %s", strerror(errno));
        close(socket_client);
        return -1;
    }
    if(setsockopt(socket_client,SOL_SOCKET,SO_BROADCAST,&optval,sizeof(optval)) < 0)
    {
        printf("echo reply socket V4 SO_BROADCAST flag set failed : %s", strerror(errno));
        close(socket_client);
        return -1;
    }
    return socket_client;
}

int IDMMgr_create_v4_server_socket()
{
    int      socket_server = -1;
    int     optval;
    struct  sockaddr_in serveraddr;
    struct  timeval timeout;
    /* create reply socket always */
    if (( socket_server = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        CcspTraceInfo(("echo reply socket creation V4 failed : %s", strerror(errno)));
        return -1;
    }
    optval = 1;
    if( setsockopt( socket_server, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) )
    {
        CcspTraceInfo(("echo reply socket V4 SO_REUSEADDR flag set failed : %s", strerror(errno)));
        close( socket_server);
        return -1;
    }
    if(setsockopt(socket_server,SOL_SOCKET,SO_BROADCAST,&optval,sizeof(optval)) < 0)
    {
        printf("echo reply socket V4 SO_BROADCAST flag set failed : %s", strerror(errno));
        close(socket_server);
        return -1;
    }
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (setsockopt( socket_server, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        CcspTraceInfo(("setsockopt failed for timeout : %s", strerror(errno)));
        close( socket_server);
        return -1;
    }

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((uint16_t)3785);
    if (bind( socket_server, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
    {
        CcspTraceInfo(("v4 socket bind failed : %s", strerror(errno)));
        close( socket_server);
        return -1;
    }

    CcspTraceInfo(("[%s:%d] Created ECHO Reply V4 socket : %d",__FUNCTION__, __LINE__,  socket_server));
    return  socket_server;
}

static void* IDMMgr_Heart_Beat_thread(void *arg )
{
    int     socket_server = -1;
    int     socket_client = -1;
    int     ret;
    struct  sockaddr_in srcAddr;
    struct  sockaddr_in Recv_addr;
    socklen_t sendsize = 0;
    struct  timeval timeout;
    fd_set  r_fds;
    uint8_t recvBuf[512];
    time_t  last_HB_sent_time;
    struct  ifreq ifr;
    unsigned char serverInterfaceMac[20];
    char hello[64] = {0};

    pthread_detach(pthread_self());

    socket_server = IDMMgr_create_v4_server_socket();
    socket_client = IDMMgr_create_v4_client_socket();

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, "brlan0");

    /* Wait for interface to come up */
    ioctl(socket_server, SIOCGIFFLAGS, &ifr);
    while(!((ifr.ifr_flags & ( IFF_UP | IFF_BROADCAST )) == ( IFF_UP | IFF_BROADCAST )))
    {
        ioctl(socket_server, SIOCGIFFLAGS, &ifr);
        CcspTraceInfo(("[%s: %d] Wait for interface to come up\n", __FUNCTION__, __LINE__));
        sleep(2);
    }


    /* get Interface MAC */
    ioctl( socket_server, SIOCGIFHWADDR, &ifr);
    const unsigned char* mac=(unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(serverInterfaceMac,"%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    CcspTraceInfo(("\n[%s: %d] %s mac : %s \n", __FUNCTION__, __LINE__, ifr.ifr_name, serverInterfaceMac));

    /* get Interface Broadcast address */
    if(ioctl(socket_server, SIOCGIFBRDADDR, &ifr) != 0)
    {
        printf("Could not find interface named %s", ifr.ifr_name);
    }
    struct sockaddr_in *addr = (struct sockaddr_in *) &ifr.ifr_broadaddr;

    /* Update Receive address */
    Recv_addr.sin_family       = AF_INET;
    Recv_addr.sin_port         = htons(3785);
    Recv_addr.sin_addr.s_addr = addr->sin_addr.s_addr;

    CcspTraceInfo(("\n[%s: %d] %s Broadcast address mac : %s \n", __FUNCTION__, __LINE__, ifr.ifr_name ,inet_ntoa(addr->sin_addr)));
    /*send first hello message */
    sprintf(hello, "Hello from %s", serverInterfaceMac);
    if(socket_client != -1)
    {
        sendto( socket_client, (const char *)hello, strlen(hello),
                MSG_CONFIRM, (const struct sockaddr *) &Recv_addr,
                sizeof(Recv_addr));
        last_HB_sent_time = time(0);
    }

    for (;( socket_server != -1) && ( socket_client != -1);)
    {
        memset(recvBuf, 0, sizeof(recvBuf));
        FD_ZERO(&r_fds);
        FD_SET( socket_server, &r_fds);
        timeout.tv_sec = 1; // 1 sec wakeup
        timeout.tv_usec = 0;
        while ( (ret = select( socket_server + 1, &r_fds, NULL, NULL, &timeout)) == -1 && errno == EINTR)
            continue;
        if (ret < 0)
        {
            CcspTraceInfo(("select failed with errno = %s", strerror(errno)));
            perror("IHC ERROR: during select ");
            pthread_exit(NULL);
        }

        if (FD_ISSET( socket_server, &r_fds))
        {
            //CcspTraceInfo(("[%s: %d] incoming data V4 socket\n", __FUNCTION__, __LINE__));
            if (recvfrom( socket_server, recvBuf, sizeof(recvBuf), 0, (struct sockaddr *)&srcAddr, &sendsize) < 0)
            {
                CcspTraceInfo(("echo v4 reply recvfrom failed: %s\n", strerror(errno)));
            }
            else
            {
                if(!strncmp("Hello from ",recvBuf, strlen("Hello from ")))
                {
                    char clientIP[20] = {0};
                    char clientMac[20] = {0};

                    snprintf(clientIP,sizeof(clientIP),"%s",inet_ntoa(srcAddr.sin_addr));
                    snprintf(clientMac,sizeof(clientMac),"%s",(recvBuf+strlen("Hello from ")));
                    if(strcmp(clientMac, serverInterfaceMac))
                    {
                        CcspTraceInfo((" server : msg => %s , client ip => %s, port => %d  \n", recvBuf, clientIP, (int) ntohs(srcAddr.sin_port)));
                        IDMMgr_UpdateDeviceList(clientMac,clientIP);
                    }
                }
            }
        }

        /*Update Device status */
        IDMMgr_UpdateDeviceStatus();

        /*Check time interval to send hello */
        time_t current_time = time(0);
        if(difftime(current_time, last_HB_sent_time) > 10)
        {
            /*Broadcast Hello message */
            last_HB_sent_time = time(0);
            sendto( socket_client, (const char *)hello, strlen(hello),
                    MSG_CONFIRM, (const struct sockaddr *) &Recv_addr,
                    sizeof(Recv_addr));
            //IDMMgr_print_status();
        }

    }
    CcspTraceInfo((" Exit %s  \n", __FUNCTION__));
    pthread_exit(NULL);
}

ANSC_STATUS IDMMgr_Start_HeartBeat_Thread()
{

    pthread_t                HBB_thread;
    int                      iErrorCode     = 0;

    iErrorCode = pthread_create( &HBB_thread, NULL, &IDMMgr_Heart_Beat_thread, NULL );
    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start Heart_Beat  Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        CcspTraceInfo(("%s %d - WanManager Heart_Beat Thread Started Successfully\n", __FUNCTION__, __LINE__ ));
    }

    return ANSC_STATUS_SUCCESS;
}
