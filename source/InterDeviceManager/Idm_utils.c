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
#include "Idm_rbus.h"

#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>

int sysevent_fd = -1;
token_t sysevent_token;

#define SYS_IP_ADDR                 "127.0.0.1"
#define IDM_SYSNAME_SND          "IDM"
#define SYSEVENT_OPEN_MAX_RETRIES   6
#define MESH_INTERFACE_STATUS     "mesh_wan_linkstatus"
#define MESH_INTERFACE_STATUS_UP  "up"


extern ANSC_HANDLE  bus_handle;
extern char         g_Subsystem[32];
static IDM_DML_LINK_LIST sidmDmlListInfo;

ANSC_STATUS IDM_SyseventInit()
{
    ANSC_STATUS ret = ANSC_STATUS_SUCCESS;
    bool send_fd_status = FALSE;
    int try = 0;

    /* Open sysevent descriptor to send messages */
    while(try < SYSEVENT_OPEN_MAX_RETRIES)
    {
       sysevent_fd =  sysevent_open(SYS_IP_ADDR, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, IDM_SYSNAME_SND, &sysevent_token);
       if(sysevent_fd >= 0)
       {
          send_fd_status = TRUE;
          break;
       }
       try++;
       usleep(50000);
    }
    if (send_fd_status == FALSE)
    {
        ret = ANSC_STATUS_FAILURE;
    }

    return ret;
}

void IDM_SyseventClose()
{
    if (0 <= sysevent_fd)
    {
        sysevent_close(sysevent_fd, sysevent_token);
    }

}

ANSC_STATUS addDevice(IDM_REMOTE_DEVICE_LINK_INFO *newNode)
{
    if(NULL == newNode)
        return ANSC_STATUS_FAILURE;

    IDM_REMOTE_DEVICE_LINK_INFO *tmp = NULL;
    IDM_REMOTE_DEVICE_LINK_INFO *head = sidmDmlListInfo.pListHead;

    if(head == NULL)
    {
        sidmDmlListInfo.pListHead = newNode;
        sidmDmlListInfo.pListTail = sidmDmlListInfo.pListHead;
        sidmDmlListInfo.pListHead->next = NULL;
        return ANSC_STATUS_SUCCESS;
    }
    
    IDM_REMOTE_DEVICE_LINK_INFO *tail = sidmDmlListInfo.pListTail;

    // we should have a tail node
    if(tail == NULL)
        return ANSC_STATUS_FAILURE;

    //update pidmDmlInfo->stRemoteInfo
    tail->next = newNode;
    tail->next->next = NULL;

    sidmDmlListInfo.pListTail = newNode;
    CcspTraceInfo(("%s %d - new Device has been added\n", __FUNCTION__, __LINE__));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS updateDeviceStatus(PIDM_DML_INFO pidmDmlInfo, uint32_t index, uint32_t newStatus)
{
    if(NULL == pidmDmlInfo)
        return ANSC_STATUS_FAILURE;

    IDM_REMOTE_DEVICE_LINK_INFO *head = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

    while(head != NULL)
    {
        if(head->stRemoteDeviceInfo.Index == index)
        {
            head->stRemoteDeviceInfo.Status = newStatus;
            CcspTraceInfo(("%s %d - Device %d status updated to %d\n", __FUNCTION__, __LINE__, index, newStatus ));
            return ANSC_STATUS_SUCCESS;
        }
        head=head->next;
    }
    CcspTraceInfo(("%s %d - Failed to update status for device %d\n", __FUNCTION__, __LINE__, index ));

    return ANSC_STATUS_FAILURE;
}

EVENT_DATA_TYPES getEventType(char *event)
{
    if(event != NULL)
    {
        if(strstr(event, ".MAC") || strstr(event, ".IPv4") || strstr(event, ".IPv6") || 
                strstr(event, ".Capabilities") || strstr(event, ".ModelNumber"))
            return EV_STRING;

        if(strstr(event, ".Status") || strstr(event, ".HelloInterval"))
            return EV_INTEGER;
    }
}

// Retun device node corresponding to index
//eg: Device.2.Status . 2 is the index. Get node for 2nd device
IDM_REMOTE_DEVICE_LINK_INFO* getRmDeviceNode(PIDM_DML_INFO pidmDmlInfo, uint32_t index)
{

    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }

    IDM_REMOTE_DEVICE_LINK_INFO *head = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

     while(head != NULL)
    {
        if(head->stRemoteDeviceInfo.Index == index)
        {
            
            return head;
        }
        head = head->next;
    }
    return NULL;
}

ANSC_STATUS updteSubscriptionStatus(char *event, IDM_RBUS_SUBS_STATUS *sidmRmSubStatus)
{

    if(event == NULL || sidmRmSubStatus == NULL)
        return ANSC_STATUS_FAILURE;   
 
    if(strstr(event, ".Status"))
        sidmRmSubStatus->idmRmStatusSubscribed = TRUE;
    else if(strstr(event, ".MAC"))
        sidmRmSubStatus->idmRmHelloIntervalSubscribed = TRUE;
    else if(strstr(event, ".IPv4"))
        sidmRmSubStatus->idmRmIPv4Subscribed = TRUE;
    else if(strstr(event, ".IPv6"))
        sidmRmSubStatus->idmRmIPv6Subscribed = TRUE;
    else if(strstr(event, ".Capabilities"))
        sidmRmSubStatus->idmRmCapSubscribed = TRUE;
    else if(strstr(event, ".HelloInterval"))
        sidmRmSubStatus->idmRmCapSubscribed = TRUE;
    else if(strstr(event, ".ModelNumber"))
        sidmRmSubStatus->idmRmModelNumSubscribed = TRUE;
    else if(strcmp(event, "Device.X_RDK_Remote.DeviceChange") == 0)
        sidmRmSubStatus->idmRmNewDeviceSubscribed = TRUE;
    else
    {
        CcspTraceInfo(("%s %d - Failed to update subscripton status for %s\n", __FUNCTION__, __LINE__, event));
        return ANSC_STATUS_FAILURE;    
    }

    CcspTraceInfo(("%s %d - Updatig subscription status for %s\n", __FUNCTION__, __LINE__, event));
    return ANSC_STATUS_SUCCESS;
}


int IDM_RdkBus_GetParamValuesFromDB( char *pParamName, char *pReturnVal, int returnValLength )
{
    int     retPsmGet     = CCSP_SUCCESS;
    CHAR   *param_value   = NULL, tmpOutput[256] = {0};
    /* Input Validation */
    if( ( NULL == pParamName) || ( NULL == pReturnVal ) || ( 0 >= returnValLength ) )
    {
        CcspTraceError(("%s Invalid Input Parameters\n",__FUNCTION__));
        return CCSP_FAILURE;
    }
    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, pParamName, NULL, &param_value);
    if (retPsmGet != CCSP_SUCCESS)
    {
        CcspTraceError(("%s Error %d reading %s\n", __FUNCTION__, retPsmGet, pParamName));
    }
    else
    {
        /* Copy DB Value */
        snprintf(pReturnVal, returnValLength, "%s", param_value);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(param_value);
    }
   return retPsmGet;
}

int IDM_RdkBus_SetParamValuesToDB( char *pParamName, char *pParamVal )
{
    int     retPsmSet  = CCSP_SUCCESS;
    /* Input Validation */
    if( ( NULL == pParamName) || ( NULL == pParamVal ) )
    {
        CcspTraceError(("%s Invalid Input Parameters\n",__FUNCTION__));
        return CCSP_FAILURE;
    }
    retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, pParamName, ccsp_string, pParamVal);
    if (retPsmSet != CCSP_SUCCESS)
    {
        CcspTraceError(("%s Error %d writing %s\n", __FUNCTION__, retPsmSet, pParamName));
    }
    return retPsmSet;
}

unsigned int cidrMask(unsigned int n) {
    unsigned int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}

ANSC_STATUS IDM_UpdateLocalDeviceData()
{
    struct  ifreq ifr;
    int      fd = -1;

    /* Wait for mesh */
    CcspTraceInfo(("[%s: %d] Wait for mesh to come up\n", __FUNCTION__, __LINE__));
    char meshStatus[32] = {0};

    do
    {
        /* sysevent get of mesh status */
        sysevent_get(sysevent_fd, sysevent_token, MESH_INTERFACE_STATUS, meshStatus, sizeof(meshStatus));
        sleep(2);

    } while(strcmp(meshStatus, MESH_INTERFACE_STATUS_UP) != 0);

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }



    if (( fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        CcspTraceInfo(("echo reply socket creation V4 failed : %s", strerror(errno)));
        return ANSC_STATUS_FAILURE;
    }

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, pidmDmlInfo->stConnectionInfo.Interface);

    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    /*Wait for interface to get valid IP */
    CcspTraceInfo(("[%s: %d] Wait for interface to get valid IP \n", __FUNCTION__, __LINE__));
    ifr.ifr_addr.sa_family = AF_INET;
    while(ioctl(fd, SIOCGIFADDR, &ifr) < 0)
    {
        sleep(2);
    }

    /* Wait for interface to come up */
    CcspTraceInfo(("[%s: %d] Wait for interface to come up\n", __FUNCTION__, __LINE__));
    ioctl(fd, SIOCGIFFLAGS, &ifr);
    while(!((ifr.ifr_flags & ( IFF_UP | IFF_BROADCAST )) == ( IFF_UP | IFF_BROADCAST )))
    {
        ioctl(fd, SIOCGIFFLAGS, &ifr);
        sleep(2);
    }

    pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }
    /*Local device info will be stored in first entry */
    IDM_REMOTE_DEVICE_LINK_INFO *localDevice = NULL;
    localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    if (localDevice)
    {
        struct in_addr netMask, ip_addr;

        /* get Interface MAC */
        platform_hal_GetBaseMacAddress(localDevice->stRemoteDeviceInfo.MAC);

        ioctl(fd, SIOCGIFHWADDR, &ifr);

        /* get Interface IPv4 */
        ifr.ifr_addr.sa_family = AF_INET;
        ioctl(fd, SIOCGIFADDR, &ifr);
        sprintf(localDevice->stRemoteDeviceInfo.IPv4,"%s",inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
        ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

        /* get IPv4 netmask */
        ioctl(fd, SIOCGIFNETMASK, &ifr);
        netMask.s_addr = ip_addr.s_addr & ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
        sprintf(pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList,"%s/%u", inet_ntoa(netMask), cidrMask(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr));
        CcspTraceInfo(("[%s: %d] HelloIPv4SubnetList %s \n", __FUNCTION__, __LINE__,pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList));

        //TODO: Update IPv6 address
        close(fd);


        platform_hal_GetModelName(localDevice->stRemoteDeviceInfo.ModelNumber);
        strcpy(localDevice->stRemoteDeviceInfo.Capabilities, pidmDmlInfo->stConnectionInfo.Capabilities);
        localDevice->stRemoteDeviceInfo.HelloInterval = pidmDmlInfo->stConnectionInfo.HelloInterval;

        CcspTraceInfo(("[%s: %d] MAC :%s, IP: %s, Model: %s, Capabilities: %s HelloInterval %d msec\n", __FUNCTION__, __LINE__,localDevice->stRemoteDeviceInfo.MAC,
                    localDevice->stRemoteDeviceInfo.IPv4, localDevice->stRemoteDeviceInfo.ModelNumber,localDevice->stRemoteDeviceInfo.Capabilities, localDevice->stRemoteDeviceInfo.HelloInterval));
    } 
    else
    {
        CcspTraceInfo(("LocalDevice is NULL in %s:%d\n", __FUNCTION__, __LINE__));
    }

    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return ANSC_STATUS_SUCCESS;
}
