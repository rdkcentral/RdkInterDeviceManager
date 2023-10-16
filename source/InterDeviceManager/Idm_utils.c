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
/*
 * Copyright 2021 RDK Management
 * Licensed under the Apache License, Version 2.0
 */

#include <net/if.h>
#include <sys/ioctl.h>
#include "Idm_rbus.h"
#include <ifaddrs.h>
#include <sysevent/sysevent.h>
#include <syscfg/syscfg.h>
#include <net/if_arp.h>
int sysevent_fd = -1;
token_t sysevent_token;

#define SYS_IP_ADDR                 "127.0.0.1"
#define IDM_SYSNAME_SND          "IDM"
#define SYSEVENT_OPEN_MAX_RETRIES   6
#define DM_REMOTE_DEVICE_FT_STATUS "Device.X_RDK_Remote.FileTransferStatus()"
#define INTERFACE_CHECK_TIME 2 // 2 seconds
#define INTERFACE_MAX_WAIT_TIME (60/INTERFACE_CHECK_TIME) // 1 minute

extern rbusHandle_t        rbusHandle;
extern char         g_Subsystem[32];
static IDM_DML_LINK_LIST sidmDmlListInfo;

int IsFileExists(char *file_name)
{
    struct stat file;

    return (stat(file_name, &file));
}

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
        if(0 == strcmp(RM_NUM_ENTRIES, event))
            return EV_UNSIGNEDINT;

        if(strstr(event, ".MAC") || strstr(event, ".IPv4") || strstr(event, ".IPv6") || 
                strstr(event, ".Capabilities") || strstr(event, ".ModelNumber") || strstr(event,".FileTransferStatus"))
            return EV_STRING;

        if(strstr(event, ".Status") || strstr(event, ".HelloInterval"))
            return EV_INTEGER;
    } else {
        CcspTraceInfo(("event is null\n"));
        return EV_UNKNOWN;
    }
    return EV_UNKNOWN;
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
    else if(strcmp(event, RM_NUM_ENTRIES) == 0)
        sidmRmSubStatus->idmRmDeviceNoofEntriesSubscribed = TRUE;
    else if(strncmp(event, DM_REMOTE_DEVICE_FT_STATUS, strlen(event)) == 0)
        sidmRmSubStatus->idmRmDeviceFTStatusSubscribed = TRUE;
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
    /* Input Validation */
    if( ( NULL == pParamName) || ( NULL == pReturnVal ) || ( 0 >= returnValLength ) )
    {
        CcspTraceError(("%s Invalid Input Parameters\n",__FUNCTION__));
        return CCSP_FAILURE;
    }
    rbusProperty_t prop = NULL;
    rbusObject_t outParams = NULL;
    rbusObject_t inParams = NULL;
    rbusValue_t value = NULL;
    char* propValue = NULL;

    rbusObject_Init(&inParams, NULL);
    rbusProperty_Init(&prop, pParamName, NULL) ;
    rbusObject_SetProperty(inParams,prop);
    rbusProperty_Release(prop);
    prop =NULL;

    rbusError_t rc = RBUS_ERROR_SUCCESS;
    rc = rbusMethod_Invoke(rbusHandle, "GetPSMRecordValue()", inParams, &outParams);
    if(RBUS_ERROR_SUCCESS != rc)
    {

        CcspTraceError(("%s failed for GetPSMRecordValue() with err: '%s'\n\r",__FUNCTION__, rbusError_ToString(rc)));
        return -1;
    }
    prop = rbusObject_GetProperties(outParams);
    if(prop)
    {
        value = rbusProperty_GetValue(prop);
        if(value)
        {
            propValue = rbusValue_ToString(value, NULL, 0);
            if (propValue)  {
               /* use propValue in what you need then free it */
               strncpy(pReturnVal, propValue, (returnValLength-1));
               free(propValue);
            }
        }
    }

    rbusObject_Release(inParams);
    rbusObject_Release(outParams);
    return CCSP_SUCCESS;
}

int IDM_RdkBus_SetParamValuesToDB( char *pParamName, char *pParamVal )
{
    /* Input Validation */
    if( ( NULL == pParamName) || ( NULL == pParamVal ) )
    {
        CcspTraceError(("%s Invalid Input Parameters\n",__FUNCTION__));
        return CCSP_FAILURE;
    }

    rbusValue_t value = NULL;
    rbusProperty_t prop = NULL;
    rbusObject_t inParams = NULL;
    rbusObject_t outParams = NULL;
    rbusError_t rc = RBUS_ERROR_SUCCESS;

    rbusObject_Init(&inParams, NULL);
    rbusValue_Init(&value);
    if(false == rbusValue_SetFromString(value, RBUS_STRING, pParamVal))
    {
        CcspTraceError(("%s:Invalid value '%s' for the parameter %s\n\r", __FUNCTION__, pParamVal, pParamName));
        rbusValue_Release(value);
        rbusObject_Release(inParams);
        return -1;
    }

    rbusProperty_Init(&prop, pParamName, value);
    rbusObject_SetProperty(inParams,prop);
    rbusValue_Release(value);
    rbusProperty_Release(prop);

    rc = rbusMethod_Invoke(rbusHandle, "SetPSMRecordValue()", inParams, &outParams);
    if(RBUS_ERROR_SUCCESS != rc)
    {

        CcspTraceError(("%s failed for SetPSMRecordValue() with err: '%s'\n\r",__FUNCTION__, rbusError_ToString(rc)));
        rbusObject_Release(inParams);
        return -1;
    }
    
    rbusObject_Release(inParams);
    rbusObject_Release(outParams);
    return CCSP_SUCCESS;
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
    char wan_mac[32] = {0};

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

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, pidmDmlInfo->stConnectionInfo.Interface, sizeof(ifr.ifr_name)-1);

    /*Local device info will be stored in first entry */
    IDM_REMOTE_DEVICE_LINK_INFO *localDevice = NULL;
    localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    if (localDevice)
    {
        CcspTraceInfo(("[%s: %d] Update Local Device Data. Iface(%s)\n", __FUNCTION__, __LINE__, pidmDmlInfo->stConnectionInfo.Interface));
        /* get Interface MAC */
        platform_hal_GetBaseMacAddress(wan_mac);
        strncpy(localDevice->stRemoteDeviceInfo.MAC, wan_mac, sizeof(localDevice->stRemoteDeviceInfo.MAC)-1);
        platform_hal_GetModelName(localDevice->stRemoteDeviceInfo.ModelNumber);
        strncpy(localDevice->stRemoteDeviceInfo.Capabilities, pidmDmlInfo->stConnectionInfo.Capabilities, sizeof(localDevice->stRemoteDeviceInfo.Capabilities)-1);
        localDevice->stRemoteDeviceInfo.HelloInterval = pidmDmlInfo->stConnectionInfo.HelloInterval;
    }

    localDevice = NULL;
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    pidmDmlInfo =NULL;

    /*Wait for interface to get valid IP */
    CcspTraceInfo(("[%s: %d] Wait for interface to get valid IP \n", __FUNCTION__, __LINE__));
    ifr.ifr_addr.sa_family = AF_INET;
    while(TRUE)
    {
        if(ioctl(fd, SIOCGIFADDR, &ifr) >= 0)
        {
            break;
        }
        pidmDmlInfo = IdmMgr_GetConfigData_locked();
        // set interface flag so that it will return ANSC_STATUS_DO_IT_AGAIN to get new interface details
        if(pidmDmlInfo)
        {
            if(pidmDmlInfo->stConnectionInfo.InterfaceChanged)
            {
                pidmDmlInfo->stConnectionInfo.InterfaceChanged = FALSE;
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
	        close(fd);
                return ANSC_STATUS_DO_IT_AGAIN;
            }
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        }
        sleep(2);
    }

    /* Wait for interface to come up */
    CcspTraceInfo(("[%s: %d] Wait for interface to come up\n", __FUNCTION__, __LINE__));
    while(TRUE)
    {
        ioctl(fd, SIOCGIFFLAGS, &ifr);
        if((ifr.ifr_flags & ( IFF_UP | IFF_BROADCAST )) == ( IFF_UP | IFF_BROADCAST ))
        {
            break;
        }

        pidmDmlInfo = IdmMgr_GetConfigData_locked();
        // set interface flag so that it will return ANSC_STATUS_DO_IT_AGAIN to get new interface details
        if(pidmDmlInfo)
        {
            if(pidmDmlInfo->stConnectionInfo.InterfaceChanged)
            {
                pidmDmlInfo->stConnectionInfo.InterfaceChanged = FALSE;
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
	        close(fd);
                return ANSC_STATUS_DO_IT_AGAIN;
            }
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            pidmDmlInfo =NULL;
        }
        sleep(2);
    }

    pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
	close(fd);
        return  ANSC_STATUS_FAILURE;
    }
    /*Local device info will be stored in first entry */
    localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    if (localDevice)
    {
        struct in_addr netMask, ip_addr;


        ioctl(fd, SIOCGIFHWADDR, &ifr);

        /* get Interface IPv4 */
        ifr.ifr_addr.sa_family = AF_INET;
        ioctl(fd, SIOCGIFADDR, &ifr);
        snprintf(localDevice->stRemoteDeviceInfo.IPv4, sizeof(localDevice->stRemoteDeviceInfo.IPv4), "%s",inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
        ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

        /* get IPv4 netmask */
        ioctl(fd, SIOCGIFNETMASK, &ifr);
        netMask.s_addr = ip_addr.s_addr & ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
        snprintf(pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList, sizeof(pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList), "%s/%u", inet_ntoa(netMask), cidrMask(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr));
        CcspTraceInfo(("[%s: %d] HelloIPv4SubnetList %s \n", __FUNCTION__, __LINE__,pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList));

        /* get Ipv6 address */
        struct ifaddrs *ifap, *ifa;

        getifaddrs (&ifap);
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && !strcmp(ifa->ifa_name, pidmDmlInfo->stConnectionInfo.Interface) && ifa->ifa_addr->sa_family==AF_INET6)
            {
                    struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa->ifa_addr;
                    inet_ntop(AF_INET6, &in6->sin6_addr, localDevice->stRemoteDeviceInfo.IPv6, sizeof(localDevice->stRemoteDeviceInfo.IPv6));
            }
        }
        freeifaddrs(ifap);


        CcspTraceInfo(("[%s: %d] Local device Info\nMAC :%s,\nIP: %s,\nIPv6: %s,\nModel: %s, \nCapabilities: %s \nHelloInterval %d msec\n", __FUNCTION__, __LINE__,
                    localDevice->stRemoteDeviceInfo.MAC,localDevice->stRemoteDeviceInfo.IPv4, localDevice->stRemoteDeviceInfo.IPv6, 
                    localDevice->stRemoteDeviceInfo.ModelNumber, localDevice->stRemoteDeviceInfo.Capabilities, localDevice->stRemoteDeviceInfo.HelloInterval));
    }
    else
    {
        CcspTraceInfo(("LocalDevice is NULL in %s:%d\n", __FUNCTION__, __LINE__));
    }

    close(fd);
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return ANSC_STATUS_SUCCESS;
}

// This API will check if interfcae has IP address and operational
// It will wait for interface to become up for a maximum wait time of 2 minutes
bool checkInterfaceStatus(char *interface_name)
{
    struct  ifreq ifr;
    int fd = -1;

    if(interface_name == NULL)
    {
        return FALSE;
    }

    if (( fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        return FALSE;
    }
    
    memset(&ifr, 0, sizeof(ifr));

    if(strlen(interface_name) > 0)
    {
        strncpy(ifr.ifr_name, interface_name, sizeof(ifr.ifr_name)-1 );
        ifr.ifr_addr.sa_family = AF_INET;
        // maximum wait time is 2 minute
        int wait_time = 0;
        while(wait_time < INTERFACE_MAX_WAIT_TIME)
        {
            if(ioctl(fd, SIOCGIFADDR, &ifr) >= 0)
            {
                // interface has IP address. Check if it is UP
                ioctl(fd, SIOCGIFFLAGS, &ifr);

                if((ifr.ifr_flags & ( IFF_UP | IFF_BROADCAST )) == ( IFF_UP | IFF_BROADCAST ))
                {
                    CcspTraceInfo(("%s:%d Interface %s is up\n", __FUNCTION__, __LINE__,interface_name));
                    close(fd);
                    return TRUE;
                }
            }
            sleep(INTERFACE_CHECK_TIME);
            wait_time++;
        }
        CcspTraceInfo(("%s:%d Wait time exceeded . %s is down\n", __FUNCTION__, __LINE__,interface_name));
    }
    close(fd);
    return FALSE;
}

int getARPMac(char *interface, char *ip_address, char *mac_address)
{

    int sock = 0;
    struct arpreq arpreq;
    struct sockaddr_in *sin = NULL;
    unsigned char *mac_data = NULL;

    if(!ip_address || !interface || !mac_address)
    {
        return -1;
    }

    memset(&arpreq, 0, sizeof(arpreq));

    sin = (struct sockaddr_in *) &arpreq.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr(ip_address);
    strncpy (arpreq.arp_dev, interface, sizeof(arpreq.arp_dev) - 1);
    
    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) 
    {
        CcspTraceInfo(("%s %d ARP socket creation failed\n",  __FUNCTION__, __LINE__));
        return -1;
    }

    // parse ARP cache to get MAC
    if (ioctl(sock, SIOCGARP, &arpreq) < 0) 
    {
        CcspTraceInfo(("%s %d ARP IOCTL failed\n", __FUNCTION__, __LINE__));
        close(sock);
        return -1;
    }

    mac_data = (unsigned char *) &arpreq.arp_ha.sa_data[0];

    if(mac_data)
    {
        snprintf(mac_address, MAC_ADDR_SIZE , "%02X:%02X:%02X:%02X:%02X:%02X", mac_data[0],mac_data[1], mac_data[2], mac_data[3], mac_data[4], mac_data[5]);
    

        CcspTraceInfo(("%s %d Mac address of client %s: %s\n", __FUNCTION__, __LINE__, ip_address, mac_address));
    }

    close(sock);

    return 1;
}

bool checkMacAddr(const char *mac)
{
    uint32_t bytes[6] = { 0 };

    if(mac == NULL)
    {
        CcspTraceInfo(("%s %d Mac address is NULL\n", __FUNCTION__, __LINE__));
        return FALSE;
    }

    if((strlen(mac) <= 0) || (strlen(mac) != 17)) 
    {
        CcspTraceInfo(("%s %d Mac address is empty or not in valid format\n", __FUNCTION__, __LINE__));
        return FALSE;
    }

    return (6 == sscanf(mac, "%02X:%02X:%02X:%02X:%02X:%02X"
            , &bytes[5]
            , &bytes[4]
            , &bytes[3]
            , &bytes[2]
            , &bytes[1]
            , &bytes[0]));
}
