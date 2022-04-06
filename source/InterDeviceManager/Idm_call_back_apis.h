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

#ifndef _IDM_CB_H_
#define _IDM_CB_H_

#include "Idm_rbus.h"

ANSC_STATUS IDMMgr_Start_Device_Discovery();
int discovery_cb(device_info_t* Device, uint discovery_status, uint authentication_status );
int connection_cb(device_info_t* Device, connection_info_t* conn_info, uint encryption_status);
int rcv_message_cb( connection_info_t* conn_info, char *payload);
/*dummy function */
int start_discovery(discovery_config_t* discoveryConf, int (*discovery_cb)(device_info_t* Device, uint discovery_status, uint authentication_status))
{
}
int open_remote_connection(connection_config_t* connectionConf, int (*connection_cb)(device_info_t* Device, connection_info_t* conn_info, uint encryption_status), int (*rcv_message_cb)( connection_info_t* conn_info, char *payload)) 
{
}

int send_remote_message(connection_info_t* conn_info, char *payload)
{
}

int close_remote_connection(connection_info_t* conn_info)
{
}

#endif
