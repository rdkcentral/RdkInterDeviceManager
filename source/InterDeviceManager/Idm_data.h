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

#ifndef _IDM_DATA_H_
#define _IDM_DATA_H_

#include "Idm_rbus.h"

typedef struct _WANMGR_CONFIG_DATA_
{
    PIDM_DML_INFO           pidmDmlInfo;
    pthread_mutex_t         mDataMutex;
} IDMMGR_CONFIG_DATA;

PIDM_DML_INFO IdmMgr_GetConfigData_locked(void);

void IdmMgrDml_GetConfigData_release(PIDM_DML_INFO pidmDmlInfo);

void IdmMgr_SetConfigData_Default();

ANSC_STATUS IdmMgr_Data_Init(void);

#endif
