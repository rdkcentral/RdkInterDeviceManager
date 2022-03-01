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

#ifndef _IDM_IPC_SERVER_H_
#define _IDM_IPC_SERVER_H_

#define MAX_CLIENTS 5
#define EOK (0)
#define SIZE 512
#define PORT 8888

typedef struct {
    int master_sock_fd;
    int client_fd[MAX_CLIENTS];
    int server_init_ok;
    pthread_t handler_thread;
    pthread_t receive_thread;
    pthread_mutex_t server_fd_lock;
} idm_server_sock_t;

int idm_server_sock_init(idm_server_sock_t *fd_data);
int idm_server_sock_delete(idm_server_sock_t *fd_data);
void idm_server_remote_send_request_response(char *ipcreq, int reqlen);

#endif
