#! /bin/sh

#Script to restart IDM if remote coneection has broken

#Check file /tmp/idm_restart_attempts.

#attempt=never_attempted -> Never ever restarted. Good IDM connection between xb<->xle
#attempt=0 -> There was connection issue , but restarted and connection got established
#attempt=1 -> Restarted once. But still connection didn't establish
#attempt=2 -> Restarted twice , but connection didn't establish
#attempt=3 -> 3 times restarted , but connection didn't establish
#attempt=4 -> 4 times restarted , but connection didn't establish
#attempt=5 -> 5 times restarted , but connection didn't establish

RESTART_FILE=/tmp/idm_restart_attempts
MAX_ATTEMPTS=5
UPNP_FILE=/tmp/idm_upnp_not_operational
#This function will check number of restart attempts. If it exceeds 5, no further restart is done

function check_and_update_attempts()
{
    if [ ! -f  "$RESTART_FILE" ]; then
        touch "$RESTART_FILE"
        echo attempt=1 > $RESTART_FILE
        NUM_ATTEMPTS=1
        return
    fi

    attempt=$(grep "attempt=never_attempted" $RESTART_FILE)
    if [ -n "$attempt" ]; then
        sed -i 's/attempt=.*/attempt=1 /g' $RESTART_FILE
        NUM_ATTEMPTS=1
        return
    fi

    attempt=$(grep attempt $RESTART_FILE)

    if [ -z "$attempt" ]; then
        echo attempt=1 >> $RESTART_FILE
        NUM_ATTEMPTS=1
    else
        num=$(echo "$attempt" | cut -d "=" -f2)
        NUM_ATTEMPTS=$num
        if [ "$num" -lt "$MAX_ATTEMPTS" ]; then
            ((num=num+1))
            sed -i "s/attempt=.*/attempt=$num /g" $RESTART_FILE
        fi
    fi
}

#indicates this script executed
if [ ! -f  "$RESTART_FILE" ]; then
    touch $RESTART_FILE
fi

if [ -f "$UPNP_FILE" ]; then
    rm -f "$UPNP_FILE"
    systemctl restart RdkInterDeviceManager
    exit 0
fi

MODE=$(dmcli eRT getv Device.X_RDKCENTRAL-COM_DeviceControl.DeviceNetworkingMode | grep value: | awk -F: '{print $3}' | tr -d ' ')

if [ -z "$MODE" ]; then
    exit 0
fi

#If mesh interface does not have IP, exit from recovery

if [ "$MODE" = "0" ]; then
    MESH_IP=$(ip a l br403 | awk '/inet/ {print $2}'| grep /24)
    if [ -z "$MESH_IP" ]; then
        exit 0
    fi
fi

if [ "$MODE" = "1" ]; then
    MESH_IP=$(ip a l br-home | awk '/inet/ {print $2}'| grep /24)
    if [ -z "$MESH_IP" ]; then
        exit 0
    fi
fi

CONN_IF_PID=$(ps | grep Device.X_RDK_Connection.Interface | grep -v grep | awk '{print $1}')

if [ -n "$CONN_IF_PID" ]; then
    kill -9 $CONN_IF_PID
fi


INTERFACE=$(dmcli eRT getv Device.X_RDK_Connection.Interface | grep value: | awk -F: '{print $3}' | tr -d ' ')

if [ "$INTERFACE" != "br-home" ] &&  [ "$INTERFACE" != "br403" ]; then
    exit 0
fi

MODEL=$(deviceinfo.sh -mo | tr -d '\r\n')

if [ "$MODEL" == "WNXL11BWL" ] && [ "$MODE" == "0" ]; then
    exit 0
fi

ADDRESS=$(ip -f inet addr show "$INTERFACE" | awk '/inet / {print $2}')

if [ -z "$ADDRESS" ]; then
    exit 0
fi

ACCOUNT_ID=$(dmcli eRT getv Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AccountInfo.AccountID | grep value: | awk -F: '{print $3}' | tr -d ' ')

if [ "$ACCOUNT_ID" = "Unknown" ]; then
    REASON_ACCOUNT=$(grep "reason=invalid_account_id" $RESTART_FILE)
    if [ -z "$REASON_ACCOUNT" ]; then
        echo "reason=invalid_account_id" >> $RESTART_FILE
    fi
    exit 0
else
    sed -i '/reason=invalid_account_id/d' $RESTART_FILE
fi

#At this point mesh is up. Check if the connection was established initially by IDM

if [ ! -f "/tmp/idm_established" ]; then
    REASON_ESTA=$(grep "reason=never_established" $RESTART_FILE)
    if [ -z "$REASON_ESTA" ]; then
        echo "reason=never_established" >> $RESTART_FILE
    fi
    exit 0
else
    sed -i '/reason=never_established/d' $RESTART_FILE
fi

CONN_IF_PID=$(ps | grep Device.X_RDK_Remote.Device.2.Status | grep -v grep | awk '{print $1}')

if [ -n "$CONN_IF_PID" ]; then
    kill -9 $CONN_IF_PID
fi

#idm was established initially. Now monitor the connection
value=$(dmcli eRT getv Device.X_RDK_Remote.Device.2.Status | grep value: | awk -F: '{print $3}'| tr -d ' ') 
if [ "$value" != "3" ]; then
    check_and_update_attempts
    if [ "$NUM_ATTEMPTS" -ge "$MAX_ATTEMPTS" ]; then
        exit 0
    fi
    systemctl restart RdkInterDeviceManager
else
    attempt=$(grep "attempt=never_attempted" $RESTART_FILE)
    if [ -z "$attempt" ]; then
        attempt=$(grep attempt $RESTART_FILE)
        if [ -n "$attempt" ]; then
            #previous restart happenend. Now established
            sed -i 's/attempt=.*/attempt=0 /g' $RESTART_FILE
        else
            #Never ever restarted. Good connection
            echo attempt=never_attempted >> $RESTART_FILE
        fi
    fi
    exit 0
fi

while true
do
    #check the status until 3 minutes
    sleep 60

    CONN_IF_PID=$(ps | grep Device.X_RDK_Remote.Device.2.Status | grep -v grep | awk '{print $1}')

    if [ -n "$CONN_IF_PID" ]; then
        kill -9 $CONN_IF_PID
    fi

    value=$(dmcli eRT getv Device.X_RDK_Remote.Device.2.Status | grep value: | awk -F: '{print $3}'| tr -d ' ') 
    if [ "$value" = "3" ]; then
        #IDM was restarted forcefully and connection got established. clear attempt
        sed -i 's/attempt=.*/attempt=0 /g' $RESTART_FILE
	break
    fi
    ((iter=iter+1))
    if [ $iter -ge 3 ]; then
        #even if status takes more than 3 minutes to establish, on next attempt status will be checked
        break
    fi
done

