#!/bin/bash
### BEGIN INIT INFO
# Provides: Palo Alto External Dynamic List Service
# Required-Start: 
# Required-Stop: 
# Should-Start: 
# Should-Stop: 
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Start up Palo Alto External Dynamic List Service
# Description: Start up Palo Alto External Dynamic List Service - Pandl.py
### END INIT INFO


ACTION=$1
SERVICEPATH=/home/paloalto/paloalto-edl-agent
SERVICE=panedl.py
PYTHON=$( which python )
USER='paloalto'
lockfile=/var/lock/$SERVICE


if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

function restart() {
  stop
  start
}

function stop() {
  status
  RETVAL=$?
  if [ $RETVAL -eq 0 ];then
    echo -n $"Shutting down $SERVICE: "
    PID=$( ps -ef | grep $SERVICE | grep -v grep | awk '{ print $2 }' )
    kill $PID
    echo
  fi
}

function start() {

  status
  RETVAL=$?
  if [ $RETVAL -ne 0 ];then
    echo -n $"Starting $SERVICE: "
    cd $SERVICEPATH
    su -s "/bin/bash" -c "$PYTHON $SERVICE &" $USER
    RETVAL=$?
    echo
  fi

}

function status() {

  PID=$( ps -ef | grep $SERVICE | grep -v grep | awk '{ print $2 }' )
  if [ $PID ];then
    kill -0 $PID
    RETVAL=$?
    if [ $RETVAL -eq 0 ];then
      echo "Service $SERVICE is running ***"
      return $RETVAL
    else
      echo "Service $SERVICE is stopped"
      return $RETVAL
    fi
  else
    echo "Service $SERVICE is stopped"
    return 1
 fi
  
}

function execute() {
  case "$ACTION" in
    start)
      start
      ;;
    stop)
      stop
      ;;
    status)
      status
      ;;
    restart)
      restart
      ;;
    *)
      echo "Usage: $0 {start|stop|status|restart}"
      exit 1
  esac
}

execute
