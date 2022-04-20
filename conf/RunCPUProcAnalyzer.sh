#!/bin/sh

source /etc/device.properties
source /etc/log_timestamp.sh

WANINTERFACE="erouter0"
PATTERN_FILE="/tmp/proc_pattern_file"

man_usage()
{
  echo "USAGE:   RunCPUProcAnalyzer.sh {start|stop} {args}"
}

# Get the MAC address of the machine
getMacAddressOnly()
{
     mac=`ifconfig $WANINTERFACE | grep HWaddr | cut -d " " -f7 | sed 's/://g'`
     echo $mac
}

if [ $# -lt 1 ]; then
   man_usage
   exit 1
fi

arg_val=$1
NeedUpload=$2
case $arg_val in
        start)
            if [ "$BOX_TYPE" = "XB3" ]; then
                 nice -n 19 /usr/bin/cpuprocanalyzer
            else
                 touch /tmp/PROC_ANALYZER_ENABLE
            fi
            exit 0
        ;;
        stop)
            if [ "$NeedUpload" -eq 1 ]; then
                 MAC=`getMacAddressOnly`
                 dt=`date "+%m-%d-%y-%I-%M%p"`
                 echo "*.tgz" > $PATTERN_FILE   # .tgz should be excluded while tar
                 mkdir /tmp/$dt
                 tar -X $PATTERN_FILE -cvzf /tmp/$dt/$MAC"_CPAstats_"$dt".tgz" /tmp/cpuprocanalyzer
                 rm $PATTERN_FILE
                 sleep 1
                 chmod 777 -R /tmp/$dt
                 /rdklogger/uploadRDKBLogs.sh "" HTTP "" false "" /tmp/$dt
                 sleep 1;
            fi

            rm -rf /tmp/cpuprocanalyzer
            if [ "$BOX_TYPE" != "XB3" ]; then
                 rm -rf /tmp/PROC_ANALYZER_ENABLE
            fi

	    if [ "$NeedUpload" -eq 1 ]; then
                 rm -rf /tmp/$dt
	    fi
            exit 0
        ;;
        *)
            man_usage
            exit 0
esac
