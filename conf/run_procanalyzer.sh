#!/bin/sh

PATTERN_FILE="/tmp/proc_pattern_file"

man_usage()
{
  echo "USAGE:  run_procanalyzer.sh {start|stop} {args}"
}

if [ $# -lt 1 ]; then
   man_usage
   exit 1
fi

arg_val=$1
case $arg_val in
        start)
                 nice -n 19 /usr/bin/cpuprocanalyzer
                 exit 0
        ;;
        stop)
            echo "*.tgz" > $PATTERN_FILE   # .tgz should be excluded while tar
            mkdir /tmp/extender_procanalyzer
            tar -X $PATTERN_FILE -cvzf /tmp/extender_procanalyzer/extender_procanalyzer.tgz /tmp/cpuprocanalyzer
            rm $PATTERN_FILE
            sleep 1
            chmod 777 -R /tmp/extender_procanalyzer
            rm -rf /tmp/cpuprocanalyzer
            exit 0
        ;;
        *)
            man_usage
            exit 0
esac

