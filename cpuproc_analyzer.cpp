/* If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include <string.h>
#include <map>
#include <sstream>
#include <stdarg.h>

#ifdef PROCANALYZER_BROADBAND
#include <telemetry_busmessage_sender.h>
#include <json-c/json.h>
#endif

#ifndef PROCANALYZER_EXTENDER
#include "rdk_debug.h"
#endif
#include <bits/stdc++.h>
using namespace std;

#ifndef PROCANALYZER_EXTENDER
extern "C" {
    // C Function call
#include <cimplog/cimplog.h>
#define LOGGING_MODULE "CPUPROCANALYZER"
const char *rdk_logger_module_fetch(void);
}
#endif

/**
 * @defgroup CPU_PROC_ANALYZER CPU Proc Analyzer
 *
 * - RDK PROC ANALYZER is a tool that enables different teams like :
 * development, triage and testing to analyze the CPU and memory utilization of the processes that run on top of RDK framework.
 * - It runs periodically to collect cpu utilisation,load average and memory usage.
 * - It helps us in detecting the memory leaks, cpu and memory performance regressions.
 * - This tool is implemented as a service and is also highly configurable
 *
 * Flow diagram of CPU Proc Analyzer -
 * @image html CPUproc_analyzer_Flowchart_main.png
 * @image html CPUproc_analyzer_Flowchart_1.png
 *
 * @defgroup CPU_PROC_ANALYZER_API  CPU Proc Public APIs
 * @ingroup  CPU_PROC_ANALYZER
 *
 * @defgroup CPU_PROC_ANALYZER_TYPES CPU Proc Data Types
 * @ingroup  CPU_PROC_ANALYZER
 */

/**
 * @addtogroup CPU_PROC_ANALYZER_TYPES
 * @{
 */

#define LINE_LIMIT 256          //!< FILE LINE LIMIT
#define NAME_LIMIT 20           //!< FILE NAME LIMIT
#define SLEEP_SECS 60           //!< Sleep Interval for the data collection
#define TIME_TO_RUN_SECS 0      //!< 0 means, tool should run until it is killed manually
#define BUFF_SIZE_64  64
#define BUFF_SIZE_16  16
#define DEFAULT_MEM_THRESHOLD 1536  //Max filesize limit
#define MONITOR_ALL_PROC_DEF 0  //Default Monitor all process flag
#define DEFAULT_DYNAMIC 1  //Default for Dynamic
#define ITERATION_THRESHOLD 25  //Max number of runs
#define TELEMETRY_ONLY_DEF 0 // Only telemetry reporting default flag

#define CPU_MASK 0x10
#define MEMORY_MASK 0x08
#define FDCOUNT_MASK 0x04
#define THREADCOUNT_MASK 0x02
#define LOADAVG_MASK 0x02
#define CLICOUNT_MASK 0x01

#define SYS_DEF_MASK 0x1F
#define PROC_DEF_MASK 0x1E

typedef unsigned int uint;

#ifdef PROCANALYZER_BROADBAND
uint PROC_MASK = 0x00;
uint SYS_MASK = 0x00;
#else
uint PROC_MASK = 0x1E;
uint SYS_MASK = 0x1F;
#endif

#define MAX(x,y) ((x>y)?x:y)

#define PROC_EVENT_NONE  0x00000000
#define PROC_EVENT_FORK  0x00000001
#define PROC_EVENT_EXEC  0x00000002
#ifdef PROCANALYZER_EXTENDER
#define  RDK_LOG_ERROR 0
#define  RDK_LOG_DEBUG 1
#define  RDK_LOG_INFO 2
#define  RDK_LOG_TRACE1 3
#define  RDK_LOG get_proclog
#define  EXTENDER_VENDOR_NAME_STR "vendor_name"
#define  EXTENDER_MODEL_NAME_STR  "model"
#endif
pthread_mutex_t mtx;
/**
 * @struct stPrevData
 *
 * @brief Holds status of previous data such as Total Major Faults Raised,Total CPU Used Time,User Used CPU Time,System Used CPU Time.
 */
struct stPrevData
{
    unsigned int prevTotalMajFaultsRaised;
    unsigned long prevTotalUsedCPUTime;
    unsigned long prevUserUsedCPUTime;
    unsigned long prevSystemUsedCPUTime;
    double prevTotalCPUTime_usec;
    bool status;
};

/**
 * @struct stCPUInfo
 *
 * @brief Holds status of CPU information such as Total Time and Idle Time of CPU.
 */
struct stCPUInfo
{
    unsigned long long total;
    unsigned long long idle;
} prevCPUInfo;

typedef struct EnvVarNode
{
    char* name;
    char* value;
    struct EnvVarNode *next;
} EnvVarNode;


map<unsigned int, struct stPrevData> prevData;

FILE* fp_selectedps = NULL;
FILE* fp_stat = NULL;
FILE* fp_dataOut = NULL;

#if defined  PROCANALYZER_BROADBAND
 #define CONFIG_PATH "/nvram"
 #define LOG_PATH    "/tmp"
#elif defined PROCANALYZER_EXTENDER
 #define CONFIG_PATH "/usr/opensync/scripts"
 #define LOG_PATH    "/tmp"
#else
 #define CONFIG_PATH "/opt"
 #define LOG_PATH    "/opt/logs"
#endif

string outputDir = LOG_PATH"/cpuprocanalyzer/";
string outputDynamicDir = LOG_PATH"/cpuprocanalyzer/dynamic/";

long totalTimeElapsed_sec = 0;
char strTime[80];
list<string>  exclude_process_list;
list<string> :: iterator it;
#ifdef PROCANALYZER_EXTENDER
// Get the Log level
char* GetCurTimeStamp();
void get_proclog(int log_level,const char * log_module ,const char *format, ...)
{
     printf("%s\t",GetCurTimeStamp());
    if(log_level==0){
        printf("<ERROR>\t");
    }
    else if(log_level==1){
        printf("<DEBUG>\t");
    }
    else if(log_level==2){
        printf("<INFO>\t");
    }
    else if(log_level==3){
        printf("<TRACE1>\t");
    }
    va_list args;
    printf("%s\t",log_module);
    va_start(args, format);
    vprintf(format, args);
    printf("\n");
    va_end(args);
    return;
}

int get_device_param(char* param,char* value)
{
    char tmp_string[BUFF_SIZE_64]  ="\0";
    char buf1[BUFF_SIZE_64]        ="\0";
    sprintf(tmp_string," ovsh s AWLAN_Node %s -j | grep :",param);
    FILE * fp = popen(tmp_string, "r");
    if (fp == 0)
    {
       RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", " popen failed.Failed to run the command.\n");
       return -1;
    }
    fgets(buf1, BUFF_SIZE_64, fp);
    sscanf(buf1,"        \"%[^'\"''']\": \"%[^'\"']\"",tmp_string,value);
    pclose(fp);
    return 1;
}
#endif

char* removespaces(char *str);
int read_config_param(const char *paramname,const char *filename,char *res)
{
    FILE *fp = fopen(filename,"r");
    char tmp_string[128] = {0};
    char* tmp;
    char* pch;
    if(fp)
    {
        memset(tmp_string,0,128);
        while(fgets(tmp_string,128,fp)!= NULL)
        {
            if(strstr(tmp_string,paramname))
            {
                tmp=removespaces(tmp_string);
                pch=strchr(tmp,'=');
                pch=pch+1;
                strncpy(res,pch,BUFF_SIZE_64);
                return 1;
            }
            memset(tmp_string,0,128);
        }
        fclose(fp);
    }
    return 0;
}

char* removespaces(char *str)
{
        int i=0,j=0;
        while(str[i] != NULL)
        {
                if (str[i] != ' ')
                      str[j++] = str[i];
           i++;
        }
    str[j] = '\0';
    return str;
}
/**
 * @}
 */

/**
 * @addtogroup CPU_PROC_ANALYZER_API
 * @{
 */

/**
 *  @brief This function reads the Process Name from /proc/stat.
 *
 *  @param[in] fp           File Pointer
 *  @param[in] procName     Process Name
 */
void ReadProcessName(FILE* fp, char* procName)
{
    char ch;
    int i = 0;
    while(!feof(fp) && fgetc(fp) != '(');
    while(!feof(fp))
    {
        ch = fgetc(fp);
        if(ch == ')' || ferror(fp) || feof(fp)) break;
        //REPLACING CHARACTERS IN PROCESS NAME
        if(ch == 0 || ch == ' ' || ch==':' || ch == '\\' || ch == '/' || ch == '[' || ch == ']' || ch == '{' || ch == '}' || ch == '(' || ch == ')')
            ch = '-';
        procName[i] = ch;

        ++i;
    }
    procName[i] = '\0';
}

/**
 * @brief This function reads the Process Command Line Output from /proc/cmdline and removes extra characters.
 *
 * @param[in] fp         File Pointer
 * @param[in] str        String
 */
void ReadSkippingRandomChar(FILE* fp, char* str)
{
    char ch;
    int i = 0;
    while(!feof(fp))
    {
        ch = fgetc(fp);
        if(ferror(fp) || feof(fp)) break;
        if(ch == 0) ch = ' ';
        str[i] = ch;
        ++i;
    }
    str[i] = '\0';
}


/**
 * @brief This function retrieves value of matching string from a file.
 */
char* GetValuesFromFile (char *fname, char *searchStr, char *strValue, unsigned int strValueLen)
{
    char buf1[BUFF_SIZE_64]   = "\0";
    char tmpStr[BUFF_SIZE_64] = "\0";
    char srch[BUFF_SIZE_64]   = "\0";

    FILE *fp = fopen (fname, "r" );

    if (!fp) {
       RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "fopen failed.Failed to read %s\n", searchStr);
       return NULL;
    }

    memset(buf1, 0, BUFF_SIZE_64);
    memset(tmpStr, 0, BUFF_SIZE_64);

    while (fgets(buf1,BUFF_SIZE_64,fp)) {

        if (strstr(buf1, searchStr)) {
            memset (srch, 0, sizeof(srch));
            sprintf(srch, "%s%%s", searchStr);
            sscanf (buf1, srch, tmpStr);
            strncpy (strValue, tmpStr, strValueLen-1);

            if (strValue[strlen(strValue)] == '\n') {
                strValue[strlen(strValue)] = '\0';
            }
            break;
        }
    }
    fclose(fp);
    return strValue;
}

#if defined  PROCANALYZER_BROADBAND
void ReadRFCJson()
{
    string rfc_filename = outputDir + "rfc_list.txt";
    static const char filename[] = "/tmp/rfc-current.json";

    if(access(filename, R_OK))
    {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "rfc-current.json is not accessible.\n");
        return;
    }

    FILE *fp1 = fopen(rfc_filename.c_str(),"a");
    struct json_object *obj, *feature_obj, *feaCtrl_obj, *featArr_obj, *name_obj, *enable_obj;

    obj = json_object_from_file(filename);
    feaCtrl_obj = json_object_object_get(obj, "featureControl");
    feature_obj = json_object_object_get(feaCtrl_obj, "features");

    int arrlen = json_object_array_length(feature_obj);

    if(fp1)
    {
        for(int i=0; i<arrlen; i++)
        {
            featArr_obj = json_object_array_get_idx(feature_obj, i);
            name_obj = json_object_object_get(featArr_obj, "name");
            enable_obj = json_object_object_get(featArr_obj, "enable");
            fprintf(fp1, "%s : %s\n", json_object_get_string(name_obj), json_object_get_string(enable_obj));
        }
        fclose(fp1);
    }
    else
    {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "Cannot open RFC file.\n");
    }
    json_object_put(obj);
}
#endif

void GetNumOfClientsConnected(unsigned int *cliCount)
{
    char buf[8] = {0};
    FILE *fp = NULL;

    fp = popen("dmcli eRT getv Device.Hosts.HostNumberOfEntries | grep value | awk '{print $5}'", "r");
    if(fp)
    {
        if(fgets(buf, 8, fp))
        {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "Number of Clients connected : %d\n", atoi(buf));
            *cliCount = atoi(buf);
        }
        pclose(fp);
    }
    else
    {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "Popen failure\n");
    }
}

/**
 * @brief This function retrieves device name and manufacturer name.
 */
void ReadDeviceName()
{
    char mfgname[BUFF_SIZE_16]     = "\0";
    char devicename[BUFF_SIZE_16]  = "\0";
    char buildname[BUFF_SIZE_64]   = "\0";
    char name[100]                 = "\0";
 
    #if defined PROCANALYZER_BROADBAND
    memset (mfgname, 0, BUFF_SIZE_16);
    GetValuesFromFile ("/etc/device.properties", "MANUFACTURE=", mfgname, sizeof(mfgname));

    if (strncmp(mfgname,"UNKNOWN",strlen(mfgname))) {
        GetValuesFromFile ("/etc/device.properties", "MFG_NAME=", mfgname, sizeof(mfgname));
    }

    memset(devicename,0,BUFF_SIZE_16);
    GetValuesFromFile ("/etc/device.properties", "BOX_TYPE=", devicename, sizeof(devicename));
    #elif defined PROCANALYZER_EXTENDER
    get_device_param(EXTENDER_VENDOR_NAME_STR,mfgname);
    get_device_param(EXTENDER_MODEL_NAME_STR,devicename);
    #else

    memset (mfgname, 0, BUFF_SIZE_16);
    GetValuesFromFile ("/etc/device.properties", "MFG_NAME=", mfgname, sizeof(mfgname));

    memset(devicename,0,BUFF_SIZE_16);
    GetValuesFromFile ("/etc/device.properties", "DEVICE_NAME=", devicename, sizeof(devicename));

    #endif

    memset (name, 0, sizeof(name));
    snprintf (name, BUFF_SIZE_64, "%s%s", mfgname, devicename);

    memset(buildname, 0, sizeof(buildname));
    GetValuesFromFile ("/version.txt", "imagename:", buildname, sizeof(buildname));

    if (!strcmp(buildname, "")) {
        GetValuesFromFile ("/version.txt", "imagename=", buildname, sizeof(buildname));
    }


    FILE *fpout = fopen(LOG_PATH"/cpuprocanalyzer/deviceinfo.data", "w");

    if (!fpout) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "Could not open deviceInfo.data.\n");
    }
    else {
        fprintf(fpout, "DEVICE_NAME:%s\nBUILD_NAME:%s\n ", name, buildname);
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "Device name %s and Build name  %s written successfully.\n",name, buildname);
        fclose (fpout);
    }
}

/**
 * @}
 */

/**
 * @addtogroup CPU_PROC_ANALYZER_TYPES
 * @{
 */

/**
 * @struct stProcData
 *
 * @brief Holds status of Process data such as :
 * - PID of process, Process State, Parent PID, Process Group ID, Session ID of the Process.
 * - The Kernel Flags word of the Process, Major Faults, Minor Faults, Nice value, Number of threads in the process.
 * - Resident Set Size, Virtual memory size, Real-time scheduling priority, Scheduling Policy.
 */
struct stProcData
{
    int d_pid;
    char s_comm[1000], c_state;
    int d_ppid, d_pgrp, d_session, d_tty_nr, d_tpgid;
    unsigned u_flags;
    unsigned long lu_minflt, lu_cminflt, lu_majflt, lu_cmajflt, lu_utime, lu_stime;
    long ld_cutime, ld_cstime, ld_priority, ld_nice, ld_num_threads, ld_itrealvalue;
    unsigned long long llu_starttime;
    unsigned long lu_vsize;
    long ld_rss;
    unsigned long lu_rsslim, lu_startcode, lu_endcode, lu_startstack, lu_kstkesp, lu_kstkeip, lu_signal, lu_blocked, lu_sigignore, lu_sigcatch, lu_wchan, lu_nswap, lu_cnswap;
    int d_exit_signal, d_processor;
    unsigned int u_rt_priority, u_policy;
    unsigned long long llu_delayacct_blkio_ticks;
    unsigned long lu_guest_time;
    long ld_cguest_time;

/**
 * @}
 */

/**
 * @addtogroup CPU_PROC_ANALYZER_API
 * @{
 */

/**
 * @brief This function reads status of the Process and gives information like :
 * - Parent PID, Parent Name, Number of threads in the Process
 *
 * @param[in] fp_procStat       File Pointer
 */
    void ReadProcStat(FILE* fp_procStat)
    {

        fscanf(fp_procStat, "%d", &d_pid);
        ReadProcessName(fp_procStat, s_comm);
        fscanf(fp_procStat, " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld", &c_state, &d_ppid, &d_pgrp, &d_session, &d_tty_nr, &d_tpgid, &u_flags, &lu_minflt, &lu_cminflt, &lu_majflt, &lu_cmajflt, &lu_utime, &lu_stime, &ld_cutime, &ld_cstime, &ld_priority, &ld_nice, &ld_num_threads, &ld_itrealvalue, &llu_starttime, &lu_vsize, &ld_rss, &lu_rsslim, &lu_startcode, &lu_endcode, &lu_startstack, &lu_kstkesp, &lu_kstkeip, &lu_signal, &lu_blocked, &lu_sigignore, &lu_sigcatch, &lu_wchan, &lu_nswap, &lu_cnswap, &d_exit_signal, &d_processor, &u_rt_priority, &u_policy, &llu_delayacct_blkio_ticks, &lu_guest_time, &ld_cguest_time);

        RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER","%s(%d): %d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld\n", __func__, __LINE__, d_pid, s_comm, c_state, d_ppid, d_pgrp, d_session, d_tty_nr, d_tpgid, u_flags, lu_minflt, lu_cminflt, lu_majflt, lu_cmajflt, lu_utime, lu_stime, ld_cutime, ld_cstime, ld_priority, ld_nice, ld_num_threads, ld_itrealvalue, llu_starttime, lu_vsize, ld_rss, lu_rsslim, lu_startcode, lu_endcode, lu_startstack, lu_kstkesp, lu_kstkeip, lu_signal, lu_blocked, lu_sigignore, lu_sigcatch, lu_wchan, lu_nswap, lu_cnswap, d_exit_signal, d_processor, u_rt_priority, u_policy, llu_delayacct_blkio_ticks, lu_guest_time, ld_cguest_time);

    }

/**
 * @brief This function constructs a file name based on parameters such as - output Directory Name,PID value,s_comm data,PID value,s_comm data. 
 * For example : "/opt/logs/cpuprocanalyzer/<PID value>/s_comm/<PID value>/s_comm"
 *
 * @param[in] outProcFilename       Output Process Filename
 */
    void OutFilename(char* outProcFilename,int is_dynamic)
    {
        if(is_dynamic == 1)
        {
            sprintf(outProcFilename, "%s%d_%s/%d_%s.data", outputDynamicDir.c_str(), d_pid, s_comm,d_pid,s_comm);
        }
        else
        {
            sprintf(outProcFilename, "%s%d_%s/%d_%s.data", outputDir.c_str(), d_pid, s_comm,d_pid, s_comm);
        }
    }

/**
 * @brief This function constructs a file name based on parameters such as - output Directory Name,PPID value,Parent process Name,PID value,s_comm data. 
 * For example : "/opt/logs/cpuprocanalyzer/<PPID value>/<Parent process name>/<PID value>/s_comm"
 *
 * @param[in] outProcFilename       Output Process Filename
 * @param[in] ppid                  Parent PID
 * @param[in] pname                 Parent Name
 */
    void OutFilename(char* outProcFilename, int ppid, char* pname)
    {
        sprintf(outProcFilename, "%s%d_%s/threads/%d_%s.data", outputDir.c_str(), ppid, pname, d_pid, s_comm);
    }

/**
 * @brief This function gives Total CPU used time.
 *
 * - Total CPU Used Time value is the sum of User Used CPU Time value and System Used CPU Time value
 *
 * @param[out] outTotalTime         Output Total CPU Used Time value
 */
    void GetTotalUsedTime(unsigned long* outTotalTime)
    {
        *outTotalTime = lu_utime + lu_stime;// + (ld_cutime + ld_cstime);
    }

/**
 * @brief This function gives User used CPU time.
 *
 * - User time is the amount of time the CPU was busy executing code in user space.
 *
 * @param[out] outUserTime          Output User used CPU Time value
 */
    void GetUserUsedTime(unsigned long* outUserTime)
    {
        *outUserTime = lu_utime;
    }

/**
 * @brief This function gives information about System used CPU time.
 *
 * - System time is the amount of time the CPU was busy executing code in kernel space.
 *
 * @param[out] outSystemTime            Output System used CPU Time value
 */
    void GetSystemUsedTime(unsigned long* outSystemTime)
    {
        *outSystemTime = lu_stime;
    }

/**
 * @brief This function gives the information about Total Major Faults.
 *
 * - The number of major faults the process has made which required loading a memory page from disk.
 *
 * @param[out] outTotalMjrFlts      Outputs Total Major Faults
 */
    void GetTotalMjrFlts(unsigned int* outTotalMjrFlts)
    {
        *outTotalMjrFlts = lu_majflt;// + lu_cmajflt;
    }
};

/**
 *  @brief This function gives Current Date and Time in the format Year-Month-Day and Hours-Minutes-Seconds.
 *
 *  @ret Returns date and time in string format.
 */
char* GetCurTimeStamp()
{
    time_t rawtime;
    tm* timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(strTime,80,"%Y-%m-%d %H:%M:%S",timeinfo);
    return strTime;
}

/**
 * @brief This function gives information about the Memory parameters.
 *
 * - Information such as Virtual Memory Size, Resident Set Size and Size Of Stack
 *
 * @param[in]  filename      Name of the File
 * @param[out] memParam      Memory Parameters
 * @param[in]  param         It can be parameter like Virtual Memory Size, Resident Set Size and Size Of Stack.
 */
void GetMemParams(char* filename, unsigned long* memParam, char* param)
{
    char line[128]= {'\0'};

    string str;
    FILE* fp_status = fopen(filename, "r");
    if(fp_status)
    {
        while(!feof(fp_status))
        {
            fgets(line, sizeof(line)-1, fp_status);
            if(strncmp(line, param, strlen(param)) == 0)
            {
                stringstream ss(line);
                for (int idx=0; idx<2; idx++)
                    ss >> str;
                *memParam = atoi(str.c_str());
                break;
            }
            memset(line,0,sizeof(line));
        }
        fclose(fp_status);
    }
    else
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ERROR opening the file: %s\n", __func__, __LINE__, filename);
    }
}

/**
 * @brief This function gives Load Average values.
 *
 * Output Example = 0.75 0.33 0.25 1/25 1747 where :
 *
 * - First three fields : Load averages over the last 1,5 and 15 minutes.
 * - The fourth field consists of two numbers separated by a slash (/), where :
 *   First number is the number of currently executing kernel scheduling entities(processes,threads);
 *   this will be less than or equal to the number of CPUs.
 * - The value after the slash is the number of kernel scheduling entities that currently exist on the system.
 * - The fifth field is the PID of the process.
 *
 * @param[out] loadavg      Load Average value
 */
void GetLoadAverage(float* loadavg)
{
    //Capture Load Average value
    FILE *fp;
    if ((fp = fopen("/proc/loadavg", "r")) == NULL)
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ERROR reading file: /proc/loadavg", __func__, __LINE__);
    }
    else
    {
        fscanf(fp, "%f", loadavg);
        fclose(fp);
    }
}

/**
 * @brief This function gives information about Used memory.
 *
 * - It reports statistics about memory usage on the system and gives information like Total usable RAM and Free Memory.
 * - Used Memory is calculated by subtracting Free Memory from Total Memory.
 *
 * @param[out] mem      Used Memory value
 */
void GetUsedMemory(unsigned long* mem)
{
    //Capture Used Memory value
    char line[64]= {'\0'};
    string str;
    int count=0;
    unsigned long memTotal = 0;
    unsigned long memFree = 0;
    FILE* fp = fopen("/proc/meminfo", "r");
    if(fp)
    {
        while(!feof(fp))
        {
            fgets(line, sizeof(line), fp);
            if(strncmp(line, "MemTotal:", 8) == 0)
            {
                stringstream ss(line);
                for (int idx=0; idx<2; idx++)
                    ss >> str;
                memTotal = atoi(str.c_str());
                count++;
            }
            else if(strncmp(line, "MemFree:", 7) == 0)
            {
                stringstream ss(line);
                for (int idx=0; idx<2; idx++)
                    ss >> str;
                memFree = atoi(str.c_str());
                count++;
            }
            if(count == 2) break;
            memset(line,0,sizeof(line));
        }
        *mem = memTotal - memFree;
        fclose(fp);
    }
    else
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ERROR opening the file: /proc/meminfo\n", __func__, __LINE__);
    }
}

/**
 * @brief This function gives the Idle percent value.
 *
 * - Idle time is the amount of time the CPU was not busy or otherwise, the amount of time it executed the System Idle process.
 * - Idle time actually measures unused CPU capacity.
 *
 * @param[out] idlepercent      Idle Percent Value
 */
void GetIdlePercent(float* idlePercent)
{
    char buf[320];
    unsigned long u, n, s, i, w, x, y, z;
    stCPUInfo currentCPUInfo;
    FILE* fp = fopen("/proc/stat", "r");
    if(fp)
    {
        fgets(buf, sizeof(buf), fp);
        sscanf(buf, "cpu %lu %lu %lu %lu %lu %lu %lu %lu", &u, &n, &s, &i, &w, &x, &y, &z);
        currentCPUInfo.total = u + n + s + i + w + x + y + z;
        currentCPUInfo.idle = i;

        *idlePercent = (float)(100 * (currentCPUInfo.idle - prevCPUInfo.idle)/(currentCPUInfo.total - prevCPUInfo.total));

        prevCPUInfo.total = currentCPUInfo.total;
        prevCPUInfo.idle = currentCPUInfo.idle;
    }
    fclose(fp);
}

/**
 * @brief This function to exclude the process list of least concern.
 */
void CreateExclusionList()
{
    char tmp_string[32];
    sprintf(tmp_string,"cd ../../bin");
    system(tmp_string);
    sprintf(tmp_string,"busybox --list");
    FILE * fp = popen( tmp_string, "r" );
    if ( fp == 0 ) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Could not get busy box list\n");
        return;
    }
    char buf1[ BUFF_SIZE_64 ];
    while(fgets(buf1,BUFF_SIZE_64,fp)!= NULL)
    {
        buf1[strlen(buf1) - 1] = '\0';
        exclude_process_list.push_back(string(buf1));
        memset(buf1,0,sizeof(buf1));
    }
    pclose(fp);
    //exclude_process_list.push_back("cpuprocanalyzer");
}

/**
 * @brief This function gives information about the File Descriptors in process.
 *
 * @param[in] d_pid         PID of process
 * @param[in] FDCount       File Descriptor in process
 */
void GetFDCount(char* filename, int* FDCount)

{
    FILE * fp = popen( filename, "r" );

    if ( fp == 0 )
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Could not get FD Count\n");
    }
    else
    {
        fscanf(fp, "%d" , FDCount);
        pclose(fp);
    }
}

/**
 * @brief This function gives information about the File Descriptors at system level.
 *
 * @param[in] FDCountSystem File Descriptors at system level
*/

void GetFDCountSystem(int* FDCountSystem)

{
    char tmp_string[64] = {0};
    snprintf(tmp_string, sizeof(tmp_string), "/proc/sys/fs/file-nr" );
    FILE * fp = fopen( tmp_string, "r" );

    if ( fp == 0 )
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Could not get FD Count System Level\n");
    }
    else
    {
        fscanf(fp, "%d" , FDCountSystem);
        fclose(fp);
    }
}

/**
 * @brief This is to set the bit mask for System/Process.
*/

uint SetMask(char* res)
{
    uint bit_mask = 0x00;
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Input param = %s, strlen(res) = %d, sizeof() = %d\n",
                           res, strlen(res), sizeof(res));

    char *newline = strchr( res, '\n' );
    if ( newline )
    {
        *newline = '\0';
    }

    char *token = strtok(res, ",");
    while(token != NULL)
    {
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Token = %s, Strlen = %d, sizeof() = %d\n", token, strlen(token), sizeof(token));
        if(strncmp(token,"cpu",strlen(token)) == 0)
        {
            bit_mask |= CPU_MASK;
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Cpu mask is set : %d\n", bit_mask);
        }
        else if(strncmp(token,"memory",strlen(token)) == 0)
        {
            bit_mask |= MEMORY_MASK;
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Memory mask is set : %d\n", bit_mask);
        }
        else if(strncmp(token,"fd",strlen(token)) == 0)
        {
            bit_mask |= FDCOUNT_MASK;
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","FD mask is set : %d\n", bit_mask);
        }
        else if(strncmp(token,"loadavg",strlen(token)) == 0)
        {
            bit_mask |= LOADAVG_MASK;
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","LoadAvg mask is set : %d\n", bit_mask);
        }
        else if(strncmp(token,"thread",strlen(token)) == 0)
        {
            bit_mask |= THREADCOUNT_MASK;
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Thread mask is set : %d\n", bit_mask);
        }
        else if(strncmp(token,"cliconnected",strlen(token)) == 0)
        {
            bit_mask |= CLICOUNT_MASK;
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Cli count mask is set : %d\n", bit_mask);
        }
        token = strtok(NULL, ",");
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","token is : %s\n", token);
    }
    return bit_mask;
}

/**
 * @brief This function gives status information about the process.
 *
 * - Information such as Process Name, PID of the parent, Virtual memory size, Resident set size, Size of Stack.
 *
 * @param[in] procData      Process Data
 * @param[in] ppid          Parent pid,default to 0
 * @param[in] pname         Parent Name
 * @param[in] is_dynamic    Flag to check dynamically created process.
 */
int LogProcData(stProcData* procData, int ppid=0, char* pname="",int is_dynamic=0, bool telemetryOnly=0)
{
    char tmp_string[1024] = {0};
    unsigned long vmStack=0;
    unsigned long vmSize=0;
    unsigned long vmRSS=0;
    int return_val;
    int FDCount=0;
    string searchstr   = ".sh";
    string searchstr_1 = "kworker";
    string s;
    memset(tmp_string,0,1024);
    (ppid != 0) ? sprintf(tmp_string, "/proc/%d/task/%d/stat", ppid, procData->d_pid)
    : sprintf(tmp_string, "/proc/%d/stat", procData->d_pid);

    fp_stat = fopen(tmp_string, "r");
    if(fp_stat)   {
        procData->ReadProcStat(fp_stat);
        fclose(fp_stat);
    }
    else
    {
       RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Failed to open %s file\n", tmp_string);
       return 0;
    }

    // excluding processes of least concern
    if(ppid!= 0)
    {
         for(it=exclude_process_list.begin();it!=exclude_process_list.end();it++)
        {
            s= *it;
            if(strncmp(procData->s_comm,s.c_str(),MAX(strlen(procData->s_comm),strlen(s.c_str()))) == 0)
            {
                return 0;
            }
        }
    }
    //process
    else
    {
        if(strlen(procData->s_comm) == 0)
        {
            return 0;
        }
        else
        {
            for(it=exclude_process_list.begin();it!=exclude_process_list.end();it++)
            {
                s = *it;
                if(strncmp(procData->s_comm,s.c_str(),MAX(strlen(procData->s_comm),strlen(s.c_str()))) == 0)
                {
                    return 0;
                }
            }
        }
    }

    if(PROC_MASK & MEMORY_MASK)
    {
       (ppid != 0) ? sprintf(tmp_string, "/proc/%d/task/%d/status", ppid, procData->d_pid)
       : sprintf(tmp_string, "/proc/%d/status", procData->d_pid);
       GetMemParams(tmp_string, &vmStack, "VmStk:");
       GetMemParams(tmp_string, &vmSize, "VmSize:");
       GetMemParams(tmp_string, &vmRSS, "VmRSS:");
    }
    if(PROC_MASK & FDCOUNT_MASK)
    {
       (ppid != 0) ? snprintf(tmp_string, sizeof(tmp_string), "ls /proc/%d/task/%d/fd | wc -l", ppid, procData->d_pid)
       : snprintf(tmp_string, sizeof(tmp_string), "ls /proc/%d/fd | wc -l", procData->d_pid);
       GetFDCount(tmp_string, &FDCount);
    }


    /*
      Possible cases from /proc/<pid>/cmdline that confirms a script running
          1. /bin/sh <script>
          2. /bin/bash <script>
          2. sh <script>
          3. -sh
          4. -bash
      Substring sh in processname can be cross verified with the presence of "sh" in /proc/<pid>/comm
    */
    sprintf(tmp_string, "/proc/%d/cmdline", procData->d_pid);
    FILE* fp_cmd = fopen(tmp_string, "r");
    if(fp_cmd)
    {
        fgets(tmp_string, sizeof(tmp_string), fp_cmd);
        fclose(fp_cmd);

        if ( (strncmp(tmp_string,"/bin/sh",strlen(tmp_string)) == 0) ||
             (strncmp(tmp_string,"sh",strlen(tmp_string)) ==0 ) ||
             (strncmp(tmp_string,"-sh",strlen(tmp_string)) == 0) ||
             (strncmp(tmp_string,"-bash",strlen(tmp_string)) == 0) ||
             (strncmp(tmp_string,"/bin/bash",strlen(tmp_string)) == 0) )
        {
            RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CPUPROCANALYZER","Rejecting process : %s\n", procData->s_comm);
            return 0;
        } else if ( strstr(tmp_string,searchstr.c_str()) ) {
            sprintf(tmp_string, "/proc/%d/comm", procData->d_pid);
            FILE* fp_cmd = fopen(tmp_string, "r");
            if(fp_cmd)
            {
                fgets(tmp_string, sizeof(tmp_string), fp_cmd);
                fclose(fp_cmd);
                if( (strncmp(tmp_string,"sh",strlen(tmp_string)) == 0) || (strncmp(tmp_string,"bash",strlen(tmp_string)) == 0) )
                {
                    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CPUPROCANALYZER","Rejecting process : %s\n", procData->s_comm);
                    return 0;
                }
            }
        }
    }

    /*  Reject kworker_threads  */
    sprintf(tmp_string, "/proc/%d/comm", procData->d_pid);
    fp_cmd = fopen(tmp_string, "r");
    if(fp_cmd)
    {
        fgets(tmp_string, sizeof(tmp_string), fp_cmd);
        fclose(fp_cmd);
        if( strstr(tmp_string,searchstr_1.c_str()) )
        {
            return 0;
        }
    }

    if (ppid != 0) {
        sprintf(tmp_string, "%s/%d_%s/threads/", outputDir.c_str(), ppid, pname);
    }
    else
    {
        if(is_dynamic  == 0)
        {
            sprintf(tmp_string, "%s%d_%s", outputDir.c_str(), procData->d_pid, procData->s_comm);

        }
        else
        {
            sprintf(tmp_string, "%s%d_%s", outputDynamicDir.c_str(), procData->d_pid, procData->s_comm);
        }
    }

    mkdir(tmp_string, S_IRWXU | S_IRWXG | S_IRWXO);
    (ppid != 0) ? procData->OutFilename(tmp_string, ppid, pname) : procData->OutFilename(tmp_string,is_dynamic);
    fp_dataOut = fopen(tmp_string, "a+");
    if(fp_dataOut)
    {
        unsigned long currentTotalUsedCPUTime = 0;
        unsigned int currentTotalMajorFaultsRaised = 0;
        unsigned long currentUserUsedCPUTime = 0;
        unsigned long currentSystemUsedCPUTime = 0;
        struct timeval currentTime;
        double currentTime_usec, timeDiff_usec, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System;
        unsigned int majorFaultsRaise;

        procData->GetTotalUsedTime(&currentTotalUsedCPUTime);
        procData->GetUserUsedTime(&currentUserUsedCPUTime);
        procData->GetSystemUsedTime(&currentSystemUsedCPUTime);
        procData->GetTotalMjrFlts(&currentTotalMajorFaultsRaised);
        gettimeofday(&currentTime, NULL);
        currentTime_usec = (currentTime.tv_sec*1000000.0)+currentTime.tv_usec;

        timeDiff_usec = currentTime_usec - prevData[procData->d_pid].prevTotalCPUTime_usec;
        if(timeDiff_usec == 0) timeDiff_usec = 1;
        cpuUseRaise = 100*(currentTotalUsedCPUTime - prevData[procData->d_pid].prevTotalUsedCPUTime)/(sysconf(_SC_CLK_TCK)*timeDiff_usec/1000000);
        cpuUseRaise_User = 100*(currentUserUsedCPUTime - prevData[procData->d_pid].prevUserUsedCPUTime)/(sysconf(_SC_CLK_TCK)*timeDiff_usec/1000000);
        cpuUseRaise_System = 100*(currentSystemUsedCPUTime - prevData[procData->d_pid].prevSystemUsedCPUTime)/(sysconf(_SC_CLK_TCK)*timeDiff_usec/1000000);
        if(ppid == 0)
            RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %d %0.2lf %0.2lf %0.2lf %ld %ld %0.2lf %0.2lf\n", __func__, __LINE__, procData->d_pid, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, currentTotalUsedCPUTime, prevData[procData->d_pid].prevTotalUsedCPUTime, sysconf(_SC_CLK_TCK), timeDiff_usec);
        majorFaultsRaise = (currentTotalMajorFaultsRaised - prevData[procData->d_pid].prevTotalMajFaultsRaised);

        prevData[procData->d_pid].prevTotalUsedCPUTime = currentTotalUsedCPUTime;
        prevData[procData->d_pid].prevUserUsedCPUTime = currentUserUsedCPUTime;
        prevData[procData->d_pid].prevSystemUsedCPUTime = currentSystemUsedCPUTime;
        prevData[procData->d_pid].prevTotalCPUTime_usec = currentTime_usec;
        prevData[procData->d_pid].prevTotalMajFaultsRaised = currentTotalMajorFaultsRaised;

        if(prevData[procData->d_pid].status != 1)
        {
            sprintf(tmp_string, "/proc/%d/cmdline", procData->d_pid);
            FILE* fp_cmd = fopen(tmp_string, "r");
            if(fp_cmd)
            {
                ReadSkippingRandomChar(fp_cmd, tmp_string);
                fclose(fp_cmd);

                if(telemetryOnly == false)
                {
                fprintf(fp_dataOut, "Command-Line : %s\n\n", tmp_string);
                if(PROC_MASK)
                {
                    fprintf(fp_dataOut, "El-Time\tTimeStamp\t");
                    if(PROC_MASK & CPU_MASK)
                    {
                       fprintf(fp_dataOut, "\tCPU%\tCPU%:U\tCPU%:S\tMjrFlts");
                    }
                    if(PROC_MASK & MEMORY_MASK)
                    {
                       fprintf(fp_dataOut, "\tVmSize\tVmRSS\tVmStk");
                    }
                    if(PROC_MASK & THREADCOUNT_MASK)
                    {
                       fprintf(fp_dataOut, "\tThreadCount");
                    }
                    if(PROC_MASK & FDCOUNT_MASK)
                    {
                       fprintf(fp_dataOut, "\tFDCount");
                    }
                    fprintf(fp_dataOut, "\n");
                }
                else
                {
                   fprintf(fp_dataOut, "El-Time\tTimeStamp\t\tCPU%\tCPU%:U\tCPU%:S\tMjrFlts\tVmSize\tVmRSS\tVmStk\tThreadCount\tFDCount\n");
                }
            }
        }
        }

       if(is_dynamic ==1 )
        {
            sprintf(tmp_string, "/proc/%d/stat", procData->d_pid);
            FILE *f = fopen(tmp_string, "r");
            if ( f == 0 ) {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Failed to open /proc/%d/stat/ of dynamic process\n", procData->d_pid);
                return 0;
            }
            else {
                fscanf(f, " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld", &procData->c_state, &procData->d_ppid, &procData->d_pgrp, &procData->d_session, &procData->d_tty_nr, &procData->d_tpgid, &procData->u_flags, &procData->lu_minflt, &procData->lu_cminflt, &procData->lu_majflt, &procData->lu_cmajflt, &procData->lu_utime, &procData->lu_stime, &procData->ld_cutime, &procData->ld_cstime, &procData->ld_priority, &procData->ld_nice, &procData->ld_num_threads, &procData->ld_itrealvalue, &procData->llu_starttime, &procData->lu_vsize, &procData->ld_rss, &procData->lu_rsslim, &procData->lu_startcode, &procData->lu_endcode, &procData->lu_startstack, &procData->lu_kstkesp, &procData->lu_kstkeip, &procData->lu_signal, &procData->lu_blocked, &procData->lu_sigignore, &procData->lu_sigcatch, &procData->lu_wchan, &procData->lu_nswap, &procData->lu_cnswap, &procData->d_exit_signal, &procData->d_processor, &procData->u_rt_priority, &procData->u_policy, &procData->llu_delayacct_blkio_ticks, &procData->lu_guest_time,&procData->ld_cguest_time);
                cpuUseRaise= procData->lu_utime + procData->lu_stime;
                cpuUseRaise_User = procData->lu_utime;
                cpuUseRaise_System = procData->lu_stime;

                if(telemetryOnly == false)
                {
                if(PROC_MASK)
                {
                    fprintf(fp_dataOut, "%ld\t%s", totalTimeElapsed_sec, GetCurTimeStamp());
                    if(PROC_MASK & CPU_MASK)
                    {
                      fprintf(fp_dataOut, "\t%0.2lf\t%0.2lf\t%0.2lf\t%d", cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise);
                      RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %0.2lf %0.2lf %0.2lf %d \n", __func__, __LINE__, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise);
                    }
                    if(PROC_MASK & MEMORY_MASK)
                    {
                       fprintf(fp_dataOut, "\t%ld\t%ld\t%ld", vmSize, vmRSS, vmStack);
                       RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %ld %ld %ld \n", __func__, __LINE__, vmSize, vmRSS, vmStack);
                    }
                    if(PROC_MASK & THREADCOUNT_MASK)
                    {
                      fprintf(fp_dataOut, "\t%ld\t", ((procData->ld_num_threads)-1));
                      RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %ld \n", __func__, __LINE__, ((procData->ld_num_threads)-1));
                    }
                    if(PROC_MASK & FDCOUNT_MASK)
                    {
                       fprintf(fp_dataOut, "\t%d\t", FDCount);
                       RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %d \n", __func__, __LINE__, FDCount);
                    }
                    fprintf(fp_dataOut, "\n");
                }
                else
                {
                   fprintf(fp_dataOut, "%ld\t%s\t%0.2lf\t%0.2lf\t%0.2lf\t%d\t%ld\t%ld\t%ld\t%ld\t\t%d\t\n", totalTimeElapsed_sec, GetCurTimeStamp(), cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack, ((procData->ld_num_threads)-1), FDCount);
                   RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %0.2lf %0.2lf %0.2lf %d %ld %ld %ld %ld %d \n", __func__, __LINE__, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack, ((procData->ld_num_threads)-1), FDCount);
                }
            }
            }
            fclose(f);
       }

       if(prevData[procData->d_pid].status)
       {
            if(telemetryOnly == false)
            {
            if(PROC_MASK)
            {
                fprintf(fp_dataOut, "%ld\t%s", totalTimeElapsed_sec, GetCurTimeStamp());
                if(PROC_MASK & CPU_MASK)
                {
                   fprintf(fp_dataOut, "\t%0.2lf\t%0.2lf\t%0.2lf\t%d", cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise);
                   RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %0.2lf %0.2lf %0.2lf %d \n", __func__, __LINE__, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise);
                }
                if(PROC_MASK & MEMORY_MASK)
                {
                   fprintf(fp_dataOut, "\t%ld\t%ld\t%ld", vmSize, vmRSS, vmStack);
                   RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %ld %ld %ld \n", __func__, __LINE__, vmSize, vmRSS, vmStack);
                }
                if(PROC_MASK & THREADCOUNT_MASK)
                {
                   fprintf(fp_dataOut, "\t%ld\t", ((procData->ld_num_threads)-1));
                   RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %ld \n", __func__, __LINE__, ((procData->ld_num_threads)-1));
                }
                if(PROC_MASK & FDCOUNT_MASK)
                {
                   fprintf(fp_dataOut, "\t%d\t", FDCount);
                   RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %d \n", __func__, __LINE__, FDCount);
                }
                fprintf(fp_dataOut, "\n");
            }
            else
            {
               fprintf(fp_dataOut, "%ld\t%s\t%0.2lf\t%0.2lf\t%0.2lf\t%d\t%ld\t%ld\t%ld\t%ld\t\t%d\t\n", totalTimeElapsed_sec, GetCurTimeStamp(), cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack, ((procData->ld_num_threads)-1), FDCount);
               RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %0.2lf %0.2lf %0.2lf %d %ld %ld %ld %ld %d \n", __func__, __LINE__, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack, ((procData->ld_num_threads)-1), FDCount);
            }
       }
       }
           fclose(fp_dataOut);

       #if defined  PROCANALYZER_BROADBAND
       //Telemetry event send
       if(ppid == 0)
       {
           char eventName[32]={'\0'};
           char telemetry_buf[128] = {'\0'};
           snprintf(eventName, sizeof(eventName), "CPA_INFO_%s", procData->s_comm);
           snprintf(telemetry_buf, sizeof(telemetry_buf), "%ld,%0.2lf,%d,%d", vmRSS, cpuUseRaise, FDCount, procData->ld_num_threads-1);
           RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Event : %s, Value : %s\n", eventName, telemetry_buf);
           t2_event_s(eventName, telemetry_buf);
       }
       #endif
    }
    else
    {
        if(telemetryOnly == false)
        {
           RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","%s(%d): ERROR opening the file: %s\n", __func__, __LINE__, tmp_string);
        }
        return 0;
    }

    prevData[procData->d_pid].status = 1;
    return 1;
}

static volatile bool need_exit = false;

/*
 * @brief Connect to netlink
 * returns netlink socket, or -1 on error
 */
static int netlink_connect()
{
    int rc;
    int netlink_sock;
    struct sockaddr_nl nl_sockaddr;

    netlink_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (netlink_sock == -1) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Failed to create socket. Error code = %d \n", errno);
        return -1;
    }

    nl_sockaddr.nl_family = AF_NETLINK;
    nl_sockaddr.nl_groups = CN_IDX_PROC;
    nl_sockaddr.nl_pid = getpid();

    rc = bind(netlink_sock, (struct sockaddr *)&nl_sockaddr, sizeof(nl_sockaddr));
    if (rc == -1) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","bind operation failed, closing the socket\n");
        close(netlink_sock);
        return -1;
    }

    return netlink_sock;
}

/*
 * @brief subscribe for netlink process events by setting it to multicast listen mode
 */
static int subscribe_proc_events(int netlink_sock, bool enable)
{
    int retCode;
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_header;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_message;
            enum proc_cn_mcast_op cn_mcast;
        };
    }
    netlink_msg;

    memset(&netlink_msg, 0, sizeof(netlink_msg));
    netlink_msg.nl_header.nlmsg_len = sizeof(netlink_msg);
    netlink_msg.nl_header.nlmsg_pid = getpid();
    netlink_msg.nl_header.nlmsg_type = NLMSG_DONE;

    netlink_msg.cn_message.id.idx = CN_IDX_PROC;
    netlink_msg.cn_message.id.val = CN_VAL_PROC;
    netlink_msg.cn_message.len = sizeof(enum proc_cn_mcast_op);

    netlink_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

    retCode = send(netlink_sock, &netlink_msg, sizeof(netlink_msg), 0);
    if (retCode == -1) {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","netlink send  failed\n");
        return -1;
    }

    return 0;
}

/*
 * @brief handle net link process events and identify newly forked or executing process
 */

static int handle_process_events(int netlink_sock)
{
    RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CPUPROCANALYZER"," handle proc ev entered \n");
    int retCode;
    stProcData dProcData;

    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_header;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_message;
            struct proc_event process_event;
        };
    }
    netlink_msg;

    while (!need_exit) {
        retCode = recv(netlink_sock, &netlink_msg, sizeof(netlink_msg), 0);
        memset(&dProcData,0,sizeof(dProcData));
        if (retCode == 0) {
            /* shutdown? */
            return 0;
        } else if (retCode == -1) {
            if (errno == EINTR) continue;
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","netlink recv failed \n");
            return -1;
        }
        switch (netlink_msg.process_event.what) {
        case PROC_EVENT_NONE:
            RDK_LOG(RDK_LOG_DEBUG,"LOG.RDK.CPUPROCANALYZER","Setting Multicast listen success.\n");
            break;
        // Received a fork event from netlink socket
        case PROC_EVENT_FORK:
            RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER","Forked new proc : form parent TID=%d PID=%d => child TID=%d PID=%d\n",
                    netlink_msg.process_event.event_data.fork.parent_pid,
                    netlink_msg.process_event.event_data.fork.parent_tgid,
                    netlink_msg.process_event.event_data.fork.child_pid,
                    netlink_msg.process_event.event_data.fork.child_tgid);
            dProcData.d_pid = netlink_msg.process_event.event_data.fork.child_pid;
            pthread_mutex_lock(&mtx);
            LogProcData(&dProcData,0,"",1);
            pthread_mutex_unlock(&mtx);
            break;
       // Received an exec event from netlink socket
        case PROC_EVENT_EXEC:
            RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER","Exec Proc: TID=%d PID=%d\n",
                    netlink_msg.process_event.event_data.exec.process_pid,
                    netlink_msg.process_event.event_data.exec.process_tgid);
            break;
        default:
            RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER","unhandled nelink proc event\n");
            break;
        }
    }
    return 0;
}

/*
*
* Thread for handling dynamic process based on netlink process events
*
*/
static void *handle_proc_ev_thread(void *arg )
{
    int netlink_sock = netlink_connect();
    if(netlink_sock == -1)
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Failed to create netlink socket \n");
        return NULL;
    }
    int rc = subscribe_proc_events(netlink_sock, true);
    if(rc == -1)
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER"," Setting of event listen failed \n");
        close(netlink_sock);
        return NULL;
    }
    rc = handle_process_events(netlink_sock);
    if(rc == -1)
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Subscription request failed\n");
    }
    return NULL;
}


int checkifdigit(char* ch,int size)
{
        int retid = 1;
        int i;
        for(i=0;i<size;i++)
        {
        if(isdigit(*ch))
        {
        continue;}
        else
        {
          retid = 0;
          break;
        }
        ch=ch+1;
        }
        return retid;
}

bool CheckMemLimit (int itr, unsigned long memLimit)
{
    char buf1[BUFF_SIZE_64]={0};
    static int prev_mem=0;
    int size_diff=0;
    int cur_mem=0;
    char tmp_filename[128]={0};
    sprintf(tmp_filename,"du -s %s | awk '{print$1}'",outputDir.c_str());

    FILE * fp = popen(tmp_filename, "r");

    if (fp == 0)
    {
       RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): popen failed.Failed to read tmp details.\n", __func__, __LINE__);
       return false;
    }

    memset(buf1, 0, BUFF_SIZE_64);
    fgets(buf1, BUFF_SIZE_64, fp);
    pclose(fp);

    cur_mem=atoi(buf1);
    if (itr!=2)
    {
      size_diff=(cur_mem - prev_mem);
    }
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Mem Limits curr : %d | prev : %d | diff : %d\n", cur_mem, prev_mem, size_diff);
    prev_mem=cur_mem;

    if ((cur_mem + size_diff) >= memLimit)
        return false;
    return true;
}

/**
 * @brief Main Function.
 *
 * Fetches information such as Load Average value, Used Memory value and Idle Percent value for all the Processes in the list from /opt/logs/cpuprocanalyzer/loadandmem.data.
 */
int main(int argc, char** argv)
{

    const char* pDebugConfig = NULL;
    const char* pEnvConfig = NULL;
    const char* DEBUG_ACTUAL_PATH = "/etc/debug.ini";
    const char* ENV_ACTUAL_PATH = "/etc/procanalyzerconfig.ini";
    const char* ENV_OVERRIDE_PATH = CONFIG_PATH"/procanalyzerconfig.ini";
    const char* DEBUG_OVERRIDE_PATH = CONFIG_PATH"/debug.ini";
    const char* PROCESSES_LIST_PATH = CONFIG_PATH"/processes.list";
    int iteration = 0;
    int pCount = 0;

    int returncode = EXIT_SUCCESS;
    string dynamicFolder;
    int returnid;
    pthread_t process_handler_tid;
    #ifndef PROCANALYZER_EXTENDER
    if (access(DEBUG_OVERRIDE_PATH, F_OK) != -1)
        pDebugConfig = DEBUG_OVERRIDE_PATH;
    else
        pDebugConfig = DEBUG_ACTUAL_PATH;

    rdk_logger_init(pDebugConfig);
    #endif
    if (access(ENV_OVERRIDE_PATH, F_OK) != -1)
        pEnvConfig = ENV_OVERRIDE_PATH;
    else
        pEnvConfig = ENV_ACTUAL_PATH;

    #if defined  PROCANALYZER_BROADBAND
    t2_init("cpuprocanalyzer");
    #endif

    char tmp_string[256]={0};
    unsigned long timeToRun_sec ;
    unsigned int sleepInterval_ms;
    unsigned long memoryLimit;
    bool monitorAllProcess = false;
    bool enableDynamic = true;
    bool telemetryOnly = false;
    string grepProcesses;
    int env;
    char* ptr;
    char res[64];
    string ps_filename = outputDir + "selectedps.list";
    memset(res,0,64);
    ((env=read_config_param("FEATURE.CPUPROCANALYZER.SleepInterval",pEnvConfig,res)) == 0) ? sleepInterval_ms = SLEEP_SECS*1000 : sleepInterval_ms = strtol(res,&ptr,10)*1000;
    memset(res,0,64);
    ((env=read_config_param("FEATURE.CPUPROCANALYZER.TimeToRun",pEnvConfig,res)) == 0) ? timeToRun_sec = TIME_TO_RUN_SECS : timeToRun_sec = strtol(res,&ptr,10);
    memset(res,0,64);
    ((env=read_config_param("FEATURE.CPUPROCANALYZER.DynamicProcess",pEnvConfig,res)) == 0) ? enableDynamic = DEFAULT_DYNAMIC : enableDynamic = res[0] - '0';
    memset(res,0,64);
    ((env=read_config_param("FEATURE.CPUPROCANALYZER.MonitorAllProcess",pEnvConfig,res)) == 0) ? monitorAllProcess = MONITOR_ALL_PROC_DEF : monitorAllProcess = res[0] - '0';
    memset(res,0,64);
    ((env=read_config_param("FEATURE.CPUPROCANALYZER.TelemetryOnly",pEnvConfig,res)) == 0) ? telemetryOnly = TELEMETRY_ONLY_DEF : telemetryOnly = res[0] - '0';
    memset(res,0,64);
    ((env=read_config_param("FEATURE.CPUPROCANALYZER.MemoryLimit",pEnvConfig,res)) == 0) ? memoryLimit = DEFAULT_MEM_THRESHOLD : memoryLimit = strtol(res,&ptr,10);
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","%s(%d):\nSleep Interval(secs): %d\nTime To Run(secs): %ld\n", __func__, __LINE__, sleepInterval_ms/1000, timeToRun_sec);
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Monitor All Process = %d, MemLimit = %ld\nDynamic = %d\ntelemetryOnly = %d\n", monitorAllProcess, memoryLimit, enableDynamic, telemetryOnly);

        #if defined  PROCANALYZER_BROADBAND
        memset(res,0,64);
        if((read_config_param("FEATURE.CPUPROCANALYZER.SystemStatsToMonitor",pEnvConfig,res)) == 0)
        {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","SYSStats config absent, res value = %s\n", res);
            SYS_MASK = SYS_DEF_MASK;
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","SYSStats config absent, set to DEF MASK = %d\n", SYS_MASK);
        }
        else
        {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","SYSStats config present, res value = %s\n", res);
            SYS_MASK = SetMask(res);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","SYS MASK is set\n");
        }

        memset(res,0,64);
        if((read_config_param("FEATURE.CPUPROCANALYZER.ProcessStatsToMonitor",pEnvConfig,res)) == 0)
        {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","PROCStats config absent, res value = %s\n", res);
            PROC_MASK = PROC_DEF_MASK;
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","PROCStats Config absent, set to DEF MASK = %d\n", PROC_MASK);
        }
        else
        {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","PROCStats config present, res value = %s\n", res);
            PROC_MASK = SetMask(res);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","PROC MASK is set\n");
        }
        #endif

        //Clearing the contents of the output directory before running the tool
        sprintf(tmp_string, "cd %s && rm -rf *", outputDir.c_str());
        system(tmp_string);
        RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CPUPROCANALYZER","Create this directory always: %s\n", tmp_string);
        mkdir(outputDir.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
        if(telemetryOnly == false)
        {
            mkdir(outputDynamicDir.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
            RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CPUPROCANALYZER","Creating if telemetryOnly false, outputDynamicDir.c_str()\n");
        }
        ReadDeviceName();
        CreateExclusionList();

        #if defined  PROCANALYZER_BROADBAND
        if(telemetryOnly == false)
        {
            ReadRFCJson();
        }
        #endif

    char tmpstring[1024],tmpstring1[128];
    char buf1[64],buf2[64];
    int val;

    unsigned long long startTime_sec = time(NULL);
    unsigned long long currentTime_sec = time(NULL);
    unsigned long timeElapsed_sec = 0;
    bool terminate = false;
    stProcData procData, threadData;

    unsigned int cliCount = 0;
    float loadAvg;
    unsigned long usedMemory;
    float idlePercent;
    bool firstIter = true;
    bool monitorSysLevel = false;
    int FDCountSystem=0;


    if(enableDynamic) {
        returncode = pthread_create(&process_handler_tid,NULL,handle_proc_ev_thread,NULL);

        if (returncode == -1) {
            returncode = EXIT_FAILURE;
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Dynamic process thread creation failed \n");
        }
    }

    while (iteration++, !terminate && CheckMemLimit (iteration,memoryLimit))/*&& (iteration < ITERATION_THRESHOLD) && CheckMemLimit (iteration))*/
    {
        //Capture Load Average value
        FILE *fp;
        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Inside while.....\n");
        if(telemetryOnly == false)
        {
        if(SYS_MASK)
        {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","SYS MASK NOT NULL, %d\n", SYS_MASK);
            if(SYS_MASK & CPU_MASK)
            {
                GetIdlePercent(&idlePercent);
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Idle: %0.2f\n", __func__, __LINE__, idlePercent);
            }
            if(SYS_MASK & MEMORY_MASK)
            {
                GetUsedMemory(&usedMemory);
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Mem: %ld\n", __func__, __LINE__, usedMemory);
            }
            if(SYS_MASK & FDCOUNT_MASK)
            {
                GetFDCountSystem(&FDCountSystem);
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): FDCountSystem: %d\n", __func__, __LINE__, FDCountSystem);
            }
            if(SYS_MASK & LOADAVG_MASK)
            {
                GetLoadAverage(&loadAvg);
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Load: %0.2f\n", __func__, __LINE__, loadAvg);
            }
            if(SYS_MASK & CLICOUNT_MASK)
            {
                GetNumOfClientsConnected(&cliCount);
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ClientCount: %d\n", __func__, __LINE__, cliCount);
            }
        }
        else
        {
            RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CPUPROCANALYZER","DEFAULT MASK is set\n");
            GetIdlePercent(&idlePercent);
            GetLoadAverage(&loadAvg);
            GetUsedMemory(&usedMemory);
            GetFDCountSystem(&FDCountSystem);
            GetNumOfClientsConnected(&cliCount);
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Load: %0.2f Mem: %ld \
                                        Idle: %0.2f FDCountSystem: %d ClientCount = %d\n",
                                        __func__, __LINE__, loadAvg, usedMemory, idlePercent,
                                        FDCountSystem, cliCount);
        }

        fp = fopen(LOG_PATH"/cpuprocanalyzer/loadandmem.data", "a+");

        if(fp)
        {
            if(firstIter)
            {
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","First Iter = %d\n", firstIter);
                if(SYS_MASK)
                {
                    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","SYS_MASK NOT NULL, write data to loadandmem file\n");
                    fprintf(fp, "TimeStamp\t\t");
                    if(SYS_MASK & LOADAVG_MASK)
                    {
                        fprintf(fp, "LoadAvg\t");
                    }
                    if(SYS_MASK & MEMORY_MASK)
                    {
                        fprintf(fp, "UsedMem\t");
                    }
                    if(SYS_MASK & CPU_MASK)
                    {
                        fprintf(fp, "Idle%\t");
                    }
                    if(SYS_MASK & FDCOUNT_MASK)
                    {
                        fprintf(fp, "FDCountSystem\t");
                    }
                    if(SYS_MASK & CLICOUNT_MASK)
                    {
                        fprintf(fp, "ClientCount\t");
                    }
                    fprintf(fp, "\n");
                }
                else
                {
                     fprintf(fp, "TimeStamp\t\tLoadAvg\tUsedMem\tIdle%\tFDCountSystem\tClientCount\n");
                }

                firstIter = false;
            }

            if(SYS_MASK)
            {
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Start printing values to loadandmem file\n");
                fprintf(fp, "%s", GetCurTimeStamp());
                if(SYS_MASK & LOADAVG_MASK)
                {
                    fprintf(fp, "\t%0.2f", loadAvg);
                }
                if(SYS_MASK & MEMORY_MASK)
                {
                   fprintf(fp, "\t%ld", usedMemory);
                }
                if(SYS_MASK & CPU_MASK)
                {
                   fprintf(fp, "\t%0.2f", idlePercent);
                }
                if(SYS_MASK & FDCOUNT_MASK)
                {
                    fprintf(fp, "\t%d", FDCountSystem);
                }
                if(SYS_MASK & CLICOUNT_MASK)
                {
                    fprintf(fp, "\t\t%d", cliCount);
                }
                fprintf(fp, "\n");
            }
            else
            {
                fprintf(fp, "%s\t%0.2f\t%ld\t%0.2f\t%d\t\t%d\n", GetCurTimeStamp(),
                             loadAvg, usedMemory, idlePercent, FDCountSystem, cliCount);
            }
            fclose(fp);
        }
        else
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d):ERROR opening loadandmem.data file\n", __func__, __LINE__);
        }

        if(monitorAllProcess == true)
        {
           char tstr[100];
           memset (tstr, 0, sizeof(tstr));
           RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER","Monitoring all process...\n");
           sprintf (tstr, "ps -w > %s", ps_filename.c_str());
           if (system(tstr) == -1)
           {
              RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): FAILED ps command\n", __func__, __LINE__);
              RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Monitoring at system level only...\n", __func__, __LINE__);
              continue;
           }
        }
        else if(access(PROCESSES_LIST_PATH, F_OK) != -1)
        {
           FILE* ptr1=fopen(ps_filename.c_str(), "w");

           if (ptr1)
           {
           //Read from /opt/processes.list or /nvram/processes.list
              FILE* fp;
              fp = fopen(PROCESSES_LIST_PATH, "r");
              if (fp)
              {
                 RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Read from process list and populate Selected ps file\n");
                 memset(buf1,0,64);
                 memset(buf2,0,64);
                 while (fgets(buf1,64,fp)!= NULL)
                 {
                    sprintf(tmpstring1,"pidof %s",buf1);
                    FILE *ptr2 = popen(tmpstring1,"r");
                    if (ptr2)
                    {
                        while (fscanf(ptr2,"%s",buf2) != EOF)
                        {
                            fprintf(ptr1,"%s\n",buf2);
                            memset(buf2,0,64);
                        }
                        pclose(ptr2);
                    } else {
                        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Popen failure for process, %s\n", __func__, __LINE__, buf1);
                    }
                    memset(buf1,0,64);
                 }
                 fclose (fp);
              } else {
                  RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Process file open failure\n", __func__, __LINE__);
              }
              fclose(ptr1);
           }
           else
           {
              if(telemetryOnly == false)
              {
                  RDK_LOG(RDK_LOG_ERROR,"LOG.RDK.CPUPROCANALYZER"," Error opening the file: %s",ps_filename.c_str());
                  continue;
              }
           }
        }
        else
        {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Monitoring at system level only...\n", __func__, __LINE__);
            monitorSysLevel = true;
        }

        if(!monitorSysLevel)
        {
           fp_selectedps = fopen(ps_filename.c_str(), "r");
           if(fp_selectedps)
           {
               while(!feof(fp_selectedps))
               {
                   fgets(tmp_string, LINE_LIMIT, fp_selectedps);
                   if(ferror(fp_selectedps) || feof(fp_selectedps))
                       break;
                   sscanf(tmp_string, "%d", &procData.d_pid);
                   pthread_mutex_lock(&mtx);
                   RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Calling LogProcData\n");
                   if(!LogProcData(&procData,0,"",0,telemetryOnly))
                   {
                       pthread_mutex_unlock(&mtx);
                       continue;
                   }
                   pCount++;
                   pthread_mutex_unlock(&mtx);
                   if(telemetryOnly == false)
                   {
                   sprintf(tmp_string, "ls /proc/%d/task/ > %s%d_%s/threads.list", procData.d_pid, outputDir.c_str(), procData.d_pid, procData.s_comm);
                   system(tmp_string);
                   sprintf(tmp_string, "%s%d_%s/threads.list", outputDir.c_str(), procData.d_pid, procData.s_comm);
                   FILE* fp_thread_list = fopen(tmp_string, "r");
                   if(fp_thread_list)
                   {
                       while(!feof(fp_thread_list))
                       {
                           fgets(tmp_string, LINE_LIMIT, fp_thread_list);
                           if( ferror(fp_thread_list) || feof(fp_thread_list) )
                               break;
                           sscanf(tmp_string, "%d", &threadData.d_pid);
                           if(threadData.d_pid != procData.d_pid)
                           {
                               pthread_mutex_lock(&mtx);
                               LogProcData(&threadData, procData.d_pid, procData.s_comm);
                               pthread_mutex_unlock(&mtx);
                           }
                       }
                       fclose(fp_thread_list);
                   }
                   memset(tmp_string,0,sizeof(tmp_string));
                   }
               }
               fclose(fp_selectedps);
               RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","MAP erase logic\n");
               map<unsigned int, struct stPrevData>::iterator it = prevData.begin();
               while(it != prevData.end())
               {
                   stPrevData preData = it->second;
                   if(preData.status == 0)
                   {
                       RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","%s(%d): ***Removing %d from map***\n", __func__, __LINE__, it->first);
                       prevData.erase(it);
                   }
                   else
                       preData.status = 0;
                   ++it;
               }
           }
           else
           {
               if(telemetryOnly == false)
               {
                   RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","%s(%d): ERROR opening the file: %s\n", __func__, __LINE__, ps_filename.c_str());
               }
           }

           RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER", "[%d]No. of process monitored : %d\n\n", iteration, pCount);
           pCount = 0;
        }

        if(timeToRun_sec)
        {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Check time to run...\n");
            currentTime_sec = time(NULL);
            timeElapsed_sec = difftime(currentTime_sec, startTime_sec);
            if(timeElapsed_sec >= timeToRun_sec)
            {
               RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Time elapsed, Terminate = true\n");
               terminate = true;
            }
        }

        if(!terminate)
        {
            RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Terminate NOT TRUE, sleep\n");
            usleep(sleepInterval_ms*1000);
            totalTimeElapsed_sec += sleepInterval_ms/1000;
        }
    }

    #if defined PROCANALYZER_BROADBAND
    RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER", "Triggering RunCPUProcAnalyzer.sh stop...\n");
    if (telemetryOnly == false)
    {
         system("/lib/rdk/RunCPUProcAnalyzer.sh stop 1");
    }
    else
    {
         system("/lib/rdk/RunCPUProcAnalyzer.sh stop 0");
    }

    #elif  defined PROCANALYZER_EXTENDER
    RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER", "Stop CPU Proc Analyzer ...\n");
    system("/usr/opensync/scripts/run_procanalyzer.sh stop");
    #endif

    sleep(5);
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","%s(%d): ***Exiting the application***\n", __func__, __LINE__);
    return 0;
}

#ifndef PROCANALYZER_EXTENDER
const char *rdk_logger_module_fetch(void)
{
    return "LOG.RDK.CPUPROCANALYZER";
}
#endif
/**
 * @} // End of Doxygen
 */

