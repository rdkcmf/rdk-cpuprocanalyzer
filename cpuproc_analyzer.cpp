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
#include "rdk_debug.h"
#include <bits/stdc++.h>
using namespace std;

extern "C" {
    // C Function call
#include <cimplog/cimplog.h>
#define LOGGING_MODULE "CPUPROCANALYZER"
const char *rdk_logger_module_fetch(void);
}


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

#define LINE_LIMIT 1000         //!< FILE LINE LIMIT
#define NAME_LIMIT 20           //!< FILE NAME LIMIT
#define SLEEP_SECS 60         //!< Sleep Interval for the data collection
#define TIME_TO_RUN_SECS 0      //!< 0 means, tool should run until it is killed manually
#define BUFF_SIZE_64  64
#define BUFF_SIZE_16  16
#define MEM_THRESHOLD 1536  //Max filesize limit
#define ITERATION_THRESHOLD 25  //Max number of runs

#define PROC_EVENT_NONE  0x00000000
#define PROC_EVENT_FORK  0x00000001
#define PROC_EVENT_EXEC  0x00000002

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

#ifdef PROCANALYZER_BROADBAND
 #define CONFIG_PATH "/nvram"
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

char* removespaces(char *str);
int read_config_param(const char *paramname,const char *filename,char *res)
{
   FILE *fp = fopen(filename,"r");
        char tmp_string[128];
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
                  strncpy(res,pch,BUFF_SIZE_16);
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
    pclose(fp);
    return strValue;
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

    #if PROCANALYZER_BROADBAND
    memset (mfgname, 0, BUFF_SIZE_16);
    GetValuesFromFile ("/etc/device.properties", "MANUFACTURE=", mfgname, sizeof(mfgname));

    if (strncmp(mfgname,"UNKNOWN",strlen(mfgname))) {
        GetValuesFromFile ("/etc/device.properties", "MFG_NAME=", mfgname, sizeof(mfgname));
    }

    memset(devicename,0,BUFF_SIZE_16);
    GetValuesFromFile ("/etc/device.properties", "BOX_TYPE=", devicename, sizeof(devicename));

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
        exclude_process_list.push_back(string(buf1));
        memset(buf1,0,sizeof(buf1));
    }
    pclose(fp);
    exclude_process_list.push_back("cpuprocanalyzer");
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
void LogProcData(stProcData* procData, int ppid=0, char* pname="",int is_dynamic=0)
{
    char tmp_string[1024];
    unsigned long vmStack=0;
    unsigned long vmSize=0;
    unsigned long vmRSS=0;
    char char_array[512];
    int return_val;
    string searchstr = ".sh";
    string word,s;
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
       RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Failed to open proc/stat/ file of the process \n");
    }

    // excluding processes of least concern

    if(ppid!= 0)
    {
         for(it=exclude_process_list.begin();it!=exclude_process_list.end();it++)
        {
            s= *it;
            if(strncmp(procData->s_comm,s.c_str(),strlen(procData->s_comm)) == 0)
            {
                return;
            }
        }
    }
    //process
    else
    {
        if(strlen(procData->s_comm) == 0)
        {
            return;
        }
        else
        {
            for(it=exclude_process_list.begin();it!=exclude_process_list.end();it++)
            {
                s = *it;
                if(strncmp(procData->s_comm,s.c_str(),strlen(procData->s_comm)) == 0)
                {
                    return;
                }
            }
        }
    }

    (ppid != 0) ? sprintf(tmp_string, "/proc/%d/task/%d/status", ppid, procData->d_pid)
    : sprintf(tmp_string, "/proc/%d/status", procData->d_pid);
    GetMemParams(tmp_string, &vmStack, "VmStk:");
    GetMemParams(tmp_string, &vmSize, "VmSize:");
    GetMemParams(tmp_string, &vmRSS, "VmRSS:");

    //Check for shell scripts
    if(strstr(procData->s_comm,"sh") || strstr(procData->s_comm,"bash"))
    {
        sprintf(tmp_string, "/proc/%d/cmdline", procData->d_pid);
        FILE* fp_cmd = fopen(tmp_string, "r");
        if(fp_cmd)
        {
            fscanf(fp_cmd, "%s", tmp_string);
            fclose(fp_cmd);
            RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CPUPROCANALYZER","cmd line :%s\n",tmp_string);
            stringstream ss(tmp_string);
            while(ss >> word)
            {
                if( strstr(word.c_str(),searchstr.c_str()))
                {
                    strncpy(char_array,word.c_str(),sizeof(char_array));
                    return_val = strncmp(char_array,"sh",strlen(char_array));
                    if(return_val == 0)
                    {
                        return;
                    }
                    return_val =strncmp(char_array,"cpuprocanalyzer",strlen(char_array));
                    if(return_val == 0)
                    {
                        return;
                    }

                    int i=0;
                    while(char_array[i] != '\0')
                    {
                        if(char_array[i]== '/')
                        {
                            char_array[i]= '_';
                        }
                        i++;
                    }
                    strncpy(procData->s_comm,char_array,sizeof(procData->s_comm)-1);
                }
                else
                {
                    return;
                }
            }
            return_val = strncmp(tmp_string,"sh",strlen(tmp_string));
            if(return_val == 0)
            {
                return;
            }

        }
        else
        {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER"," Failed to open cmdline of shell script\n");
            return ;
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
                fprintf(fp_dataOut, "Command-Line : %s\n\n", tmp_string);
                fprintf(fp_dataOut, "El-Time\tTimeStamp\t\tCPU%\tCPU%:U\tCPU%:S\tMjrFlts\tVmSize\tVmRSS\tVmStk\n");
            }
        }

       if(is_dynamic ==1 )
        {
            sprintf(tmp_string, "/proc/%d/stat", procData->d_pid);
            FILE *f = fopen(tmp_string, "r");
            if ( f == 0 ) {
                RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Failed to open /proc/stat/ of dynamic process\n" );
                return ;
            }
            else {
        fscanf(f, " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld", &procData->c_state, &procData->d_ppid, &procData->d_pgrp, &procData->d_session, &procData->d_tty_nr, &procData->d_tpgid, &procData->u_flags, &procData->lu_minflt, &procData->lu_cminflt, &procData->lu_majflt, &procData->lu_cmajflt, &procData->lu_utime, &procData->lu_stime, &procData->ld_cutime, &procData->ld_cstime, &procData->ld_priority, &procData->ld_nice, &procData->ld_num_threads, &procData->ld_itrealvalue, &procData->llu_starttime, &procData->lu_vsize, &procData->ld_rss, &procData->lu_rsslim, &procData->lu_startcode, &procData->lu_endcode, &procData->lu_startstack, &procData->lu_kstkesp, &procData->lu_kstkeip, &procData->lu_signal, &procData->lu_blocked, &procData->lu_sigignore, &procData->lu_sigcatch, &procData->lu_wchan, &procData->lu_nswap, &procData->lu_cnswap, &procData->d_exit_signal, &procData->d_processor, &procData->u_rt_priority, &procData->u_policy, &procData->llu_delayacct_blkio_ticks, &procData->lu_guest_time,&procData->ld_cguest_time);

                cpuUseRaise= procData->lu_utime + procData->lu_stime;
               cpuUseRaise_User = procData->lu_utime;
                cpuUseRaise_System = procData->lu_stime;

                fprintf(fp_dataOut, "%ld\t%s\t%0.2lf\t%0.2lf\t%0.2lf\t%d\t%ld\t%ld\t%ld\t\n", totalTimeElapsed_sec, GetCurTimeStamp(), cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack);

                RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %0.2lf %0.2lf %0.2lf %d %ld %ld %ld \n", __func__, __LINE__, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack);
            }
           fclose(f);
       }

        if(prevData[procData->d_pid].status)
        {
            fprintf(fp_dataOut, "%ld\t%s\t%0.2lf\t%0.2lf\t%0.2lf\t%d\t%ld\t%ld\t%ld\t\n", totalTimeElapsed_sec, GetCurTimeStamp(), cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack);
           RDK_LOG(RDK_LOG_TRACE1, "LOG.RDK.CPUPROCANALYZER","%s(%d): %0.2lf %0.2lf %0.2lf %d %ld %ld %ld \n", __func__, __LINE__, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack);
        }
        fclose(fp_dataOut);
    }
    else
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","%s(%d): ERROR opening the file: %s\n", __func__, __LINE__, tmp_string);
    }

    prevData[procData->d_pid].status = 1;
 
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
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Failed to create socket \n");
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

bool CheckMemLimit (int itr)
{
    char buf1[BUFF_SIZE_64]={"\0"};
    static int prev_mem=0;
    int size_diff=0;
    int cur_mem=0;
    FILE * fp = popen("du -s /tmp/cpuprocanalyzer | awk '{print$1}'", "r");

    if (fp == 0) 
    {
       RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): popen failed.Failed to read tmp details.\n", __func__, __LINE__);
       return FALSE;
    }
  
    memset(buf1, 0, BUFF_SIZE_64);
    fgets(buf1, BUFF_SIZE_64, fp);
    pclose(fp);

    cur_mem=atoi(buf1);
    if (itr==1)
    {
      prev_mem=cur_mem;
    }
    if (itr)
    {
      size_diff=(cur_mem-prev_mem);
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","Mem Limits curr : %d | prev : %d | diff : %d\n", cur_mem, prev_mem, size_diff);

    if ((cur_mem+size_diff)>=MEM_THRESHOLD)
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
    int iteration = -1;

    int returncode = EXIT_SUCCESS;
    string dynamicFolder;
    int returnid;
    pthread_t process_handler_tid;

    if (access(DEBUG_OVERRIDE_PATH, F_OK) != -1)
        pDebugConfig = DEBUG_OVERRIDE_PATH;
    else
        pDebugConfig = DEBUG_ACTUAL_PATH;

    rdk_logger_init(pDebugConfig);

    if (access(ENV_OVERRIDE_PATH, F_OK) != -1)
        pEnvConfig = ENV_OVERRIDE_PATH;
    else
        pEnvConfig = ENV_ACTUAL_PATH;

    char tmp_string[100];
    unsigned long timeToRun_sec ;
    unsigned int sleepInterval_ms;
    bool enableDynamic = false;
    string grepProcesses;
    int env;
    char* ptr;
    char res[32];
    string ps_filename = outputDir + "selectedps.list";
   memset(res,0,32);
   ((env=read_config_param("FEATURE.CPUPROCANALYZER.SLEEP.SECS",pEnvConfig,res)) == 0) ? sleepInterval_ms = SLEEP_SECS*1000 : sleepInterval_ms =strtol(res,&ptr,10)*1000;
   memset(res,0,32);
  ((env=read_config_param("FEATURE.CPUPROCANALYZER.TIMETORUN.SECS",pEnvConfig,res)) == 0) ? timeToRun_sec = TIME_TO_RUN_SECS : timeToRun_sec = strtol(res,&ptr,10);
   RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","%s(%d):\nSleep Interval(secs): %d\nTime To Run(secs): %ld\n", __func__, __LINE__, sleepInterval_ms/1000, timeToRun_sec);
  //Clearing the contents of the output directory before running the tool
    sprintf(tmp_string, "cd %s && rm -rf *", outputDir.c_str());
    system(tmp_string);
    mkdir(outputDir.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    mkdir(outputDynamicDir.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
    ReadDeviceName();
    CreateExclusionList();


  char tmpstring[1024],tmpstring1[128];
  char buf1[64],buf2[8];
  int val;

  FILE*ptr1=fopen(ps_filename.c_str(), "w");

  if(ptr1){
  if (access(PROCESSES_LIST_PATH, F_OK) != -1)
  {
    //Read from /opt/processes.list or /nvram/processes.list
        FILE* fp;
        fp = fopen(PROCESSES_LIST_PATH, "r");
        if(fp)
        {
            memset(buf1,0,64);
            memset(buf2,0,8);
            while(fgets(buf1,64,fp)!= NULL)
            {
               sprintf(tmpstring1,"pidof %s",buf1);
               FILE *ptr2 = popen(tmpstring1,"r");
               fgets(buf2,8,ptr2);
               fprintf(ptr1,"%s\n",buf2);
               memset(buf1,0,64);
               memset(buf2,0,8);
            }
         }
    }
  else
   {
     RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER","Process list not specified. Please add required processes to be monitored...\n");
   }
    fclose(ptr1);
   }
  
   else
  {
  RDK_LOG(RDK_LOG_ERROR,"LOG.RDK.CPUPROCANALYZER"," Error opening the file: %s",ps_filename.c_str());
  }
    unsigned long long startTime_sec = time(NULL);
    unsigned long long currentTime_sec = time(NULL);
    unsigned long timeElapsed_sec = 0;
    bool terminate = false;
    stProcData procData, threadData;

    float loadAvg;
    unsigned long usedMemory;
    float idlePercent;
    bool firstIter = true;

    if(enableDynamic) {
        returncode =pthread_create(&process_handler_tid,NULL,handle_proc_ev_thread,NULL);

        if (returncode == -1) {
            returncode = EXIT_FAILURE;
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","Dynamic process thread creation failed \n");
        }
    }
    
    while (iteration++, !terminate && (iteration < ITERATION_THRESHOLD) && CheckMemLimit (iteration))
    {
        //Capture Load Average value
        FILE *fp;

        GetIdlePercent(&idlePercent);
        GetLoadAverage(&loadAvg);
        GetUsedMemory(&usedMemory);

        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Load: %0.2f Mem: %ld Idle: %0.2f\n", __func__, __LINE__, loadAvg, usedMemory, idlePercent);
        
        fp = fopen(LOG_PATH"/cpuprocanalyzer/loadandmem.data", "a+");

        if(fp)
        {
            if(firstIter)
            {
                fprintf(fp, "TimeStamp\t\tLoadAvg\tUsedMem\tIdle%\n");
                firstIter = false;
            }
            fprintf(fp, "%s\t%0.2f\t%ld\t%0.2f\n", GetCurTimeStamp(), loadAvg, usedMemory, idlePercent);
            fclose(fp);
        }
        else
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d):ERROR opening loadandmem.data file\n", __func__, __LINE__);

    if (access(PROCESSES_LIST_PATH, F_OK) != -1)
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
                LogProcData(&procData);
                pthread_mutex_unlock(&mtx);
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
                        {   pthread_mutex_lock(&mtx);
                            LogProcData(&threadData, procData.d_pid, procData.s_comm);
                            pthread_mutex_unlock(&mtx);
                        }
                    }
                    fclose(fp_thread_list);
                }
                memset(tmp_string,0,sizeof(tmp_string));
            }
            fclose(fp_selectedps);
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
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER","%s(%d): ERROR opening the file: %s\n", __func__, __LINE__, ps_filename.c_str());
        }
     }
   else
     {
        RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER","Process list not specified. Monitoring only basic statistics...\n");
     }
    
        if(timeToRun_sec)
        {
            currentTime_sec = time(NULL);
            timeElapsed_sec = difftime(currentTime_sec, startTime_sec);
            if(timeElapsed_sec >= timeToRun_sec)
                terminate = true;
        }

        usleep(sleepInterval_ms*1000);
        totalTimeElapsed_sec += sleepInterval_ms/1000;
    }
    #ifdef PROCANALYZER_BROADBAND
    RDK_LOG(RDK_LOG_INFO,"LOG.RDK.CPUPROCANALYZER", "Triggering RunCPUProcAnalyzer.sh stop...\n");
    system("/lib/rdk/RunCPUProcAnalyzer.sh stop");
    #endif
    sleep(5);
    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER","%s(%d): ***Exiting the application***\n", __func__, __LINE__);
    return 0;
}

const char *rdk_logger_module_fetch(void)
{
    return "LOG.RDK.CPUPROCANALYZER";
}

/**
 * @} // End of Doxygen
 */

