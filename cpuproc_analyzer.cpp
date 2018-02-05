/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
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
#include "rdk_debug.h"
#include "rmf_osal_util.h"
#include "rmf_osal_init.h"

using namespace std;

#define LINE_LIMIT 1000         //FILE LINE LIMIT
#define NAME_LIMIT 20           //FILE NAME LIMIT
#define SLEEP_SECS 60           //Sleep Interval for the data collection
#define TIME_TO_RUN_SECS 0      //0 means, tool should run until it is killed manually

struct stPrevData
{
    unsigned int prevTotalMajFaultsRaised;
    unsigned long prevTotalUsedCPUTime;
    unsigned long prevUserUsedCPUTime;
    unsigned long prevSystemUsedCPUTime;
    double prevTotalCPUTime_usec;
    bool status;
}; 

struct stCPUInfo
{
    unsigned long long total;
    unsigned long long idle;
}prevCPUInfo;

map<unsigned int, struct stPrevData> prevData;

FILE* fp_selectedps = NULL;
FILE* fp_stat = NULL;
FILE* fp_dataOut = NULL;

string outputDir = "/opt/logs/cpuprocanalyzer/";
long totalTimeElapsed_sec = 0;
char strTime[80];

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

    void ReadProcStat(FILE* fp_procStat)
    {
        fscanf(fp_procStat, "%d", &d_pid);
        ReadProcessName(fp_procStat, s_comm);
        fscanf(fp_procStat, " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld", &c_state, &d_ppid, &d_pgrp, &d_session, &d_tty_nr, &d_tpgid, &u_flags, &lu_minflt, &lu_cminflt, &lu_majflt, &lu_cmajflt, &lu_utime, &lu_stime, &ld_cutime, &ld_cstime, &ld_priority, &ld_nice, &ld_num_threads, &ld_itrealvalue, &llu_starttime, &lu_vsize, &ld_rss, &lu_rsslim, &lu_startcode, &lu_endcode, &lu_startstack, &lu_kstkesp, &lu_kstkeip, &lu_signal, &lu_blocked, &lu_sigignore, &lu_sigcatch, &lu_wchan, &lu_nswap, &lu_cnswap, &d_exit_signal, &d_processor, &u_rt_priority, &u_policy, &llu_delayacct_blkio_ticks, &lu_guest_time, &ld_cguest_time);

        RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld\n", __func__, __LINE__, d_pid, s_comm, c_state, d_ppid, d_pgrp, d_session, d_tty_nr, d_tpgid, u_flags, lu_minflt, lu_cminflt, lu_majflt, lu_cmajflt, lu_utime, lu_stime, ld_cutime, ld_cstime, ld_priority, ld_nice, ld_num_threads, ld_itrealvalue, llu_starttime, lu_vsize, ld_rss, lu_rsslim, lu_startcode, lu_endcode, lu_startstack, lu_kstkesp, lu_kstkeip, lu_signal, lu_blocked, lu_sigignore, lu_sigcatch, lu_wchan, lu_nswap, lu_cnswap, d_exit_signal, d_processor, u_rt_priority, u_policy, llu_delayacct_blkio_ticks, lu_guest_time, ld_cguest_time);
    }

    void OutFilename(char* outProcFilename)
    {
        sprintf(outProcFilename, "%s/%d_%s/%d_%s.data", outputDir.c_str(), d_pid, s_comm, d_pid, s_comm);
    }

    void OutFilename(char* outProcFilename, int ppid, char* pname)
    {
        sprintf(outProcFilename, "%s/%d_%s/threads/%d_%s.data", outputDir.c_str(), ppid, pname, d_pid, s_comm);
    }

    void GetTotalUsedTime(unsigned long* outTotalTime)
    {
        *outTotalTime = lu_utime + lu_stime;// + (ld_cutime + ld_cstime);
    }

    void GetUserUsedTime(unsigned long* outUserTime)
    {
        *outUserTime = lu_utime;
    }

    void GetSystemUsedTime(unsigned long* outSystemTime)
    {
        *outSystemTime = lu_stime;
    }

    void GetTotalMjrFlts(unsigned int* outTotalMjrFlts)
    {
        *outTotalMjrFlts = lu_majflt;// + lu_cmajflt;
    }
};

char* GetCurTimeStamp()
{
    time_t rawtime;
    tm* timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(strTime,80,"%Y-%m-%d %H:%M:%S",timeinfo);
    return strTime;
}

void GetMemParams(char* filename, unsigned long* memParam, char* param)
{
    char line[64]={'\0'};
    string str;
    FILE* fp_status = fopen(filename, "r");
    if(fp_status)
    {
        while(!feof(fp_status))
        {
            fgets(line, sizeof(line), fp_status);
            if(strncmp(line, param, strlen(param)) == 0)
            {
                stringstream ss(line);
                for (int idx=0; idx<2; idx++)
                    ss >> str;
                *memParam = atoi(str.c_str());
                break;
            }
        }
        fclose(fp_status);
    }
    else
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ERROR opening the file: %s\n", __func__, __LINE__, filename);
    }
}

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

void GetUsedMemory(unsigned long* mem)
{
    //Capture Used Memory value
    char line[64]={'\0'};
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
        }
        *mem = memTotal - memFree;
        fclose(fp);
    }
    else
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ERROR opening the file: /proc/meminfo\n", __func__, __LINE__);
    }
}

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

void LogProcData(stProcData* procData, int ppid=0, char* pname="")
{
    //prevData[procData->d_pid].status = 1;
    char tmp_string[1000];
    unsigned long vmStack=0;
    unsigned long vmSize=0;
    unsigned long vmRSS=0;

    (ppid != 0) ? sprintf(tmp_string, "/proc/%d/task/%d/status", ppid, procData->d_pid)
                : sprintf(tmp_string, "/proc/%d/status", procData->d_pid);
    GetMemParams(tmp_string, &vmStack, "VmStk:");
    GetMemParams(tmp_string, &vmSize, "VmSize:");
    GetMemParams(tmp_string, &vmRSS, "VmRSS:");

    (ppid != 0) ? sprintf(tmp_string, "/proc/%d/task/%d/stat", ppid, procData->d_pid) 
                : sprintf(tmp_string, "/proc/%d/stat", procData->d_pid);

    fp_stat = fopen(tmp_string, "r");
    if(fp_stat)
    {
        procData->ReadProcStat(fp_stat);
        fclose(fp_stat);
        (ppid != 0) ? sprintf(tmp_string, "%s/%d_%s/threads/", outputDir.c_str(), ppid, pname)
                    : sprintf(tmp_string, "%s/%d_%s", outputDir.c_str(), procData->d_pid, procData->s_comm);
        mkdir(tmp_string, S_IRWXU | S_IRWXG | S_IRWXO);
        (ppid != 0) ? procData->OutFilename(tmp_string, ppid, pname) : procData->OutFilename(tmp_string);
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
                RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %d %0.2lf %0.2lf %0.2lf %ld %ld %0.2lf %0.2lf\n", __func__, __LINE__, procData->d_pid, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, currentTotalUsedCPUTime, prevData[procData->d_pid].prevTotalUsedCPUTime, sysconf(_SC_CLK_TCK), timeDiff_usec);
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

            if(prevData[procData->d_pid].status)
            {
                fprintf(fp_dataOut, "%ld\t%s\t%0.2lf\t%0.2lf\t%0.2lf\t%d\t%ld\t%ld\t%ld\t\n", totalTimeElapsed_sec, GetCurTimeStamp(), cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack);

                RDK_LOG(RDK_LOG_DEBUG, "LOG.RDK.CPUPROCANALYZER", "%s(%d): %0.2lf %0.2lf %0.2lf %d %ld %ld %ld \n", __func__, __LINE__, cpuUseRaise, cpuUseRaise_User, cpuUseRaise_System, majorFaultsRaise, vmSize, vmRSS, vmStack);
            }
            fclose(fp_dataOut);
        }
        else
        {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ERROR opening the file: %s\n", __func__, __LINE__, tmp_string);
        }
    }
    else
    {
        RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ERROR opening the file: %s\n", __func__, __LINE__, tmp_string);
    }
    prevData[procData->d_pid].status = 1;
}

int main(int argc, char** argv)
{
    const char* pDebugConfig = NULL;
    const char* pEnvConfig = NULL;
    const char* DEBUG_ACTUAL_PATH = "/etc/debug.ini";
    const char* DEBUG_OVERRIDE_PATH = "/opt/debug.ini";
    const char* ENV_ACTUAL_PATH = "/etc/rmfconfig.ini";
    const char* ENV_OVERRIDE_PATH = "/opt/rmfconfig.ini";
    const char* PROCESSES_LIST_PATH = "/opt/processes.list";

    if (access(DEBUG_OVERRIDE_PATH, F_OK) != -1)
        pDebugConfig = DEBUG_OVERRIDE_PATH;
    else
        pDebugConfig = DEBUG_ACTUAL_PATH;

    if (access(ENV_OVERRIDE_PATH, F_OK) != -1)
        pEnvConfig = ENV_OVERRIDE_PATH;
    else
        pEnvConfig = ENV_ACTUAL_PATH;

    rmf_osal_init(pEnvConfig, pDebugConfig);

    char tmp_string[100];
    unsigned long timeToRun_sec = 0;
    unsigned int sleepInterval_ms = 0;
    string grepProcesses;
    const char* env;
    ((env=rmf_osal_envGet("FEATURE.CPUPROCANALYZER.SLEEP.SECS")) == NULL) ? sleepInterval_ms = SLEEP_SECS*1000 : sleepInterval_ms = atoi(env)*1000;
    ((env=rmf_osal_envGet("FEATURE.CPUPROCANALYZER.TIMETORUN.SECS")) == NULL) ? timeToRun_sec = TIME_TO_RUN_SECS : timeToRun_sec = atol(env);

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d):\nSleep Interval(secs): %d\nTime To Run(secs): %ld\n", __func__, __LINE__, sleepInterval_ms/1000, timeToRun_sec);

    if (access(PROCESSES_LIST_PATH, F_OK) != -1)
    {
        //Read from /opt/processes.list
        FILE* fp;
        fp = fopen(PROCESSES_LIST_PATH, "r");
        if(fp)
        {
            while(!feof(fp))
            {
                fscanf(fp, "%s", tmp_string);
                if( grepProcesses.size() > 0 )
                    grepProcesses += "\\|";
                grepProcesses += tmp_string;
            }
            fclose(fp);
        }
    }

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): grepProcesses: %s\n", __func__, __LINE__, grepProcesses.c_str());

    mkdir(outputDir.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);

    if( grepProcesses.size() == 0 )
        RDK_LOG(RDK_LOG_WARN, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Process list not specified. Tool will read data from all processes\n", __func__, __LINE__);
    string ps_filename = outputDir + "selectedps.list";
    grepProcesses = "ps -ae | grep -i \"" + grepProcesses + "\" > " + ps_filename;

    //Clearing the contents of the output directory before running the tool
    sprintf(tmp_string, "cd %s; rm -rf *", outputDir.c_str());
    system(tmp_string);

    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Analyzing linux ps and proc...\n", __func__, __LINE__);

    unsigned long long startTime_sec = time(NULL);
    unsigned long long currentTime_sec = time(NULL);
    unsigned long timeElapsed_sec = 0;
    bool terminate = false;
    stProcData procData, threadData;
    
    float loadAvg;
    unsigned long usedMemory;
    float idlePercent;
    bool firstIter = true;

    while(!terminate)
    {
        //Capture Load Average value
        FILE *fp;

        GetIdlePercent(&idlePercent);
        GetLoadAverage(&loadAvg);
        GetUsedMemory(&usedMemory);

        RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): Load: %0.2f Mem: %ld Idle: %0.2f\n", __func__, __LINE__, loadAvg, usedMemory, idlePercent);

        fp = fopen("/opt/logs/cpuprocanalyzer/loadandmem.data", "a+");
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

        if(system(grepProcesses.c_str()) == -1)
        {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): FAILED ps command\n", __func__, __LINE__);
            continue;
        }

        fp_selectedps = fopen(ps_filename.c_str(), "r");
        if(fp_selectedps)
        {
            while(!feof(fp_selectedps))
            {
                fgets(tmp_string, LINE_LIMIT, fp_selectedps);
                if(ferror(fp_selectedps) || feof(fp_selectedps))
                    break;
                sscanf(tmp_string, "%d", &procData.d_pid);

                LogProcData(&procData);

                sprintf(tmp_string, "ls /proc/%d/task/ > %s/%d_%s/threads.list", procData.d_pid, outputDir.c_str(), procData.d_pid, procData.s_comm);
                system(tmp_string);
                sprintf(tmp_string, "%s/%d_%s/threads.list", outputDir.c_str(), procData.d_pid, procData.s_comm);
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
                            LogProcData(&threadData, procData.d_pid, procData.s_comm);
                        }
                    }
                    fclose(fp_thread_list);
                }
            }
            fclose(fp_selectedps);
            map<unsigned int, struct stPrevData>::iterator it = prevData.begin();
            while(it != prevData.end())
	    {
		stPrevData preData = it->second;
		if(preData.status == 0)
                {
                    RDK_LOG(RDK_LOG_INFO, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ***Removing %d from map***\n", __func__, __LINE__, it->first);
                    prevData.erase(it);
                }
                else
                    preData.status = 0;
		++it;
	    }
        }
        else
        {
            RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ERROR opening the file: %s\n", __func__, __LINE__, ps_filename.c_str());
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
    RDK_LOG(RDK_LOG_ERROR, "LOG.RDK.CPUPROCANALYZER", "%s(%d): ***Exiting the application***\n", __func__, __LINE__);
    return 0;
}
