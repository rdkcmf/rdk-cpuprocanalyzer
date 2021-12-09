########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([cpuprocanalyzer], [1.0], [SaiSuneel_Marri@comcast.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([cfg])
AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 1.9])

LT_INIT
AC_LANG([C++])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],
[AM_DEFAULT_VERBOSITY=1
AC_SUBST(AM_DEFAULT_VERBOSITY)])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h unistd.h])
#PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.24.0])

# broadband
PROCANALYZER_BROADBAND=" "
AC_ARG_ENABLE([procanalyzer-broadband],
        AS_HELP_STRING([--enable-procanalyzer-broadband],[This will decide broadband or video device]),
        [
          case "${enableval}" in
           yes) PROCANALYZER_BROADBAND=true ;; 
           no) PROCANALYZER_BROADBAND=false 
                echo "Video Device ";;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-procanalyzer-broadband]) ;;
           esac
           ],
         [echo " broadband device"])
AM_CONDITIONAL([PROCANALYZER_BROADBAND], [test x$PROCANALYZER_BROADBAND = xtrue])

AC_SUBST(PROCANALYZER_BROADBAND)

# Extender
PROCANALYZER_EXTENDER=" "
AC_ARG_ENABLE([procanalyzer-extender],
        AS_HELP_STRING([--enable-procanalyzer-extender],[This will decide broadband or pod device]),
        [
          case "${enableval}" in
           yes) PROCANALYZER_EXTENDER=true ;;
           no) PROCANALYZER_EXTENDER=false
                echo "Extender device ";;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-procanalyzer-extender]) ;;
           esac
           ],
         [echo " extender device"])
AM_CONDITIONAL([PROCANALYZER_EXTENDER], [test x$PROCANALYZER_EXTENDER = xtrue])

AC_SUBST(PROCANALYZER_EXTENDER)


AC_CONFIG_FILES([Makefile])

AC_OUTPUT
