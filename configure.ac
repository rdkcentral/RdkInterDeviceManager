############################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2022 Sky
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################
#############################################################################
#
# Copyright 2022 RDK Management
# Licensed under the Apache License, Version 2.0
#############################################################################

#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#

AC_PREREQ([2.65])
AC_INIT([tr181], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
LT_INIT

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

GTEST_ENABLE_FLAG = ""

AC_ARG_ENABLE([gtestapp],
             AS_HELP_STRING([--enable-gtestapp],[enable Gtest support (default is no)]),
             [
               case "${enableval}" in
                yes) GTEST_SUPPORT_ENABLED=true
                     GTEST_ENABLE_FLAG="-DGTEST_ENABLE"
                     m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile])]);;
                no) GTEST_SUPPORT_ENABLED=false AC_MSG_ERROR([Gtest support is disabled]);;
                 *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]);;
               esac
             ],
             [echo "Gtestapp is disabled"])
AM_CONDITIONAL([WITH_GTEST_SUPPORT], [test x$GTEST_SUPPORT_ENABLED = xtrue])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

# Specify ccsp cpu arch

AC_ARG_WITH([ccsp-arch],
[AC_HELP_STRING([--with-ccsp-arch={arm,atom,pc,mips}],
                [specify the ccsp board CPU platform])],
[case x"$withval" in
   xarm)
     CCSP_ARCH=arm
     ;;
   xatom)
     CCSP_ARCH=atom
     ;;
   xpc)
     CCSP_ARCH=pc
     ;;
   xmips)
     CCSP_ARCH=mips
     ;;
   *)
     AC_MSG_ERROR([$withval is an invalid option to --with-ccsp-arch])
     ;;
 esac],
[CCSP_ARCH=''])
if test x"${CCSP_ARCH}" != x; then
  AC_DEFINE_UNQUOTED(CCSP_ARCH, "$CCSP_ARCH",
                     [The board CPU architecture])
fi

AM_CONDITIONAL(CCSP_ARCH_ARM, test "x$CCSP_ARCH" = xarm)
AM_CONDITIONAL(CCSP_ARCH_ATOM, test "x$CCSP_ARCH" = xatom)
AM_CONDITIONAL(CCSP_ARCH_PC, test "x$CCSP_ARCH" = xpc)
AM_CONDITIONAL(CCSP_ARCH_MIPS, test "x$CCSP_ARCH" = xmips)

# Specify ccsp platform (device)

AC_ARG_WITH([ccsp-platform],
[AC_HELP_STRING([--with-ccsp-platform={intel_usg,pc,bcm}],
                [specify the ccsp platform])],
[case x"$withval" in
   xintel_usg)
     CCSP_PLATFORM=intel_usg
     ;;
   xpc)
     CCSP_PLATFORM=pc
     ;;
   xbcm)
     CCSP_PLATFORM=bcm
     ;;
   *)
     AC_MSG_ERROR([$withval is an invalid option to --with-ccsp-platform])
     ;;
 esac],
[CCSP_PLATFORM=''])
if test x"${CCSP_PLATFORM}" != x; then
  AC_DEFINE_UNQUOTED(CCSP_PLATFORM, "$CCSP_PLATFORM",
                     [The CCSP platform device])
fi

SYSTEMD_CFLAGS=" "
SYSTEMD_LDFLAGS=" "
AC_ARG_ENABLE([notify],
    AS_HELP_STRING([--enable-notify],[enable systemd notify]),
    [
      case "${enableval}" in
          yes) SYSTEMD_CFLAGS="-DENABLE_SD_NOTIFY"
                SYSTEMD_LDFLAGS="-lsystemd" ;;
           no) AC_MSG_ERROR([systemd notify is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-notify ]) ;;
           esac
           ],
      [echo "headless build is enable"])

NONROOT_CFLAGS=" "
AC_ARG_ENABLE([dropearly],
        AS_HELP_STRING([--enable-dropearly],[enable dropearly]),
        [
          case "${enableval}" in
           yes) NONROOT_CFLAGS="-DDROP_ROOT_EARLY" ;;
            no) AC_MSG_NOTICE([dropearly is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-dropearly ]) ;;
           esac
           ],
         [echo "dropearly is enable"])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST(CCSP_ARCH)
AC_SUBST(SYSTEMD_CFLAGS)
AC_SUBST(SYSTEMD_LDFLAGS)
AC_SUBST(NONROOT_CFLAGS)

AC_CONFIG_FILES(
  source/TR-181/middle_layer_src/Makefile
  source/TR-181/Makefile
  source/Makefile
  source/InterDeviceManager/Makefile
  Makefile
)
AC_SUBST(GTEST_ENABLE_FLAG)
AC_OUTPUT
