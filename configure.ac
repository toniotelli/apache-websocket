# Setup.
AC_INIT([mod_websocket], [0.1.0])
AC_CONFIG_SRCDIR([mod_websocket.c])

# Declare optional user-defined variables.
AC_ARG_VAR([APACHE_BINDIR],
           [the directory containing the binaries for your httpd installation
            (if you have a non-standard installation path, setting this value is
            easier than setting APXS, APACHECTL, and HTTPD separately)])

AC_ARG_VAR([APXS], [the path to the Apache apxs@<:@2@:>@ tool])

AC_ARG_VAR([APACHECTL], [the path to the apachectl tool])

AC_ARG_VAR([HTTPD], [the path to the httpd executable])

AC_ARG_VAR([LIBTOOL], [the path to libtool])

AC_ARG_VAR([TEST_MPM], [the name of the MPM to use during testing ('event',
                        'worker', etc.), or 'builtin' to use a statically
                        compiled MPM])

# Sanity-check user-defined variables.
AS_IF([test \( "x$APACHE_BINDIR" != "x" \) -a \( ! -d "$APACHE_BINDIR" \)],
      [AC_MSG_WARN([APACHE_BINDIR value $APACHE_BINDIR does not appear to be a valid directory])])

AS_IF([test \( "x$APXS" != "x" \) -a \( ! -x "$APXS" \)],
      [AC_MSG_WARN([APXS value $APXS does not appear to be an executable file])])

AS_IF([test \( "x$APACHECTL" != "x" \) -a \( ! -x "$APACHECTL" \)],
      [AC_MSG_WARN([APACHECTL value $APACHECTL does not appear to be an executable file])])

AS_IF([test \( "x$HTTPD" != "x" \) -a \( ! -x "$HTTPD" \)],
      [AC_MSG_WARN([HTTPD value $HTTPD does not appear to be an executable file])])

# Find the programs.
AS_IF([test "x$APACHE_BINDIR" != "x"], [SEARCHPATH=$APACHE_BINDIR:$PATH],
      [SEARCHPATH=$PATH])

AC_PATH_PROGS([APXS], [apxs apxs2], [no], [$SEARCHPATH])
AS_IF([test "x$APXS" = "xno"],
      [AC_MSG_ERROR([could not find the apxs tool])])

AC_PATH_PROG([APACHECTL], [apachectl], [no], [$SEARCHPATH])
AS_IF([test "x$APACHECTL" = "xno"],
      [AC_MSG_ERROR([could not find the apachectl tool])])

AC_PATH_PROGS([HTTPD], [httpd apache2], [no], [$SEARCHPATH])
AS_IF([test "x$HTTPD" = "xno"],
      [AC_MSG_ERROR([could not find the Apache httpd executable])])

AC_PATH_PROG([LIBTOOL], [libtool], [no])
AS_IF([test "x$LIBTOOL" = "xno"],
      [AC_MSG_ERROR([could not find an installed libtool])])

# Figure out where the installed httpd keeps its modules.
AC_MSG_CHECKING([for the httpd modules directory])
system_modules_dir=`"$APXS" -q libexecdir`
AC_MSG_RESULT([$system_modules_dir])

AC_SUBST(system_modules_dir)

# Try to figure out which MPM we should use.
AC_MSG_CHECKING([for an installed MPM module to load during test])

AS_IF([test "x$TEST_MPM" = "x"], [
  # No TEST_MPM was supplied on the command line.
  mpm_comment="# "
  TEST_MPM=builtin

  module=`find $system_modules_dir -name 'mod_mpm_*.so' -print -quit`
  AS_IF([test "x$module" != "x"], [
    mpm_comment=
    module=${module##*mod_mpm_}
    TEST_MPM=${module%.so}
  ])
], [
  # The user supplied an explicit TEST_MPM.
  AS_IF([test "x$TEST_MPM" = "xbuiltin"],
        [mpm_comment="# "],
        [mpm_comment=])
])
AC_MSG_RESULT([$TEST_MPM])
AC_SUBST(mpm_comment)

# Check to make sure the MPM exists.
module_path=$system_modules_dir/mod_mpm_$TEST_MPM.so
AS_IF([test "x$TEST_MPM" != "xbuiltin" -a ! -f "$module_path"],
      [AC_MSG_WARN([TEST_MPM value $TEST_MPM does not appear to refer to an installed module ($module_path)])])

# Figure out which version of httpd is installed.
AC_MSG_CHECKING([the httpd version])
httpd_version=`"$HTTPD" -v | sed -n -e "s/^.*Apache\/\(2\.@<:@0-9@:>@\+\).*$/\1/p"`
AS_IF([test "x$httpd_version" = "x2.2"],
      [
        # Enable the 2.2 config.
        conf_22=
        conf_24="# "
      ],
      [
        # Enable the 2.4 config.
        conf_22="# "
        conf_24=

        AS_IF([test "x$httpd_version" != "x2.4"],
              [ httpd_version="unknown (assuming 2.4)" ])
      ])
AC_MSG_RESULT([$httpd_version])

AC_SUBST(conf_22)
AC_SUBST(conf_24)

# Define the template-generated files.
AC_CONFIG_FILES([
  Makefile
  test/httpd/test.conf
])

# Output everything.
AC_OUTPUT
