AC_PREREQ([2.69])
AC_INIT([ell],[0.79])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(build-aux)

AC_REQUIRE_AUX_FILE([tap-driver.sh])

AM_INIT_AUTOMAKE([foreign subdir-objects color-tests silent-rules
					tar-pax no-dist-gzip dist-xz])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

COMPILER_FLAGS

AC_LANG([C])

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_CC_ASAN
AC_PROG_CC_LSAN
AC_PROG_CC_UBSAN
AC_PROG_INSTALL
AC_PROG_AWK

LT_PREREQ(2.2)
LT_INIT([disable-static])

AC_ARG_ENABLE(optimization, AS_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -O0"
	fi
])

AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(pie, AS_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(asan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(asan, AS_HELP_STRING([--enable-asan],
			[enable linking with address sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_asan__init}" = "yes" &&
				test "${ac_cv_prog_cc_asan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=address";
		LDFLAGS="$LDFLAGS -fsanitize=address"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(lsan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(lsan, AS_HELP_STRING([--enable-lsan],
			[enable linking with leak sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_lsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_lsan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=leak";
		LDFLAGS="$LDFLAGS -fsanitize=leak"
	fi
])

save_LIBS=$LIBS
AC_CHECK_LIB(ubsan, _init)
LIBS=$save_LIBS

AC_ARG_ENABLE(ubsan, AS_HELP_STRING([--enable-ubsan],
			[enable linking with undefined behavior sanitizer]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_lib_ubsan__init}" = "yes" &&
				test "${ac_cv_prog_cc_ubsan}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=undefined";
		LDFLAGS="$LDFLAGS -fsanitize=undefined"
	fi
])

AC_CHECK_FUNCS(explicit_bzero)
AC_CHECK_FUNCS(rawmemchr)

AC_CHECK_FUNC(signalfd, dummy=yes,
			AC_MSG_ERROR(signalfd support is required))

AC_CHECK_FUNC(timerfd_create, dummy=yes,
			AC_MSG_ERROR(timerfd support is required))

AC_CHECK_FUNC(epoll_create, dummy=yes,
			AC_MSG_ERROR(epoll support is required))

AC_CHECK_HEADERS(linux/types.h linux/if_alg.h)

AC_ARG_ENABLE(glib, AS_HELP_STRING([--enable-glib],
				[enable ell/glib main loop example]),
					[enable_glib=${enableval}])
if (test "${enable_glib}" = "yes"); then
	PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.32, dummy=yes,
				AC_MSG_ERROR(GLib >= 2.32 is required))
	AC_SUBST(GLIB_CFLAGS)
	AC_SUBST(GLIB_LIBS)
fi
AM_CONDITIONAL(GLIB, test "${enable_glib}" = "yes")

if (test "$USE_MAINTAINER_MODE" = "yes"); then
	AC_CHECK_PROG(have_openssl, [openssl], [yes], [no])
	AC_CHECK_PROG(have_xxd, [xxd], [yes], [no])
fi

AC_ARG_ENABLE(tests, AS_HELP_STRING([--disable-tests],
				[disable unit tests compilation]),
					[enable_tests=${enableval}])
AM_CONDITIONAL(TESTS, test "${enable_tests}" != "no")

AC_ARG_ENABLE(tools, AS_HELP_STRING([--disable-tools],
				[disable extra tools compilation]),
					[enable_tools=${enableval}])
AM_CONDITIONAL(TOOLS, test "${enable_tools}" != "no")

AC_ARG_ENABLE(examples, AS_HELP_STRING([--disable-examples],
				[disable code examples compilation]),
					[enable_examples=${enableval}])
AM_CONDITIONAL(EXAMPLES, test "${enable_examples}" != "no")

AM_CONDITIONAL(CERT_TESTS, test "${have_openssl}" = "yes")
AM_CONDITIONAL(OPENSSL_PROVIDER, test "${have_openssl}" = "yes" &&
				openssl list -providers > /dev/null 2>&1 )
AC_SUBST(OPENSSL_PROVIDER)

AC_CONFIG_FILES(Makefile ell/ell.pc)

AC_OUTPUT
