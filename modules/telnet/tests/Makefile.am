LIBS     = @MODULES_LIBS@
LDADD = ../libtelnet.la -lboost_unit_test_framework
AM_CPPFLAGS = @MODULES_CPPFLAGS@ -DBOOST_TEST_DYN_LINK=1

check_PROGRAMS = test_telnet
check_SCRIPTS =

AM_DEFAULT_SOURCE_EXT = .cc

TESTS = $(check_PROGRAMS) $(check_SCRIPTS)

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)

test_telnet_LDADD = ../libtelnet.la @ZORP_LIBS@ -lboost_unit_test_framework

EXTRA_DIST = $(check_SCRIPTS)
