LIBS = @MODULETESTS_LIBS@ @DEPS_LIBS@
LDADD = ../libsmtp.la -lboost_unit_test_framework
AM_CPPFLAGS = @MODULES_CPPFLAGS@ -DBOOST_TEST_DYN_LINK=1

AM_DEFAULT_SOURCE_EXT = .cc

check_PROGRAMS = smtp_sanitize_addr smtp_parse smtp_request
TESTS = smtp_sanitize_addr smtp_parse smtp_request
