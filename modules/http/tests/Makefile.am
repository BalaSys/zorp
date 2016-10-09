LIBS=@MODULETESTS_LIBS@
AM_CPPFLAGS = @MODULES_CPPFLAGS@ -DBOOST_TEST_DYN_LINK=1

check_PROGRAMS = http_parse_url http_canon_url

LDADD = ../httpmisc.lo -lboost_unit_test_framework

http_parse_url_SOURCES = http_parse_url.cc

http_canon_url_SOURCES = http_canon_url.cc

TESTS = http_parse_url http_canon_url
