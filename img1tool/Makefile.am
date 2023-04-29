AM_CFLAGS = -I$(top_srcdir)/include $(GLOBAL_CFLAGS) $(openssl_CFLAGS) $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(openssl_LIBS) $(libgeneral_LIBS)

lib_LTLIBRARIES = libimg1tool.la
bin_PROGRAMS = img1tool

BUILT_SOURCES = pwnage2.crt.h

libimg1tool_la_CFLAGS = $(AM_CFLAGS)
libimg1tool_la_CXXFLAGS = $(AM_CXXFLAGS)
libimg1tool_la_LDFLAGS = $(AM_LDFLAGS)
libimg1tool_la_SOURCES = img1tool.cpp \
						 crc32.c

img1tool_CFLAGS = $(AM_CFLAGS)
img1tool_CXXFLAGS = $(AM_CXXFLAGS)
img1tool_LDFLAGS = $(AM_LDFLAGS)
img1tool_LDADD = libimg1tool.la
img1tool_SOURCES = 	main.cpp

$(BUILT_SOURCES): %.crt.h: %.crt
	python3 ${srcdir}/../makeShellcodeHeader.py $<

CLEANFILES = pwnage2.crt.h