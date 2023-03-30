AM_CFLAGS = -I$(top_srcdir)/include $(GLOBAL_CFLAGS) $(openssl_CFLAGS) $(libgeneral_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS) $(GLOBAL_CXXFLAGS)
AM_LDFLAGS = $(openssl_LIBS) $(libgeneral_LIBS)

lib_LTLIBRARIES = libimg2tool.la
bin_PROGRAMS = img2tool

libimg2tool_la_CFLAGS = $(AM_CFLAGS)
libimg2tool_la_CXXFLAGS = $(AM_CXXFLAGS)
libimg2tool_la_LDFLAGS = $(AM_LDFLAGS)
libimg2tool_la_SOURCES = img2tool.cpp \
						 crc32.c

img2tool_CFLAGS = $(AM_CFLAGS)
img2tool_CXXFLAGS = $(AM_CXXFLAGS)
img2tool_LDFLAGS = $(AM_LDFLAGS)
img2tool_LDADD = libimg2tool.la
img2tool_SOURCES = 	main.cpp
