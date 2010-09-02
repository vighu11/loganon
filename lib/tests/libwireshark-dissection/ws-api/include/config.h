/* $Id: config.h.win32 20646 2007-01-31 05:26:41Z ulfl $ */
/* config.h.win32 Generated manually. :-) */
/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */

/* Generated Bison and Flex files test whether __STDC__ is defined
   in order to check whether to use ANSI C features such as "const".

   GCC defines it as 1 even if extensions that render the implementation
   non-conformant are enabled; Sun's C compiler (and, I think, other
   AT&T-derived C compilers) define it as 0 if extensions that render
   the implementation non-conformant are enabled; Microsoft Visual C++
   6.0 doesn't define it at all if extensions that render the implementation
   non-conformant are enabled.

   We define it as 0 here, so that those generated files will use
   those features (and thus not get type warnings when compiled with
   MSVC++). */
#ifndef __STDC__
#define __STDC__ 0
#endif

/* Use Unicode in Windows runtime functions. */
#define UNICODE 1
#define _UNICODE 1

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if your processor stores words with the most significant
   byte first (like Motorola and SPARC, unlike Intel and VAX).  */
/* #undef WORDS_BIGENDIAN */

/* Define if lex declares yytext as a char * by default, not a char[].  */
#define YYTEXT_POINTER 1

#define HAVE_PLUGINS		1
#define PLUGINS_NEED_ADDRESS_TABLE 1

/* Plugins can also use the import library of libwireshark.dll instead
   of the old API. In that case we undefine PLUGINS_NEED_ADDRESS_TABLE 
   for the plugin. We don't undefine PLUGINS_NEED_ADDRESS_TABLE globally.
   Thus Wireshark will be still able to load plugins using the old API. 
   The macro HAVE_WIN32_LIBWIRESHARK_LIB has to be defined in plugin's 
   makefile.nmake. A template is available in doc/README.plugins */
#ifdef HAVE_WIN32_LIBWIRESHARK_LIB
#undef PLUGINS_NEED_ADDRESS_TABLE
#endif

/* #undef HAVE_SA_LEN */

/* #undef NEED_STRERROR_H */

#define NEED_MKSTEMP 1

#define HAVE_LIBPCAP 1

#define HAVE_PCAP_FINDALLDEVS 1
#define HAVE_PCAP_DATALINK_NAME_TO_VAL 1
#define HAVE_PCAP_DATALINK_VAL_TO_NAME 1
#define WPCAP_CONSTIFIED 1
#define HAVE_LIBWIRESHARKDLL 1

#define HAVE_AIRPCAP 1
#define HAVE_AIRPDCAP 1

/* availability of pcap_freecode() is handled at runtime */
#define HAVE_PCAP_FREECODE 1

/* define macro for importing variables from an dll 
 * it depends on HAVE_LIBWIRESHARK and _NEED_VAR_IMPORT_
 */
#if defined (_NEED_VAR_IMPORT_) && defined (HAVE_LIBWIRESHARKDLL)
#  define WS_VAR_IMPORT __declspec(dllimport) extern
#else
#  define WS_VAR_IMPORT extern
#endif

#define HAVE_NET_SNMP 1

/* Define if you have the gethostbyname2 function.  */
/* #undef HAVE_GETHOSTBYNAME2 */

/* Define if you have the getprotobynumber function.  */
/* #undef HAVE_GETPROTOBYNUMBER */

/* Define if you have the <arpa/inet.h> header file.  */
/* #undef HAVE_ARPA_INET_H */

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <iconv.h> header file.  */
/* #undef HAVE_ICONV */

/* Define if you have the <netdb.h> header file.  */
/* #undef HAVE_NETDB_H */

/* Define if you have the <netinet/in.h> header file.  */
/* #define HAVE_NETINET_IN_H 1 */

/* Define if you have the <snmp/snmp.h> header file.  */
/* #undef HAVE_SNMP_SNMP_H */

/* Define if you have the <snmp/version.h> header file.  */
/* #undef HAVE_SNMP_VERSION_H */

/* Define if you have the <stdarg.h> header file.  */
#define HAVE_STDARG_H 1

/* Define if you have the <stddef.h> header file.  */
/* #undef HAVE_STDDEF_H */

/* Define if you have the <sys/ioctl.h> header file.  */
/* #undef HAVE_SYS_IOCTL_H */

/* Define if you have the <sys/socket.h> header file.  */
/* #undef HAVE_SYS_SOCKET_H */

/* Define if you have the <sys/sockio.h> header file.  */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1

/* Define if you have the <sys/time.h> header file.  */
/* #define HAVE_SYS_TIME_H 1 */

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <sys/wait.h> header file.  */
/* #undef HAVE_SYS_WAIT_H */

/* Define if you have the <unistd.h> header file.  */
/* #define HAVE_UNISTD_H 1 */

/* Define if <inttypes.h> defines PRI[doxu]64 macros */
/* #define INTTYPES_H_DEFINES_FORMATS */

/* Format for printing 64-bit signed decimal numbers */
#ifndef PRId64
#ifdef _MSC_EXTENSIONS
#define PRId64  "I64d"
#else /* _MSC_EXTENSIONS */
#define PRId64  "lld"
#endif /* _MSC_EXTENSIONS */
#endif /* PRId64 */

/* Format for printing 64-bit unsigned octal numbers */
#ifndef PRIo64
#ifdef _MSC_EXTENSIONS
#define PRIo64  "I64o"
#else /* _MSC_EXTENSIONS */
#define PRIo64  "llo"
#endif /* _MSC_EXTENSIONS */   
#endif /* PRIo64 */   

/* Format for printing 64-bit unsigned decimal numbers */
#ifndef PRIu64
#ifdef _MSC_EXTENSIONS
#define PRIu64  "I64u"
#else /* _MSC_EXTENSIONS */
#define PRIu64  "llu"  
#endif /* _MSC_EXTENSIONS */
#endif /* PRIu64 */

/* Formats for printing 64-bit unsigned hexadecimal numbers */
/* XXX - it seems that GLib has problems with the MSVC like I64x.
   As we use GLib's g_sprintf and alike, it should be safe to use
   llx everywhere now, making the macros pretty useless. For details see:
   http://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1025 */
#ifndef PRIx64
#ifdef _MSC_EXTENSIONS
/*#define PRIx64  "I64x"*/
#define PRIx64  "llx"
#else /* _MSC_EXTENSIONS */
#define PRIx64  "llx"
#endif /* _MSC_EXTENSIONS */
#endif /* PRIx64 */

#ifndef PRIX64
#ifdef _MSC_EXTENSIONS
/*#define PRIX64  "I64X"*/
#define PRIX64  "llX"
#else /* _MSC_EXTENSIONS */
#define PRIX64  "llX"
#endif /* _MSC_EXTENSIONS */
#endif /* PRIX64 */

/* Define if you have the z library (-lz).  */
#define HAVE_LIBZ 1

/* Define to use GNU ADNS library */
#define HAVE_GNU_ADNS 1
#define ADNS_JGAA_WIN32 1

/* Define to use the PCRE library */
#define HAVE_LIBPCRE 1

/* Define to use the Nettle library */


/* Define to use the gnutls library */
#define HAVE_LIBGNUTLS 1

/* Define to use the libgcrypt library */
#define HAVE_LIBGCRYPT 1

/* Define to use mit kerberos for decryption of kerberos/sasl/dcerpc */
#define HAVE_MIT_KERBEROS 1
#ifdef HAVE_MIT_KERBEROS
#define HAVE_KERBEROS
#endif

/* Define to use Lua */
#define HAVE_LUA 1
#define HAVE_LUA_5_1 1

/* Define to use Portaudio library */
#define HAVE_LIBPORTAUDIO 1
/* Define  version of of the Portaudio library API */


#ifndef WIN32
#define WIN32			1
#endif

#define HAVE_WINDOWS_H		1
#define HAVE_WINSOCK2_H		1
#define HAVE_DIRECT_H		1
#define NEED_INET_ATON_H	1
#define NEED_INET_V6DEFS_H	1
#define NEED_GETOPT_H		1
#define NEED_STRPTIME_H		1
#define strcasecmp		stricmp
#define strncasecmp		strnicmp
#define popen			_popen
#define pclose			_pclose

/* Needed for zlib, according to http://www.winimage.com/zLibDll/ */
/*#define ZLIB_DLL                1
#define _WINDOWS                1*/

/* Name of package */
#define PACKAGE "wireshark"

/* Version number of package */
#define VERSION "0.99.6"

/* We don't know what the plugin installation directory will be. */
#define PLUGIN_DIR NULL

/* We shouldn't need this under Windows but we'll define it anyway. */
#define HTML_VIEWER "mozilla"
