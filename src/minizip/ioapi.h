/* ioapi.h -- IO base function header for compress/uncompress .zip
   part of the MiniZip project - ( http://www.winimage.com/zLibDll/minizip.html )

   Copyright (C) 1998-2010 Gilles Vollant (minizip) ( http://www.winimage.com/zLibDll/minizip.html )

   Modifications for Zip64 support
   Copyright (C) 2009-2010 Mathias Svensson ( http://result42.com )

   This software is provided 'as-is', without any express or implied
   warranty. In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this software must not be misrepresented; you must not
      claim that you wrote the original software. If you use this software
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.
   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original software.
   3. This notice may not be removed or altered from any source distribution.
*/

#ifndef _ZLIBIOAPI64_H
#define _ZLIBIOAPI64_H

#if (!defined(_WIN32)) && (!defined(WIN32)) && (!defined(__APPLE__))
  #ifndef __USE_FILE_OFFSET64
    #define __USE_FILE_OFFSET64
  #endif
  #ifndef __USE_LARGEFILE64
    #define __USE_LARGEFILE64
  #endif
  #ifndef _LARGEFILE64_SOURCE
    #define _LARGEFILE64_SOURCE
  #endif
  #ifndef _FILE_OFFSET_BIT
    #define _FILE_OFFSET_BIT 64
  #endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include "zlib.h"

#if defined(USE_FILE32API)
#define fopen64 fopen
#define ftello64 ftell
#define fseeko64 fseek
#else
#ifdef __FreeBSD__
#define fopen64 fopen
#define ftello64 ftello
#define fseeko64 fseeko
#endif
#ifdef _MSC_VER
 #define fopen64 fopen
 #if (_MSC_VER >= 1400) && (!(defined(NO_MSCVER_FILE64_FUNC)))
  #define ftello64 _ftelli64
  #define fseeko64 _fseeki64
 #else
  #define ftello64 ftell
  #define fseeko64 fseek
 #endif
#endif
#endif

#ifndef ZPOS64_T
  #ifdef _WIN32
    #define ZPOS64_T fpos_t
  #else
    #include <stdint.h>
    #define ZPOS64_T uint64_t
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ZLIB_FILEFUNC_SEEK_CUR (1)
#define ZLIB_FILEFUNC_SEEK_END (2)
#define ZLIB_FILEFUNC_SEEK_SET (0)

#define ZLIB_FILEFUNC_MODE_READ      (1)
#define ZLIB_FILEFUNC_MODE_WRITE     (2)
#define ZLIB_FILEFUNC_MODE_READWRITEFILTER (3)

#define ZLIB_FILEFUNC_MODE_EXISTING (4)
#define ZLIB_FILEFUNC_MODE_CREATE   (8)

#ifndef ZCALLBACK
 #if (defined(WIN32) || defined(_WIN32) || defined (WINDOWS) || defined (_WINDOWS)) && defined(CALLBACK) && defined (USEWINDOWS_CALLBACK)
   #define ZCALLBACK CALLBACK
 #else
   #define ZCALLBACK
 #endif
#endif

typedef voidpf   (ZCALLBACK *open_file_func)      OF((voidpf opaque, const char* filename, int mode));
typedef uLong    (ZCALLBACK *read_file_func)      OF((voidpf opaque, voidpf stream, void* buf, uLong size));
typedef uLong    (ZCALLBACK *write_file_func)     OF((voidpf opaque, voidpf stream, const void* buf, uLong size));
typedef int      (ZCALLBACK *close_file_func)     OF((voidpf opaque, voidpf stream));
typedef int      (ZCALLBACK *testerror_file_func) OF((voidpf opaque, voidpf stream));

typedef long     (ZCALLBACK *tell_file_func)      OF((voidpf opaque, voidpf stream));
typedef long     (ZCALLBACK *seek_file_func)      OF((voidpf opaque, voidpf stream, uLong offset, int origin));

typedef ZPOS64_T (ZCALLBACK *tell64_file_func)    OF((voidpf opaque, voidpf stream));
typedef long     (ZCALLBACK *seek64_file_func)    OF((voidpf opaque, voidpf stream, ZPOS64_T offset, int origin));
typedef voidpf   (ZCALLBACK *open64_file_func)    OF((voidpf opaque, const void* filename, int mode));

typedef struct zlib_filefunc_def_s
{
    open_file_func      zopen_file;
    read_file_func      zread_file;
    write_file_func     zwrite_file;
    tell_file_func      ztell_file;
    seek_file_func      zseek_file;
    close_file_func     zclose_file;
    testerror_file_func zerror_file;
    voidpf              opaque;
} zlib_filefunc_def;

typedef struct zlib_filefunc64_def_s
{
    open64_file_func    zopen64_file;
    read_file_func      zread_file;
    write_file_func     zwrite_file;
    tell64_file_func    ztell64_file;
    seek64_file_func    zseek64_file;
    close_file_func     zclose_file;
    testerror_file_func zerror_file;
    voidpf              opaque;
} zlib_filefunc64_def;

void fill_fopen64_filefunc OF((zlib_filefunc64_def* pzlib_filefunc_def));
void fill_fopen_filefunc OF((zlib_filefunc_def* pzlib_filefunc_def));

#define ZREAD64(filefunc,filestream,buf,size)     ((*((filefunc).zread_file))   ((filefunc).opaque,filestream,buf,size))
#define ZWRITE64(filefunc,filestream,buf,size)    ((*((filefunc).zwrite_file))  ((filefunc).opaque,filestream,buf,size))
#define ZTELL64(filefunc,filestream)              ((*((filefunc).ztell64_file)) ((filefunc).opaque,filestream))
#define ZSEEK64(filefunc,filestream,pos,mode)     ((*((filefunc).zseek64_file)) ((filefunc).opaque,filestream,pos,mode))
#define ZCLOSE64(filefunc,filestream)             ((*((filefunc).zclose_file))  ((filefunc).opaque,filestream))
#define ZERROR64(filefunc,filestream)             ((*((filefunc).zerror_file))  ((filefunc).opaque,filestream))

voidpf call_zopen64 OF((const zlib_filefunc64_def* pfilefunc,const void*filename,int mode));
long    call_zseek64 OF((const zlib_filefunc64_def* pfilefunc,voidpf filestream, ZPOS64_T offset, int origin));
ZPOS64_T call_ztell64 OF((const zlib_filefunc64_def* pfilefunc,voidpf filestream));

void    fill_zlib_filefunc64_32_def_from_filefunc32 OF((zlib_filefunc64_def* p_filefunc64_32,const zlib_filefunc_def* p_filefunc32));

#define ZOPEN64(filefunc,filename,mode)         (call_zopen64((&(filefunc)),(filename),(mode)))
#define ZTELL64(filefunc,filestream)            (call_ztell64((&(filefunc)),(filestream)))
#define ZSEEK64(filefunc,filestream,pos,mode)   (call_zseek64((&(filefunc)),(filestream),(pos),(mode)))

#ifdef __cplusplus
}
#endif

#endif
