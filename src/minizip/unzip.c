/* unzip.c -- IO for uncompress .zip files using zlib
   Version 1.1, February 14h, 2010
   part of the MiniZip project - ( http://www.winimage.com/zLibDll/minizip.html )

   Copyright (C) 1998-2010 Gilles Vollant (minizip) ( http://www.winimage.com/zLibDll/minizip.html )

   Modifications of Unzip for Zip64
   Copyright (C) 2007-2008 Even Rouault
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NOUNCRYPT
  #define NOUNCRYPT
#endif

#include "zlib.h"
#include "unzip.h"

#ifdef STDC
#  include <stddef.h>
#  include <string.h>
#  include <stdlib.h>
#endif
#ifdef NO_ERRNO_H
    extern int errno;
#else
#   include <errno.h>
#endif

#ifndef local
#  define local static
#endif

#ifndef CASESENSITIVITYDEFAULT_NO
#  if !defined(unix) && !defined(CASESENSITIVITYDEFAULT_YES)
#    define CASESENSITIVITYDEFAULT_NO
#  endif
#endif

#ifndef UNZ_BUFSIZE
#define UNZ_BUFSIZE (16384)
#endif

#ifndef UNZ_MAXFILENAMEINZIP
#define UNZ_MAXFILENAMEINZIP (256)
#endif

#ifndef ALLOC
# define ALLOC(size) (malloc(size))
#endif
#ifndef TRYFREE
# define TRYFREE(p) {if (p) free(p);}
#endif

#define SIZECENTRALDIRITEM (0x2e)
#define SIZEZIPLOCALHEADER (0x1e)

const char unz_copyright[] =
   " unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll";

typedef struct unz64_internal_s {
    zlib_filefunc64_def z_filefunc;
    int is64bitOpenFunction;
    voidpf filestream;
    unz_global_info64 gi;
    ZPOS64_T byte_before_the_zipfile;
    ZPOS64_T num_file;
    ZPOS64_T pos_in_central_dir;
    ZPOS64_T current_file_ok;
    ZPOS64_T central_pos;
    ZPOS64_T size_central_dir;
    ZPOS64_T offset_central_dir;
    unz_file_info64 cur_file_info;
    unz64_file_pos cur_file_info_internal;
    voidpf pfile_in_zip_read;
    int encrypted;
    int isZip64;
} unz64_internal;

typedef struct {
    char *read_buffer;
    z_stream stream;
    ZPOS64_T pos_in_zipfile;
    uLong stream_initialised;
    ZPOS64_T offset_local_extrafield;
    uInt size_local_extrafield;
    ZPOS64_T pos_local_extrafield;
    ZPOS64_T total_out_64;
    uLong crc32;
    uLong crc32_wait;
    ZPOS64_T rest_read_compressed;
    ZPOS64_T rest_read_uncompressed;
    zlib_filefunc64_def z_filefunc;
    voidpf filestream;
    uLong compression_method;
    ZPOS64_T byte_before_the_zipfile;
    int raw;
} file_in_zip64_read_info_s;

local int unz64local_getByte OF((const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream, int *pi));
local int unz64local_getShort OF((const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream, uLong *pX));
local int unz64local_getLong OF((const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream, uLong *pX));
local int unz64local_getLong64 OF((const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream, ZPOS64_T *pX));
local ZPOS64_T unz64local_SearchCentralDir OF((const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream));
local ZPOS64_T unz64local_SearchCentralDir64 OF((const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream));

local int unz64local_getByte(const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream, int *pi)
{
    unsigned char c;
    int err = (int)ZREAD64(*pzlib_filefunc_def,filestream,&c,1);
    if (err==1)
    {
        *pi = (int)c;
        return UNZ_OK;
    }
    else
    {
        if (ZERROR64(*pzlib_filefunc_def,filestream))
            return UNZ_ERRNO;
        else
            return UNZ_EOF;
    }
}

local int unz64local_getShort (const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream, uLong *pX)
{
    uLong x ;
    int i = 0;
    int err;

    err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x = (uLong)i;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((uLong)i)<<8;

    if (err==UNZ_OK)
        *pX = x;
    else
        *pX = 0;
    return err;
}

local int unz64local_getLong (const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream, uLong *pX)
{
    uLong x ;
    int i = 0;
    int err;

    err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x = (uLong)i;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((uLong)i)<<8;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((uLong)i)<<16;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((uLong)i)<<24;

    if (err==UNZ_OK)
        *pX = x;
    else
        *pX = 0;
    return err;
}

local int unz64local_getLong64 (const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream, ZPOS64_T *pX)
{
    ZPOS64_T x ;
    int i = 0;
    int err;

    err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x = (ZPOS64_T)i;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((ZPOS64_T)i)<<8;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((ZPOS64_T)i)<<16;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((ZPOS64_T)i)<<24;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((ZPOS64_T)i)<<32;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((ZPOS64_T)i)<<40;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((ZPOS64_T)i)<<48;

    if (err==UNZ_OK)
        err = unz64local_getByte(pzlib_filefunc_def,filestream,&i);
    x |= ((ZPOS64_T)i)<<56;

    if (err==UNZ_OK)
        *pX = x;
    else
        *pX = 0;
    return err;
}

local int strcmpcasenosensitive_internal (const char* fileName1, const char* fileName2)
{
    for (;;)
    {
        char c1=*(fileName1++);
        char c2=*(fileName2++);
        if ((c1>='a') && (c1<='z'))
            c1 -= 0x20;
        if ((c2>='a') && (c2<='z'))
            c2 -= 0x20;
        if (c1=='\0')
            return ((c2=='\0') ? 0 : -1);
        if (c2=='\0')
            return 1;
        if (c1<c2)
            return -1;
        if (c1>c2)
            return 1;
    }
}

#ifdef  CASESENSITIVITYDEFAULT_NO
#define CASESENSITIVITYDEFAULTVALUE 2
#else
#define CASESENSITIVITYDEFAULTVALUE 1
#endif

#ifndef STRCMPCASENOSENTIVEFUNCTION
#define STRCMPCASENOSENTIVEFUNCTION strcmpcasenosensitive_internal
#endif

int ZEXPORT unzStringFileNameCompare (const char* fileName1, const char* fileName2, int iCaseSensitivity)
{
    if (iCaseSensitivity==0)
        iCaseSensitivity=CASESENSITIVITYDEFAULTVALUE;

    if (iCaseSensitivity==1)
        return strcmp(fileName1,fileName2);

    return STRCMPCASENOSENTIVEFUNCTION(fileName1,fileName2);
}

#define BUFREADCOMMENT (0x400)

local ZPOS64_T unz64local_SearchCentralDir(const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream)
{
    unsigned char* buf;
    ZPOS64_T uSizeFile;
    ZPOS64_T uBackRead;
    ZPOS64_T uMaxBack=0xffff;
    ZPOS64_T uPosFound=0;

    if (ZSEEK64(*pzlib_filefunc_def,filestream,0,ZLIB_FILEFUNC_SEEK_END) != 0)
        return 0;

    uSizeFile = ZTELL64(*pzlib_filefunc_def,filestream);

    if (uMaxBack>uSizeFile)
        uMaxBack = uSizeFile;

    buf = (unsigned char*)ALLOC(BUFREADCOMMENT+4);
    if (buf==NULL)
        return 0;

    uBackRead = 4;
    while (uBackRead<uMaxBack)
    {
        uLong uReadSize;
        ZPOS64_T uReadPos ;
        int i;
        if (uBackRead+BUFREADCOMMENT>uMaxBack)
            uBackRead = uMaxBack;
        else
            uBackRead+=BUFREADCOMMENT;
        uReadPos = uSizeFile-uBackRead ;

        uReadSize = ((BUFREADCOMMENT+4) < (uSizeFile-uReadPos)) ?
                     (BUFREADCOMMENT+4) : (uLong)(uSizeFile-uReadPos);
        if (ZSEEK64(*pzlib_filefunc_def,filestream,uReadPos,ZLIB_FILEFUNC_SEEK_SET)!=0)
            break;

        if (ZREAD64(*pzlib_filefunc_def,filestream,buf,uReadSize)!=uReadSize)
            break;

        for (i=(int)uReadSize-3; (i--)>0;)
            if (((*(buf+i))==0x50) && ((*(buf+i+1))==0x4b) &&
                ((*(buf+i+2))==0x05) && ((*(buf+i+3))==0x06))
            {
                uPosFound = uReadPos+(unsigned)i;
                break;
            }

        if (uPosFound!=0)
            break;
    }
    TRYFREE(buf);
    return uPosFound;
}

local ZPOS64_T unz64local_SearchCentralDir64(const zlib_filefunc64_def* pzlib_filefunc_def, voidpf filestream)
{
    unsigned char* buf;
    ZPOS64_T uSizeFile;
    ZPOS64_T uBackRead;
    ZPOS64_T uMaxBack=0xffff;
    ZPOS64_T uPosFound=0;
    uLong uL;

    if (ZSEEK64(*pzlib_filefunc_def,filestream,0,ZLIB_FILEFUNC_SEEK_END) != 0)
        return 0;

    uSizeFile = ZTELL64(*pzlib_filefunc_def,filestream);

    if (uMaxBack>uSizeFile)
        uMaxBack = uSizeFile;

    buf = (unsigned char*)ALLOC(BUFREADCOMMENT+4);
    if (buf==NULL)
        return 0;

    uBackRead = 4;
    while (uBackRead<uMaxBack)
    {
        uLong uReadSize;
        ZPOS64_T uReadPos;
        int i;
        if (uBackRead+BUFREADCOMMENT>uMaxBack)
            uBackRead = uMaxBack;
        else
            uBackRead+=BUFREADCOMMENT;
        uReadPos = uSizeFile-uBackRead ;

        uReadSize = ((BUFREADCOMMENT+4) < (uSizeFile-uReadPos)) ?
                     (BUFREADCOMMENT+4) : (uLong)(uSizeFile-uReadPos);
        if (ZSEEK64(*pzlib_filefunc_def,filestream,uReadPos,ZLIB_FILEFUNC_SEEK_SET)!=0)
            break;

        if (ZREAD64(*pzlib_filefunc_def,filestream,buf,uReadSize)!=uReadSize)
            break;

        for (i=(int)uReadSize-3; (i--)>0;)
            if (((*(buf+i))==0x50) && ((*(buf+i+1))==0x4b) &&
                ((*(buf+i+2))==0x06) && ((*(buf+i+3))==0x07))
            {
                uPosFound = uReadPos+(unsigned)i;
                break;
            }

        if (uPosFound!=0)
            break;
    }
    TRYFREE(buf);
    if (uPosFound == 0)
        return 0;

    if (ZSEEK64(*pzlib_filefunc_def,filestream, uPosFound,ZLIB_FILEFUNC_SEEK_SET)!=0)
        return 0;

    if (unz64local_getLong(pzlib_filefunc_def,filestream,&uL)!=UNZ_OK)
        return 0;

    if (unz64local_getLong64(pzlib_filefunc_def,filestream,&uPosFound)!=UNZ_OK)
        return 0;

    return uPosFound;
}

local unzFile unzOpenInternal (const void *path, zlib_filefunc64_def* pzlib_filefunc64_def, int is64bitOpenFunction)
{
    unz64_internal us;
    unz64_internal *s;
    ZPOS64_T central_pos;
    uLong   uL;

    uLong number_disk;
    uLong number_disk_with_CD;
    ZPOS64_T number_entry_CD;

    int err=UNZ_OK;

    if (pzlib_filefunc64_def==NULL)
        fill_fopen64_filefunc(&us.z_filefunc);
    else
        us.z_filefunc = *pzlib_filefunc64_def;
    us.is64bitOpenFunction = is64bitOpenFunction;

    us.filestream = ZOPEN64(us.z_filefunc, path, ZLIB_FILEFUNC_MODE_READ | ZLIB_FILEFUNC_MODE_EXISTING);
    if (us.filestream==NULL)
        return NULL;

    central_pos = unz64local_SearchCentralDir64(&us.z_filefunc,us.filestream);
    if (central_pos)
    {
        ZPOS64_T uL64;
        us.isZip64 = 1;

        if (ZSEEK64(us.z_filefunc, us.filestream, central_pos,ZLIB_FILEFUNC_SEEK_SET)!=0)
            err=UNZ_ERRNO;

        if (unz64local_getLong(&us.z_filefunc, us.filestream,&uL)!=UNZ_OK)
            err=UNZ_ERRNO;

        if (unz64local_getLong64(&us.z_filefunc, us.filestream,&uL64)!=UNZ_OK)
            err=UNZ_ERRNO;

        if (unz64local_getShort(&us.z_filefunc, us.filestream,&number_disk)!=UNZ_OK)
            err=UNZ_ERRNO;

        if (unz64local_getShort(&us.z_filefunc, us.filestream,&number_disk_with_CD)!=UNZ_OK)
            err=UNZ_ERRNO;

        if (unz64local_getLong64(&us.z_filefunc, us.filestream,&us.gi.number_entry)!=UNZ_OK)
            err=UNZ_ERRNO;

        if (unz64local_getLong64(&us.z_filefunc, us.filestream,&number_entry_CD)!=UNZ_OK)
            err=UNZ_ERRNO;

        if ((number_entry_CD!=us.gi.number_entry) || (number_disk!=0) || (number_disk_with_CD!=0))
            err=UNZ_BADZIPFILE;

        if (unz64local_getLong64(&us.z_filefunc, us.filestream,&us.size_central_dir)!=UNZ_OK)
            err=UNZ_ERRNO;

        if (unz64local_getLong64(&us.z_filefunc, us.filestream,&us.offset_central_dir)!=UNZ_OK)
            err=UNZ_ERRNO;

        us.gi.size_comment = 0;
    }
    else
    {
        central_pos = unz64local_SearchCentralDir(&us.z_filefunc,us.filestream);
        if (central_pos==0)
            err=UNZ_ERRNO;

        us.isZip64 = 0;

        if (ZSEEK64(us.z_filefunc, us.filestream, central_pos,ZLIB_FILEFUNC_SEEK_SET)!=0)
            err=UNZ_ERRNO;

        if (unz64local_getLong(&us.z_filefunc, us.filestream,&uL)!=UNZ_OK)
            err=UNZ_ERRNO;

        if (unz64local_getShort(&us.z_filefunc, us.filestream,&number_disk)!=UNZ_OK)
            err=UNZ_ERRNO;

        if (unz64local_getShort(&us.z_filefunc, us.filestream,&number_disk_with_CD)!=UNZ_OK)
            err=UNZ_ERRNO;

        if (unz64local_getShort(&us.z_filefunc, us.filestream,&uL)!=UNZ_OK)
            err=UNZ_ERRNO;
        us.gi.number_entry = uL;

        if (unz64local_getShort(&us.z_filefunc, us.filestream,&uL)!=UNZ_OK)
            err=UNZ_ERRNO;
        number_entry_CD = uL;

        if ((number_entry_CD!=us.gi.number_entry) || (number_disk!=0) || (number_disk_with_CD!=0))
            err=UNZ_BADZIPFILE;

        if (unz64local_getLong(&us.z_filefunc, us.filestream,&uL)!=UNZ_OK)
            err=UNZ_ERRNO;
        us.size_central_dir = uL;

        if (unz64local_getLong(&us.z_filefunc, us.filestream,&uL)!=UNZ_OK)
            err=UNZ_ERRNO;
        us.offset_central_dir = uL;

        if (unz64local_getShort(&us.z_filefunc, us.filestream,&us.gi.size_comment)!=UNZ_OK)
            err=UNZ_ERRNO;
    }

    if ((central_pos<us.offset_central_dir+us.size_central_dir) && (err==UNZ_OK))
        err=UNZ_BADZIPFILE;

    if (err!=UNZ_OK)
    {
        ZCLOSE64(us.z_filefunc, us.filestream);
        return NULL;
    }

    us.byte_before_the_zipfile = central_pos - (us.offset_central_dir+us.size_central_dir);
    us.central_pos = central_pos;
    us.pfile_in_zip_read = NULL;
    us.encrypted = 0;

    s=(unz64_internal*)ALLOC(sizeof(unz64_internal));
    if( s != NULL)
    {
        *s=us;
        unzGoToFirstFile((unzFile)s);
    }
    return (unzFile)s;
}

unzFile ZEXPORT unzOpen2 (const char *path, zlib_filefunc_def* pzlib_filefunc32_def)
{
    if (pzlib_filefunc32_def != NULL)
    {
        zlib_filefunc64_def zlib_filefunc64_def_fill;
        fill_zlib_filefunc64_32_def_from_filefunc32(&zlib_filefunc64_def_fill,pzlib_filefunc32_def);
        return unzOpenInternal(path, &zlib_filefunc64_def_fill, 0);
    }
    return unzOpenInternal(path, NULL, 0);
}

unzFile ZEXPORT unzOpen2_64 (const void *path, zlib_filefunc64_def* pzlib_filefunc_def)
{
    if (pzlib_filefunc_def != NULL)
        return unzOpenInternal(path, pzlib_filefunc_def, 1);
    return unzOpenInternal(path, NULL, 1);
}

unzFile ZEXPORT unzOpen (const char *path)
{
    return unzOpenInternal(path, NULL, 0);
}

unzFile ZEXPORT unzOpen64 (const void *path)
{
    return unzOpenInternal(path, NULL, 1);
}

int ZEXPORT unzClose (unzFile file)
{
    unz64_internal* s;
    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;

    if (s->pfile_in_zip_read!=NULL)
        unzCloseCurrentFile(file);

    ZCLOSE64(s->z_filefunc, s->filestream);
    TRYFREE(s);
    return UNZ_OK;
}

int ZEXPORT unzGetGlobalInfo64 (unzFile file, unz_global_info64* pglobal_info)
{
    unz64_internal* s;
    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    *pglobal_info=s->gi;
    return UNZ_OK;
}

int ZEXPORT unzGetGlobalInfo (unzFile file, unz_global_info* pglobal_info32)
{
    unz64_internal* s;
    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    pglobal_info32->number_entry = (uLong)s->gi.number_entry;
    pglobal_info32->size_comment = s->gi.size_comment;
    return UNZ_OK;
}

local void unz64local_DosDateToTmuDate (ZPOS64_T ulDosDate, tm_unz* ptm)
{
    ZPOS64_T uDate;
    uDate = (ZPOS64_T)(ulDosDate>>16);
    ptm->tm_mday = (uInt)(uDate&0x1f) ;
    ptm->tm_mon =  (uInt)((((uDate)&0x1E0)/0x20)-1) ;
    ptm->tm_year = (uInt)(((uDate&0x0FE00)/0x0200)+1980) ;

    ptm->tm_hour = (uInt) ((ulDosDate &0xF800)/0x800);
    ptm->tm_min =  (uInt) ((ulDosDate&0x7E0)/0x20) ;
    ptm->tm_sec =  (uInt) (2*(ulDosDate&0x1f)) ;
}

local int unz64local_GetCurrentFileInfoInternal OF((unzFile file,
                                                    unz_file_info64 *pfile_info,
                                                    unz_file_info *pfile_info_internal,
                                                    char *szFileName,
                                                    uLong fileNameBufferSize,
                                                    void *extraField,
                                                    uLong extraFieldBufferSize,
                                                    char *szComment,
                                                    uLong commentBufferSize));

local int unz64local_GetCurrentFileInfoInternal (unzFile file,
                                                 unz_file_info64 *pfile_info,
                                                 unz_file_info *pfile_info_internal,
                                                 char *szFileName,
                                                 uLong fileNameBufferSize,
                                                 void *extraField,
                                                 uLong extraFieldBufferSize,
                                                 char *szComment,
                                                 uLong commentBufferSize)
{
    unz64_internal* s;
    unz_file_info64 file_info;
    unz_file_info64 file_info_internal;
    int err=UNZ_OK;
    uLong uMagic;
    long lSeek=0;
    uLong uSizeRead;

    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    if (ZSEEK64(s->z_filefunc, s->filestream,
              s->pos_in_central_dir+s->byte_before_the_zipfile,
              ZLIB_FILEFUNC_SEEK_SET)!=0)
        err=UNZ_ERRNO;

    if (err==UNZ_OK)
    {
        if (unz64local_getLong(&s->z_filefunc, s->filestream,&uMagic) != UNZ_OK)
            err=UNZ_ERRNO;
        else if (uMagic!=0x02014b50)
            err=UNZ_BADZIPFILE;
    }

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&file_info.version) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&file_info.version_needed) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&file_info.flag) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&file_info.compression_method) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getLong(&s->z_filefunc, s->filestream,&file_info.dosDate) != UNZ_OK)
        err=UNZ_ERRNO;

    unz64local_DosDateToTmuDate(file_info.dosDate,&file_info.tmu_date);

    if (unz64local_getLong(&s->z_filefunc, s->filestream,&file_info.crc) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getLong(&s->z_filefunc, s->filestream,&uMagic) != UNZ_OK)
        err=UNZ_ERRNO;
    file_info.compressed_size = uMagic;

    if (unz64local_getLong(&s->z_filefunc, s->filestream,&uMagic) != UNZ_OK)
        err=UNZ_ERRNO;
    file_info.uncompressed_size = uMagic;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&file_info.size_filename) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&file_info.size_file_extra) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&file_info.size_file_comment) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&file_info.disk_num_start) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&file_info.internal_fa) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getLong(&s->z_filefunc, s->filestream,&file_info.external_fa) != UNZ_OK)
        err=UNZ_ERRNO;

    lSeek += file_info.size_filename;

    if ((err==UNZ_OK) && (szFileName!=NULL))
    {
        uLong uSizeRead ;

        if (file_info.size_filename<fileNameBufferSize)
        {
            *(szFileName+file_info.size_filename)='\0';
            uSizeRead = file_info.size_filename;
        }
        else
            uSizeRead = fileNameBufferSize;

        if ((file_info.size_filename>0) && (fileNameBufferSize>0))
            if (ZREAD64(s->z_filefunc, s->filestream,szFileName,uSizeRead)!=uSizeRead)
                err=UNZ_ERRNO;
        lSeek -= uSizeRead;
    }

    if ((err==UNZ_OK) && (extraField!=NULL))
    {
        ZPOS64_T uSizeRead ;
        if (file_info.size_file_extra<extraFieldBufferSize)
            uSizeRead = file_info.size_file_extra;
        else
            uSizeRead = extraFieldBufferSize;

        if (lSeek!=0)
        {
            if (ZSEEK64(s->z_filefunc, s->filestream,(ZPOS64_T)lSeek,ZLIB_FILEFUNC_SEEK_CUR)==0)
                lSeek=0;
            else
                err=UNZ_ERRNO;
        }

        if ((file_info.size_file_extra>0) && (extraFieldBufferSize>0))
            if (ZREAD64(s->z_filefunc, s->filestream,extraField,(uLong)uSizeRead)!=uSizeRead)
                err=UNZ_ERRNO;

        lSeek += file_info.size_file_extra - (uLong)uSizeRead;
    }
    else
        lSeek += file_info.size_file_extra;

    if ((err==UNZ_OK) && (file_info.size_file_extra != 0))
    {
        uLong acc = 0;

        if (lSeek!=0)
        {
            if (ZSEEK64(s->z_filefunc, s->filestream,(ZPOS64_T)lSeek,ZLIB_FILEFUNC_SEEK_CUR)==0)
                lSeek=0;
            else
                err=UNZ_ERRNO;
        }

        while(acc < file_info.size_file_extra)
        {
            uLong headerId;
            uLong dataSize;

            if (unz64local_getShort(&s->z_filefunc, s->filestream,&headerId) != UNZ_OK)
                err=UNZ_ERRNO;

            if (unz64local_getShort(&s->z_filefunc, s->filestream,&dataSize) != UNZ_OK)
                err=UNZ_ERRNO;

            if (headerId == 0x0001)
            {
                if(file_info.uncompressed_size == (ZPOS64_T)(unsigned long)-1)
                {
                    if (unz64local_getLong64(&s->z_filefunc, s->filestream,&file_info.uncompressed_size) != UNZ_OK)
                        err=UNZ_ERRNO;
                }

                if(file_info.compressed_size == (ZPOS64_T)(unsigned long)-1)
                {
                    if (unz64local_getLong64(&s->z_filefunc, s->filestream,&file_info.compressed_size) != UNZ_OK)
                        err=UNZ_ERRNO;
                }
            }
            else
            {
                if (ZSEEK64(s->z_filefunc, s->filestream,dataSize,ZLIB_FILEFUNC_SEEK_CUR)!=0)
                    err=UNZ_ERRNO;
            }

            acc += 2 + 2 + dataSize;
        }
    }

    if ((err==UNZ_OK) && (szComment!=NULL))
    {
        uLong uSizeRead ;
        if (file_info.size_file_comment<commentBufferSize)
        {
            *(szComment+file_info.size_file_comment)='\0';
            uSizeRead = file_info.size_file_comment;
        }
        else
            uSizeRead = commentBufferSize;

        if (lSeek!=0)
        {
            if (ZSEEK64(s->z_filefunc, s->filestream,(ZPOS64_T)lSeek,ZLIB_FILEFUNC_SEEK_CUR)==0)
                lSeek=0;
            else
                err=UNZ_ERRNO;
        }

        if ((file_info.size_file_comment>0) && (commentBufferSize>0))
            if (ZREAD64(s->z_filefunc, s->filestream,szComment,uSizeRead)!=uSizeRead)
                err=UNZ_ERRNO;
        lSeek+=file_info.size_file_comment - uSizeRead;
    }
    else
        lSeek+=file_info.size_file_comment;

    if ((err==UNZ_OK) && (pfile_info!=NULL))
        *pfile_info=file_info;

    // Note: pfile_info_internal is not used in this implementation
    (void)pfile_info_internal;
    (void)file_info_internal;

    return err;
}

int ZEXPORT unzGetCurrentFileInfo64 (unzFile file,
                                     unz_file_info64 *pfile_info,
                                     char *szFileName,
                                     uLong fileNameBufferSize,
                                     void *extraField,
                                     uLong extraFieldBufferSize,
                                     char *szComment,
                                     uLong commentBufferSize)
{
    return unz64local_GetCurrentFileInfoInternal(file,pfile_info,NULL,
                                                 szFileName,fileNameBufferSize,
                                                 extraField,extraFieldBufferSize,
                                                 szComment,commentBufferSize);
}

int ZEXPORT unzGetCurrentFileInfo (unzFile file,
                                   unz_file_info *pfile_info,
                                   char *szFileName,
                                   uLong fileNameBufferSize,
                                   void *extraField,
                                   uLong extraFieldBufferSize,
                                   char *szComment,
                                   uLong commentBufferSize)
{
    int err;
    unz_file_info64 file_info64;
    err = unz64local_GetCurrentFileInfoInternal(file,&file_info64,NULL,
                                                szFileName,fileNameBufferSize,
                                                extraField,extraFieldBufferSize,
                                                szComment,commentBufferSize);
    if ((err==UNZ_OK) && (pfile_info != NULL))
    {
        pfile_info->version = file_info64.version;
        pfile_info->version_needed = file_info64.version_needed;
        pfile_info->flag = file_info64.flag;
        pfile_info->compression_method = file_info64.compression_method;
        pfile_info->dosDate = file_info64.dosDate;
        pfile_info->crc = file_info64.crc;
        pfile_info->compressed_size = (uLong)file_info64.compressed_size;
        pfile_info->uncompressed_size = (uLong)file_info64.uncompressed_size;
        pfile_info->size_filename = file_info64.size_filename;
        pfile_info->size_file_extra = file_info64.size_file_extra;
        pfile_info->size_file_comment = file_info64.size_file_comment;
        pfile_info->disk_num_start = file_info64.disk_num_start;
        pfile_info->internal_fa = file_info64.internal_fa;
        pfile_info->external_fa = file_info64.external_fa;
        pfile_info->tmu_date = file_info64.tmu_date;
    }
    return err;
}

int ZEXPORT unzGoToFirstFile (unzFile file)
{
    int err=UNZ_OK;
    unz64_internal* s;
    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    s->pos_in_central_dir=s->offset_central_dir;
    s->num_file=0;
    err=unz64local_GetCurrentFileInfoInternal(file,&s->cur_file_info,
                                              &s->cur_file_info_internal,
                                              NULL,0,NULL,0,NULL,0);
    s->current_file_ok = (err == UNZ_OK);
    return err;
}

int ZEXPORT unzGoToNextFile (unzFile file)
{
    unz64_internal* s;
    int err;

    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    if (!s->current_file_ok)
        return UNZ_END_OF_LIST_OF_FILE;
    if (s->gi.number_entry != 0xffff)
        if (s->num_file+1==s->gi.number_entry)
            return UNZ_END_OF_LIST_OF_FILE;

    s->pos_in_central_dir += SIZECENTRALDIRITEM + s->cur_file_info.size_filename +
            s->cur_file_info.size_file_extra + s->cur_file_info.size_file_comment ;
    s->num_file++;
    err = unz64local_GetCurrentFileInfoInternal(file,&s->cur_file_info,
                                                &s->cur_file_info_internal,
                                                NULL,0,NULL,0,NULL,0);
    s->current_file_ok = (err == UNZ_OK);
    return err;
}

int ZEXPORT unzLocateFile (unzFile file, const char *szFileName, int iCaseSensitivity)
{
    unz64_internal* s;
    int err;
    unz64_file_pos saved_pos;
    char szCurrentFileName[UNZ_MAXFILENAMEINZIP+1];

    if (file==NULL)
        return UNZ_PARAMERROR;

    if (strlen(szFileName)>=UNZ_MAXFILENAMEINZIP)
        return UNZ_PARAMERROR;

    s=(unz64_internal*)file;
    if (!s->current_file_ok)
        return UNZ_END_OF_LIST_OF_FILE;

    saved_pos.pos_in_zip_directory = s->pos_in_central_dir;
    saved_pos.num_of_file = s->num_file;

    err = unzGoToFirstFile(file);

    while (err == UNZ_OK)
    {
        unzGetCurrentFileInfo64(file,NULL,
                                szCurrentFileName,sizeof(szCurrentFileName)-1,
                                NULL,0,NULL,0);
        if (unzStringFileNameCompare(szCurrentFileName,szFileName,iCaseSensitivity)==0)
            return UNZ_OK;
        err = unzGoToNextFile(file);
    }

    s->pos_in_central_dir = saved_pos.pos_in_zip_directory;
    s->num_file = saved_pos.num_of_file;
    return err;
}

int ZEXPORT unzGetFilePos64 (unzFile file, unz64_file_pos* file_pos)
{
    unz64_internal* s;

    if (file==NULL || file_pos==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    if (!s->current_file_ok)
        return UNZ_END_OF_LIST_OF_FILE;

    file_pos->pos_in_zip_directory  = s->pos_in_central_dir;
    file_pos->num_of_file           = s->num_file;

    return UNZ_OK;
}

int ZEXPORT unzGoToFilePos64 (unzFile file, const unz64_file_pos* file_pos)
{
    unz64_internal* s;
    int err;

    if (file==NULL || file_pos==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;

    s->pos_in_central_dir = file_pos->pos_in_zip_directory;
    s->num_file = file_pos->num_of_file;

    s->current_file_ok = 1;
    err = unz64local_GetCurrentFileInfoInternal(file,&s->cur_file_info,
                                                &s->cur_file_info_internal,
                                                NULL,0,NULL,0,NULL,0);
    s->current_file_ok = (err == UNZ_OK);
    return err;
}

int ZEXPORT unzGetFilePos (unzFile file, unz_file_pos* file_pos)
{
    unz64_file_pos file_pos64;
    int err = unzGetFilePos64(file,&file_pos64);
    if (err==UNZ_OK)
    {
        file_pos->pos_in_zip_directory = (uLong)file_pos64.pos_in_zip_directory;
        file_pos->num_of_file = (uLong)file_pos64.num_of_file;
    }
    return err;
}

int ZEXPORT unzGoToFilePos (unzFile file, unz_file_pos* file_pos)
{
    unz64_file_pos file_pos64;
    if (file_pos == NULL)
        return UNZ_PARAMERROR;

    file_pos64.pos_in_zip_directory = file_pos->pos_in_zip_directory;
    file_pos64.num_of_file = file_pos->num_of_file;
    return unzGoToFilePos64(file,&file_pos64);
}

local int unz64local_CheckCurrentFileCoherencyHeader (unz64_internal* s, uInt* piSizeVar,
                                                       ZPOS64_T *poffset_local_extrafield,
                                                       uInt *psize_local_extrafield)
{
    uLong uMagic,uData,uFlags;
    uLong size_filename;
    uLong size_extra_field;
    int err=UNZ_OK;

    *piSizeVar = 0;
    *poffset_local_extrafield = 0;
    *psize_local_extrafield = 0;

    if (ZSEEK64(s->z_filefunc, s->filestream,s->cur_file_info_internal.pos_in_zip_directory +
                                s->byte_before_the_zipfile,ZLIB_FILEFUNC_SEEK_SET)!=0)
        return UNZ_ERRNO;

    if (err==UNZ_OK)
    {
        if (unz64local_getLong(&s->z_filefunc, s->filestream,&uMagic) != UNZ_OK)
            err=UNZ_ERRNO;
        else if (uMagic!=0x04034b50)
            err=UNZ_BADZIPFILE;
    }

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&uData) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&uFlags) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&uData) != UNZ_OK)
        err=UNZ_ERRNO;
    else if ((err==UNZ_OK) && (uData!=s->cur_file_info.compression_method))
        err=UNZ_BADZIPFILE;

    if ((err==UNZ_OK) && (s->cur_file_info.compression_method!=0) &&
                         (s->cur_file_info.compression_method!=Z_DEFLATED))
        err=UNZ_BADZIPFILE;

    if (unz64local_getLong(&s->z_filefunc, s->filestream,&uData) != UNZ_OK)
        err=UNZ_ERRNO;

    if (unz64local_getLong(&s->z_filefunc, s->filestream,&uData) != UNZ_OK)
        err=UNZ_ERRNO;
    else if ((uData!=0) && (err==UNZ_OK) && (uData!=s->cur_file_info.crc))
        err=UNZ_BADZIPFILE;

    if (unz64local_getLong(&s->z_filefunc, s->filestream,&uData) != UNZ_OK)
        err=UNZ_ERRNO;
    else if (uData != 0xFFFFFFFF && (err==UNZ_OK) && (uData!=s->cur_file_info.compressed_size))
        err=UNZ_BADZIPFILE;

    if (unz64local_getLong(&s->z_filefunc, s->filestream,&uData) != UNZ_OK)
        err=UNZ_ERRNO;
    else if (uData != 0xFFFFFFFF && (err==UNZ_OK) && (uData!=s->cur_file_info.uncompressed_size))
        err=UNZ_BADZIPFILE;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&size_filename) != UNZ_OK)
        err=UNZ_ERRNO;
    else if ((err==UNZ_OK) && (size_filename!=s->cur_file_info.size_filename))
        err=UNZ_BADZIPFILE;

    *piSizeVar += (uInt)size_filename;

    if (unz64local_getShort(&s->z_filefunc, s->filestream,&size_extra_field) != UNZ_OK)
        err=UNZ_ERRNO;
    *poffset_local_extrafield= s->cur_file_info_internal.pos_in_zip_directory +
                                    SIZEZIPLOCALHEADER + size_filename;
    *psize_local_extrafield = (uInt)size_extra_field;

    *piSizeVar += (uInt)size_extra_field;

    return err;
}

int ZEXPORT unzOpenCurrentFile3 (unzFile file, int* method, int* level, int raw, const char* password)
{
    int err=UNZ_OK;
    uInt iSizeVar;
    unz64_internal* s;
    file_in_zip64_read_info_s* pfile_in_zip_read_info;
    ZPOS64_T offset_local_extrafield;
    uInt  size_local_extrafield;
    (void)password;

    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    if (!s->current_file_ok)
        return UNZ_PARAMERROR;

    if (s->pfile_in_zip_read != NULL)
        unzCloseCurrentFile(file);

    if (unz64local_CheckCurrentFileCoherencyHeader(s,&iSizeVar,&offset_local_extrafield,&size_local_extrafield)!=UNZ_OK)
        return UNZ_BADZIPFILE;

    pfile_in_zip_read_info = (file_in_zip64_read_info_s*)ALLOC(sizeof(file_in_zip64_read_info_s));
    if (pfile_in_zip_read_info==NULL)
        return UNZ_INTERNALERROR;

    pfile_in_zip_read_info->read_buffer=(char*)ALLOC(UNZ_BUFSIZE);
    pfile_in_zip_read_info->offset_local_extrafield = offset_local_extrafield;
    pfile_in_zip_read_info->size_local_extrafield = size_local_extrafield;
    pfile_in_zip_read_info->pos_local_extrafield=0;
    pfile_in_zip_read_info->raw=raw;

    if (pfile_in_zip_read_info->read_buffer==NULL)
    {
        TRYFREE(pfile_in_zip_read_info);
        return UNZ_INTERNALERROR;
    }

    pfile_in_zip_read_info->stream_initialised=0;

    if (method!=NULL)
        *method = (int)s->cur_file_info.compression_method;

    if (level!=NULL)
    {
        *level = 6;
        switch (s->cur_file_info.flag & 0x06)
        {
          case 6 : *level = 1; break;
          case 4 : *level = 2; break;
          case 2 : *level = 9; break;
        }
    }

    if ((s->cur_file_info.compression_method!=0) &&
        (s->cur_file_info.compression_method!=Z_DEFLATED))
        err=UNZ_BADZIPFILE;

    pfile_in_zip_read_info->crc32_wait=s->cur_file_info.crc;
    pfile_in_zip_read_info->crc32=0;
    pfile_in_zip_read_info->total_out_64=0;
    pfile_in_zip_read_info->compression_method = s->cur_file_info.compression_method;
    pfile_in_zip_read_info->filestream=s->filestream;
    pfile_in_zip_read_info->z_filefunc=s->z_filefunc;
    pfile_in_zip_read_info->byte_before_the_zipfile=s->byte_before_the_zipfile;

    pfile_in_zip_read_info->stream.total_out = 0;

    if ((s->cur_file_info.compression_method==Z_DEFLATED) && (!raw))
    {
        pfile_in_zip_read_info->stream.zalloc = (alloc_func)0;
        pfile_in_zip_read_info->stream.zfree = (free_func)0;
        pfile_in_zip_read_info->stream.opaque = (voidpf)0;
        pfile_in_zip_read_info->stream.next_in = 0;
        pfile_in_zip_read_info->stream.avail_in = 0;

        err=inflateInit2(&pfile_in_zip_read_info->stream, -MAX_WBITS);
        if (err == Z_OK)
            pfile_in_zip_read_info->stream_initialised=Z_DEFLATED;
        else
        {
            TRYFREE(pfile_in_zip_read_info->read_buffer);
            TRYFREE(pfile_in_zip_read_info);
            return err;
        }
    }
    pfile_in_zip_read_info->rest_read_compressed =
            s->cur_file_info.compressed_size ;
    pfile_in_zip_read_info->rest_read_uncompressed =
            s->cur_file_info.uncompressed_size ;

    pfile_in_zip_read_info->pos_in_zipfile =
            s->cur_file_info_internal.pos_in_zip_directory + SIZEZIPLOCALHEADER +
              iSizeVar;

    pfile_in_zip_read_info->stream.avail_in = (uInt)0;

    s->pfile_in_zip_read = pfile_in_zip_read_info;

    return UNZ_OK;
}

int ZEXPORT unzOpenCurrentFile (unzFile file)
{
    return unzOpenCurrentFile3(file, NULL, NULL, 0, NULL);
}

int ZEXPORT unzOpenCurrentFilePassword (unzFile file, const char* password)
{
    return unzOpenCurrentFile3(file, NULL, NULL, 0, password);
}

int ZEXPORT unzOpenCurrentFile2 (unzFile file, int* method, int* level, int raw)
{
    return unzOpenCurrentFile3(file, method, level, raw, NULL);
}

ZPOS64_T ZEXPORT unzGetCurrentFileZStreamPos64 (unzFile file)
{
    unz64_internal* s;
    file_in_zip64_read_info_s* pfile_in_zip_read_info;
    s=(unz64_internal*)file;
    if (file==NULL)
        return 0;
    pfile_in_zip_read_info=s->pfile_in_zip_read;
    if (pfile_in_zip_read_info==NULL)
        return 0;
    return pfile_in_zip_read_info->pos_in_zipfile +
                                 pfile_in_zip_read_info->byte_before_the_zipfile;
}

int ZEXPORT unzReadCurrentFile  (unzFile file, voidp buf, unsigned len)
{
    int err=UNZ_OK;
    uInt iRead = 0;
    unz64_internal* s;
    file_in_zip64_read_info_s* pfile_in_zip_read_info;
    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    pfile_in_zip_read_info=s->pfile_in_zip_read;

    if (pfile_in_zip_read_info==NULL)
        return UNZ_PARAMERROR;

    if (pfile_in_zip_read_info->read_buffer == NULL)
        return UNZ_END_OF_LIST_OF_FILE;
    if (len==0)
        return 0;

    pfile_in_zip_read_info->stream.next_out = (Bytef*)buf;

    pfile_in_zip_read_info->stream.avail_out = (uInt)len;

    if ((len>pfile_in_zip_read_info->rest_read_uncompressed) &&
        (!(pfile_in_zip_read_info->raw)))
        pfile_in_zip_read_info->stream.avail_out =
            (uInt)pfile_in_zip_read_info->rest_read_uncompressed;

    if ((len>pfile_in_zip_read_info->rest_read_compressed+
           pfile_in_zip_read_info->stream.avail_in) &&
         (pfile_in_zip_read_info->raw))
        pfile_in_zip_read_info->stream.avail_out =
            (uInt)pfile_in_zip_read_info->rest_read_compressed+
            pfile_in_zip_read_info->stream.avail_in;

    while (pfile_in_zip_read_info->stream.avail_out>0)
    {
        if ((pfile_in_zip_read_info->stream.avail_in==0) &&
            (pfile_in_zip_read_info->rest_read_compressed>0))
        {
            uInt uReadThis = UNZ_BUFSIZE;
            if (pfile_in_zip_read_info->rest_read_compressed<uReadThis)
                uReadThis = (uInt)pfile_in_zip_read_info->rest_read_compressed;
            if (uReadThis == 0)
                return UNZ_EOF;
            if (ZSEEK64(pfile_in_zip_read_info->z_filefunc,
                      pfile_in_zip_read_info->filestream,
                      pfile_in_zip_read_info->pos_in_zipfile +
                         pfile_in_zip_read_info->byte_before_the_zipfile,
                         ZLIB_FILEFUNC_SEEK_SET)!=0)
                return UNZ_ERRNO;
            if (ZREAD64(pfile_in_zip_read_info->z_filefunc,
                      pfile_in_zip_read_info->filestream,
                      pfile_in_zip_read_info->read_buffer,
                      uReadThis)!=uReadThis)
                return UNZ_ERRNO;

            pfile_in_zip_read_info->pos_in_zipfile += uReadThis;

            pfile_in_zip_read_info->rest_read_compressed-=uReadThis;

            pfile_in_zip_read_info->stream.next_in =
                (Bytef*)pfile_in_zip_read_info->read_buffer;
            pfile_in_zip_read_info->stream.avail_in = (uInt)uReadThis;
        }

        if ((pfile_in_zip_read_info->compression_method==0) || (pfile_in_zip_read_info->raw))
        {
            uInt uDoCopy,i ;

            if ((pfile_in_zip_read_info->stream.avail_in == 0) &&
                (pfile_in_zip_read_info->rest_read_compressed == 0))
                return (iRead==0) ? UNZ_EOF : (int)iRead;

            if (pfile_in_zip_read_info->stream.avail_out <
                            pfile_in_zip_read_info->stream.avail_in)
                uDoCopy = pfile_in_zip_read_info->stream.avail_out ;
            else
                uDoCopy = pfile_in_zip_read_info->stream.avail_in ;

            for (i=0;i<uDoCopy;i++)
                *(pfile_in_zip_read_info->stream.next_out+i) =
                        *(pfile_in_zip_read_info->stream.next_in+i);

            pfile_in_zip_read_info->total_out_64 = pfile_in_zip_read_info->total_out_64 + uDoCopy;

            pfile_in_zip_read_info->crc32 = crc32(pfile_in_zip_read_info->crc32,
                                pfile_in_zip_read_info->stream.next_out,
                                uDoCopy);
            pfile_in_zip_read_info->rest_read_uncompressed-=uDoCopy;
            pfile_in_zip_read_info->stream.avail_in -= uDoCopy;
            pfile_in_zip_read_info->stream.avail_out -= uDoCopy;
            pfile_in_zip_read_info->stream.next_out += uDoCopy;
            pfile_in_zip_read_info->stream.next_in += uDoCopy;
            pfile_in_zip_read_info->stream.total_out += uDoCopy;
            iRead += uDoCopy;
        }
        else if (pfile_in_zip_read_info->compression_method==Z_DEFLATED)
        {
            ZPOS64_T uTotalOutBefore,uTotalOutAfter;
            const Bytef *bufBefore;
            ZPOS64_T uOutThis;
            int flush=Z_SYNC_FLUSH;

            uTotalOutBefore = pfile_in_zip_read_info->stream.total_out;
            bufBefore = pfile_in_zip_read_info->stream.next_out;

            err=inflate(&pfile_in_zip_read_info->stream,flush);

            if ((err>=0) && (pfile_in_zip_read_info->stream.msg!=NULL))
              err = Z_DATA_ERROR;

            uTotalOutAfter = pfile_in_zip_read_info->stream.total_out;
            uOutThis = uTotalOutAfter-uTotalOutBefore;

            pfile_in_zip_read_info->total_out_64 = pfile_in_zip_read_info->total_out_64 + uOutThis;

            pfile_in_zip_read_info->crc32 =
                crc32(pfile_in_zip_read_info->crc32,bufBefore,
                        (uInt)(uOutThis));

            pfile_in_zip_read_info->rest_read_uncompressed -=
                uOutThis;

            iRead += (uInt)(uTotalOutAfter - uTotalOutBefore);

            if (err==Z_STREAM_END)
                return (iRead==0) ? UNZ_EOF : (int)iRead;
            if (err!=Z_OK)
                break;
        }
    }

    if (err==Z_OK)
        return (int)iRead;
    return err;
}

z_off_t ZEXPORT unztell (unzFile file)
{
    unz64_internal* s;
    file_in_zip64_read_info_s* pfile_in_zip_read_info;
    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    pfile_in_zip_read_info=s->pfile_in_zip_read;

    if (pfile_in_zip_read_info==NULL)
        return UNZ_PARAMERROR;

    return (z_off_t)pfile_in_zip_read_info->stream.total_out;
}

ZPOS64_T ZEXPORT unztell64 (unzFile file)
{
    unz64_internal* s;
    file_in_zip64_read_info_s* pfile_in_zip_read_info;
    if (file==NULL)
        return (ZPOS64_T)-1;
    s=(unz64_internal*)file;
    pfile_in_zip_read_info=s->pfile_in_zip_read;

    if (pfile_in_zip_read_info==NULL)
        return (ZPOS64_T)-1;

    return pfile_in_zip_read_info->total_out_64;
}

int ZEXPORT unzeof (unzFile file)
{
    unz64_internal* s;
    file_in_zip64_read_info_s* pfile_in_zip_read_info;
    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    pfile_in_zip_read_info=s->pfile_in_zip_read;

    if (pfile_in_zip_read_info==NULL)
        return UNZ_PARAMERROR;

    if (pfile_in_zip_read_info->rest_read_uncompressed == 0)
        return 1;
    return 0;
}

int ZEXPORT unzCloseCurrentFile (unzFile file)
{
    int err=UNZ_OK;

    unz64_internal* s;
    file_in_zip64_read_info_s* pfile_in_zip_read_info;
    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    pfile_in_zip_read_info=s->pfile_in_zip_read;

    if (pfile_in_zip_read_info==NULL)
        return UNZ_PARAMERROR;

    if ((pfile_in_zip_read_info->rest_read_uncompressed == 0) &&
        (!pfile_in_zip_read_info->raw))
    {
        if (pfile_in_zip_read_info->crc32 != pfile_in_zip_read_info->crc32_wait)
            err=UNZ_CRCERROR;
    }

    TRYFREE(pfile_in_zip_read_info->read_buffer);
    pfile_in_zip_read_info->read_buffer = NULL;
    if (pfile_in_zip_read_info->stream_initialised == Z_DEFLATED)
        inflateEnd(&pfile_in_zip_read_info->stream);

    pfile_in_zip_read_info->stream_initialised = 0;
    TRYFREE(pfile_in_zip_read_info);

    s->pfile_in_zip_read=NULL;

    return err;
}

int ZEXPORT unzGetGlobalComment (unzFile file, char *szComment, uLong uSizeBuf)
{
    unz64_internal* s;
    uLong uReadThis ;
    if (file==NULL)
        return (int)UNZ_PARAMERROR;
    s=(unz64_internal*)file;

    uReadThis = uSizeBuf;
    if (uReadThis>s->gi.size_comment)
        uReadThis = s->gi.size_comment;

    if (ZSEEK64(s->z_filefunc,s->filestream,s->central_pos+22,ZLIB_FILEFUNC_SEEK_SET)!=0)
        return UNZ_ERRNO;

    if (uReadThis>0)
    {
      *szComment='\0';
      if (ZREAD64(s->z_filefunc,s->filestream,szComment,uReadThis)!=uReadThis)
        return UNZ_ERRNO;
    }

    if ((szComment != NULL) && (uSizeBuf > s->gi.size_comment))
        *(szComment+s->gi.size_comment)='\0';
    return (int)uReadThis;
}

ZPOS64_T ZEXPORT unzGetOffset64 (unzFile file)
{
    unz64_internal* s;

    if (file==NULL)
          return (ZPOS64_T)-1;
    s=(unz64_internal*)file;
    if (!s->current_file_ok)
      return (ZPOS64_T)-1;
    if (s->gi.number_entry != 0 && s->gi.number_entry != 0xffff)
      if (s->num_file==s->gi.number_entry)
         return (ZPOS64_T)-1;
    return s->pos_in_central_dir;
}

uLong ZEXPORT unzGetOffset (unzFile file)
{
    ZPOS64_T offset64;

    if (file==NULL)
          return (uLong)-1;
    offset64 = unzGetOffset64(file);
    return (uLong)offset64;
}

int ZEXPORT unzSetOffset64 (unzFile file, ZPOS64_T pos)
{
    unz64_internal* s;
    int err;

    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;

    s->pos_in_central_dir = pos;
    s->num_file = s->gi.number_entry;
    err = unz64local_GetCurrentFileInfoInternal(file,&s->cur_file_info,
                                                &s->cur_file_info_internal,
                                                NULL,0,NULL,0,NULL,0);
    s->current_file_ok = (err == UNZ_OK);
    return err;
}

int ZEXPORT unzSetOffset (unzFile file, uLong pos)
{
    return unzSetOffset64(file,pos);
}

int ZEXPORT unzGetLocalExtrafield (unzFile file, voidp buf, unsigned len)
{
    unz64_internal* s;
    file_in_zip64_read_info_s* pfile_in_zip_read_info;
    uInt read_now;
    ZPOS64_T size_to_read;

    if (file==NULL)
        return UNZ_PARAMERROR;
    s=(unz64_internal*)file;
    pfile_in_zip_read_info=s->pfile_in_zip_read;

    if (pfile_in_zip_read_info==NULL)
        return UNZ_PARAMERROR;

    size_to_read = (pfile_in_zip_read_info->size_local_extrafield -
                pfile_in_zip_read_info->pos_local_extrafield);

    if (buf==NULL)
        return (int)size_to_read;

    if (len>size_to_read)
        read_now = (uInt)size_to_read;
    else
        read_now = (uInt)len ;

    if (read_now==0)
        return 0;

    if (ZSEEK64(pfile_in_zip_read_info->z_filefunc,
              pfile_in_zip_read_info->filestream,
              pfile_in_zip_read_info->offset_local_extrafield +
              pfile_in_zip_read_info->pos_local_extrafield,
              ZLIB_FILEFUNC_SEEK_SET)!=0)
        return UNZ_ERRNO;

    if (ZREAD64(pfile_in_zip_read_info->z_filefunc,
              pfile_in_zip_read_info->filestream,
              buf,read_now)!=read_now)
        return UNZ_ERRNO;

    return (int)read_now;
}
