/* ioapi.c -- IO base function for compress/uncompress .zip
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

#if defined(_WIN32) && (!(defined(_CRT_SECURE_NO_WARNINGS)))
  #define _CRT_SECURE_NO_WARNINGS
#endif

#if defined(__APPLE__) || defined(IOAPI_NO_64)
  #define fopen64 fopen
  #define ftello64 ftello
  #define fseeko64 fseeko
#endif

#include "ioapi.h"

voidpf call_zopen64 (const zlib_filefunc64_def* pfilefunc,const void*filename,int mode)
{
    if (pfilefunc->zopen64_file != NULL)
        return (*(pfilefunc->zopen64_file)) (pfilefunc->opaque,filename,mode);
    return NULL;
}

long call_zseek64 (const zlib_filefunc64_def* pfilefunc,voidpf filestream, ZPOS64_T offset, int origin)
{
    if (pfilefunc->zseek64_file != NULL)
        return (*(pfilefunc->zseek64_file)) (pfilefunc->opaque,filestream,offset,origin);
    return -1;
}

ZPOS64_T call_ztell64 (const zlib_filefunc64_def* pfilefunc,voidpf filestream)
{
    if (pfilefunc->ztell64_file != NULL)
        return (*(pfilefunc->ztell64_file)) (pfilefunc->opaque,filestream);
    return (ZPOS64_T)-1;
}

static voidpf  ZCALLBACK fopen_file_func OF((voidpf opaque, const char* filename, int mode));
static uLong   ZCALLBACK fread_file_func OF((voidpf opaque, voidpf stream, void* buf, uLong size));
static uLong   ZCALLBACK fwrite_file_func OF((voidpf opaque, voidpf stream, const void* buf, uLong size));
static ZPOS64_T ZCALLBACK ftell64_file_func OF((voidpf opaque, voidpf stream));
static long    ZCALLBACK fseek64_file_func OF((voidpf opaque, voidpf stream, ZPOS64_T offset, int origin));
static int     ZCALLBACK fclose_file_func OF((voidpf opaque, voidpf stream));
static int     ZCALLBACK ferror_file_func OF((voidpf opaque, voidpf stream));

static voidpf ZCALLBACK fopen_file_func (voidpf opaque, const char* filename, int mode)
{
    FILE* file = NULL;
    const char* mode_fopen = NULL;
    (void)opaque;
    if ((mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER)==ZLIB_FILEFUNC_MODE_READ)
        mode_fopen = "rb";
    else
    if (mode & ZLIB_FILEFUNC_MODE_EXISTING)
        mode_fopen = "r+b";
    else
    if (mode & ZLIB_FILEFUNC_MODE_CREATE)
        mode_fopen = "wb";

    if ((filename!=NULL) && (mode_fopen != NULL))
        file = fopen(filename, mode_fopen);
    return file;
}

static voidpf ZCALLBACK fopen64_file_func (voidpf opaque, const void* filename, int mode)
{
    FILE* file = NULL;
    const char* mode_fopen = NULL;
    (void)opaque;
    if ((mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER)==ZLIB_FILEFUNC_MODE_READ)
        mode_fopen = "rb";
    else
    if (mode & ZLIB_FILEFUNC_MODE_EXISTING)
        mode_fopen = "r+b";
    else
    if (mode & ZLIB_FILEFUNC_MODE_CREATE)
        mode_fopen = "wb";

    if ((filename!=NULL) && (mode_fopen != NULL))
        file = fopen64((const char*)filename, mode_fopen);
    return file;
}

static uLong ZCALLBACK fread_file_func (voidpf opaque, voidpf stream, void* buf, uLong size)
{
    uLong ret;
    (void)opaque;
    ret = (uLong)fread(buf, 1, (size_t)size, (FILE *)stream);
    return ret;
}

static uLong ZCALLBACK fwrite_file_func (voidpf opaque, voidpf stream, const void* buf, uLong size)
{
    uLong ret;
    (void)opaque;
    ret = (uLong)fwrite(buf, 1, (size_t)size, (FILE *)stream);
    return ret;
}

static long ZCALLBACK ftell_file_func (voidpf opaque, voidpf stream)
{
    long ret;
    (void)opaque;
    ret = ftell((FILE *)stream);
    return ret;
}

static ZPOS64_T ZCALLBACK ftell64_file_func (voidpf opaque, voidpf stream)
{
    ZPOS64_T ret;
    (void)opaque;
    ret = (ZPOS64_T)ftello64((FILE *)stream);
    return ret;
}

static long ZCALLBACK fseek_file_func (voidpf opaque, voidpf stream, uLong offset, int origin)
{
    int fseek_origin=0;
    long ret;
    (void)opaque;
    switch (origin)
    {
    case ZLIB_FILEFUNC_SEEK_CUR :
        fseek_origin = SEEK_CUR;
        break;
    case ZLIB_FILEFUNC_SEEK_END :
        fseek_origin = SEEK_END;
        break;
    case ZLIB_FILEFUNC_SEEK_SET :
        fseek_origin = SEEK_SET;
        break;
    default: return -1;
    }
    ret = 0;
    if (fseek((FILE *)stream, (long)offset, fseek_origin) != 0)
        ret = -1;
    return ret;
}

static long ZCALLBACK fseek64_file_func (voidpf opaque, voidpf stream, ZPOS64_T offset, int origin)
{
    int fseek_origin=0;
    long ret;
    (void)opaque;
    switch (origin)
    {
    case ZLIB_FILEFUNC_SEEK_CUR :
        fseek_origin = SEEK_CUR;
        break;
    case ZLIB_FILEFUNC_SEEK_END :
        fseek_origin = SEEK_END;
        break;
    case ZLIB_FILEFUNC_SEEK_SET :
        fseek_origin = SEEK_SET;
        break;
    default: return -1;
    }
    ret = 0;
    if(fseeko64((FILE *)stream, (off_t)offset, fseek_origin) != 0)
        ret = -1;
    return ret;
}

static int ZCALLBACK fclose_file_func (voidpf opaque, voidpf stream)
{
    int ret;
    (void)opaque;
    ret = fclose((FILE *)stream);
    return ret;
}

static int ZCALLBACK ferror_file_func (voidpf opaque, voidpf stream)
{
    int ret;
    (void)opaque;
    ret = ferror((FILE *)stream);
    return ret;
}

void fill_fopen_filefunc (zlib_filefunc_def* pzlib_filefunc_def)
{
    pzlib_filefunc_def->zopen_file = fopen_file_func;
    pzlib_filefunc_def->zread_file = fread_file_func;
    pzlib_filefunc_def->zwrite_file = fwrite_file_func;
    pzlib_filefunc_def->ztell_file = ftell_file_func;
    pzlib_filefunc_def->zseek_file = fseek_file_func;
    pzlib_filefunc_def->zclose_file = fclose_file_func;
    pzlib_filefunc_def->zerror_file = ferror_file_func;
    pzlib_filefunc_def->opaque = NULL;
}

void fill_fopen64_filefunc (zlib_filefunc64_def* pzlib_filefunc_def)
{
    pzlib_filefunc_def->zopen64_file = fopen64_file_func;
    pzlib_filefunc_def->zread_file = fread_file_func;
    pzlib_filefunc_def->zwrite_file = fwrite_file_func;
    pzlib_filefunc_def->ztell64_file = ftell64_file_func;
    pzlib_filefunc_def->zseek64_file = fseek64_file_func;
    pzlib_filefunc_def->zclose_file = fclose_file_func;
    pzlib_filefunc_def->zerror_file = ferror_file_func;
    pzlib_filefunc_def->opaque = NULL;
}

void fill_zlib_filefunc64_32_def_from_filefunc32(zlib_filefunc64_def* p_filefunc64, const zlib_filefunc_def* p_filefunc32)
{
    p_filefunc64->zopen64_file = (open64_file_func)p_filefunc32->zopen_file;
    p_filefunc64->zread_file = p_filefunc32->zread_file;
    p_filefunc64->zwrite_file = p_filefunc32->zwrite_file;
    p_filefunc64->ztell64_file = (tell64_file_func)p_filefunc32->ztell_file;
    p_filefunc64->zseek64_file = (seek64_file_func)p_filefunc32->zseek_file;
    p_filefunc64->zclose_file = p_filefunc32->zclose_file;
    p_filefunc64->zerror_file = p_filefunc32->zerror_file;
    p_filefunc64->opaque = p_filefunc32->opaque;
}
