/*
    Copyright 2012-2019 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

//#define NOLFS
#ifndef NOLFS   // 64 bit file support not really needed since the tool uses signed 32 bits at the moment, anyway I leave it enabled
    #define _LARGE_FILES        // if it's not supported the tool will work
    #define __USE_LARGEFILE64   // without support for large files
    #define __USE_FILE_OFFSET64
    #define _LARGEFILE_SOURCE
    #define _LARGEFILE64_SOURCE
    #define _FILE_OFFSET_BITS   64
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <errno.h>
#include <zlib.h>
#define LZ4F_DISABLE_OBSOLETE_ENUMS
#include "lz4.h"

#ifdef WIN32
    #include <windows.h>
    #include <direct.h>
    #define PATHSLASH   '\\'
    #define make_dir(x) mkdir(x)
#else
    #include <dirent.h>
    #define stricmp     strcasecmp
    #define strnicmp    strncasecmp
    #define stristr     strcasestr
    #define PATHSLASH   '/'
    #define make_dir(x) mkdir(x, 0755)
#endif

#if defined(_LARGE_FILES)
    #if defined(__APPLE__)
        #define fseek   fseeko
        #define ftell   ftello
    #elif defined(__FreeBSD__)
    #elif !defined(NOLFS)       // use -DNOLFS if this tool can't be compiled on your OS!
        #define off_t   off64_t
        #define fopen   fopen64
        #define fseek   fseeko64
        #define ftell   ftello64
        #ifndef fstat
            #ifdef WIN32
                #define fstat   _fstati64
                #define stat    _stati64
            #else
                #define fstat   fstat64
                #define stat    stat64
            #endif
        #endif
    #endif
#endif

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;



#define VER         "0.3.1"
#define DBG_PRINT   printf("%010"PRIx64": %016"PRIx64"\n", old_off, (u64)ret);  // 010 is ok for offset



void set_unigine_key(u8 *str);
int unigine_extract(FILE *fd, int is_encrypted);
int dumpa(u8 *fname, u8 *data, int size);
int check_wildcard(u8 *fname, u8 *wildcard);
u8 *create_dir(u8 *name);
int check_overwrite(u8 *fname);
void myalloc(u8 **data, u32 wantsize, u32 *currsize);
int myfr(FILE *fd, u8 *data, int size);
int myfw(FILE *fd, u8 *data, int size);
u64 fgetxx(FILE *fd, int bits);
int get_num(u8 *str);
void std_err(void);
uint32_t mycrc32(unsigned char *data, int size);
int unbase64(u8 *in, int insz, u8 *out, int outsz);



signed char *unigine_key    = NULL;
int     unigine_key_len     = 0;
u32     unigine_seed        = 0xa13cdbde;
int     list_only           = 0,
        force_overwrite     = 0,
        verbose             = 0,
        ver                 = 0;
u8      *filter_files       = NULL,
        *try_key_file       = NULL;



enum {
    UNIGINE_COMTYPE_NONE    = 0,
    UNIGINE_COMTYPE_LZ4,
    UNIGINE_COMTYPE_ZLIB,
    //
    UNIGINE_COMTYPE_INVALID
};



typedef struct {
    u8      *name;
    u8      *key;
} try_keys_t;
static const try_keys_t try_keys[] = {
    { "Cradle",         "fS5g_2gDc*" },
    { "Sumoman",        "1EuCM90tADY6uxkJHXyCGj0PcJ1EWzvL" },
    { "Superposition",  "ieNgeivaep9eima7ze8m" },   // "eNrLTPVLT80sS0wtsEzNzE00r0q1yAUAUNUHjg==" in Unigine_x64.dll
    { "Oil Rush",       "CF29hity73GT640LP1dlfu55gzxyeuas" },
    { NULL, NULL }
};



int main(int argc, char *argv[]) {
    FILE    *fd;
    u32     extracted_files;
    int     i,
            is_encrypted    = 1;
    u8      *fname,
            *fdir   = NULL;

    //setbuf(stdout, NULL); // disabled for better performances

    fputs("\n"
        "Unigine ung files extractor " VER "\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

    if(argc < 3) {
        printf("\n"
            "Usage: %s [options] <file.UNG> [output_folder]\n"
            "\n"
            "Options:\n"
            "-l      list the files without extracting them, you can use . as output folder\n"
            "-f W    filter the files to extract using the W wildcard, example -f \"*.oga\"\n"
            "-o      if the output files already exist this option will overwrite them\n"
            "        automatically without prompting for confirmation\n"
            "-k K    specify a custom key, default is %s\n"
            "-K FILE scan the text file looking for the custom key\n"
            "-s K    specify a custom seed, default is 0x%08x\n"
            "-v      verbose debug information\n"
            "-d      disable encryption is file data\n"
            "\n"
            "The tool automatically tries the known keys of the following games:\n",
            argv[0],
            unigine_key,
            unigine_seed);
        for(i = 0; try_keys[i].name; i++) {
            printf("  %s\n", try_keys[i].name);
        }
        printf("\n");
        exit(1);
    }

    for(i = 1; i < argc; i++) {
        if(((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) {
            //printf("\nError: wrong argument (%s)\n", argv[i]);
            //exit(1);
            break;  // needed for optional output_folder
        }
        switch(argv[i][1]) {
            case 'l': list_only         = 1;                    break;
            case 'f': filter_files      = argv[++i];            break;
            case 'o': force_overwrite   = 1;                    break;
            case 'k': set_unigine_key(argv[++i]);               break;
            case 'K': try_key_file      = argv[++i];            break;
            case 's': unigine_seed      = get_num(argv[++i]);   break;
            case 'v': verbose           = 1;                    break;
            case 'd': is_encrypted      = 0;                    break;
            default: {
                printf("\nError: wrong argument (%s)\n", argv[i]);
                exit(1);
            }
        }
    }

    fname = argv[i++];
    if(i < argc) {
        fdir = argv[i++];   // not really necessary
    }

    if(!fname || (fname[0] == '-')) {
        printf("\nError: you must specify also the output folder, use . for current one\n");
        exit(1);
    }

    printf("- open file %s\n", fname);
    fd = fopen(fname, "rb");
    if(!fd) std_err();

    if(!list_only) {
        if(fdir) {
            printf("- set output folder %s\n", fdir);
            if(chdir(fdir) < 0) std_err();
        }
    }

    extracted_files = unigine_extract(fd, is_encrypted);
    printf("\n- %u files extracted\n", extracted_files);

    fclose(fd);
    printf("- done\n");
    return 0;
}



void set_unigine_key(u8 *str) {
    if(!str || !str[0]) return;
    printf("- set key: %s\n", str);
    unigine_key     = str;
    unigine_key_len = strlen(unigine_key);
}



// Unigine::Resource::load()
void set_unigine_key2(u8 *str) {
    if(!str || !str[0]) return;
    static  u8  key[256 + 1];   // static yes
    u8      tmp[256 + 1];
    uLongf  ztmp;
    int     len;

    len = unbase64(str, -1, tmp, sizeof(tmp));
    ztmp = sizeof(key);
    if(uncompress(key, &ztmp, tmp, len) == Z_OK) {
        key[ztmp] = 0;
    } else {
        strcpy(key, tmp);
    }
    int i;
    for(i = 0; key[i]; i++) {
        if(key[i] < ' ') return;    // invalid key
    }
    set_unigine_key(key);
}



u32 unigine_seed_next(int do_scramble) {
    unigine_seed *= 0x6b982;
    unigine_seed %= 0x7fffffab; // 0xAA000070E5 is the constant for modulus

    if(do_scramble && unigine_key && unigine_key_len) {
        if(ver <= 3) unigine_seed += ((signed char)unigine_key[(unigine_seed >> 0xd) % unigine_key_len] + (unigine_key_len << 8)) * 8;
        else         unigine_seed += (unigine_key_len << 0xb) + ((signed char)unigine_key[(unigine_seed >> 0xd) % unigine_key_len] * 8);
    }

    return unigine_seed;
}



void unigine_seed_do(u8 *ret, u8 al, int mode) {
    u8      c;

    al &= 7;
    c = *ret;
    if(mode) *ret = (c << al) | (c >> (8 - al));    // ROL
    else     *ret = (c >> al) | (c << (8 - al));    // ROR
}



u64 getxx(u8 *tmp, int bytes) {
    u64     ret;
    int     i;

    ret = 0;
    for(i = 0; i < bytes; i++) {
        if(i >= (int)sizeof(ret)) continue;
        ret |= ((u64)tmp[i] << (u64)(i << (u64)3));
    }
    return ret;
}



u64 fgetxx(FILE *fd, int bits) {
    int     bytes = bits / 8;
    u8      tmp[bytes];

    u64 old_off = ftell(fd);
    myfr(fd, tmp, bytes);
    u64 ret = getxx(tmp, bytes);
    if(verbose) { printf("- fget%-2d ", bits); DBG_PRINT }
    return ret;
}



u32 unigine_get32(FILE *fd) {
    u8      tmp[4];

    u64     old_off = ftell(fd);
    myfr(fd, &tmp[3], 1);
    myfr(fd, &tmp[2], 1);
    myfr(fd, &tmp[0], 1);
    myfr(fd, &tmp[1], 1);

    unigine_seed_do(&tmp[1], unigine_seed, 0);  unigine_seed_next(1);
    unigine_seed_do(&tmp[3], unigine_seed, 1);  unigine_seed_next(1);
    unigine_seed_do(&tmp[2], unigine_seed, 0);  unigine_seed_next(1);
    unigine_seed_do(&tmp[0], unigine_seed, 1);  unigine_seed_next(1);
    tmp[3] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[0] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[2] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[1] ^= unigine_seed;                     unigine_seed_next(1);

    u64 ret = getxx(tmp, sizeof(tmp));
    if(verbose) { printf("- get32  "); DBG_PRINT }
    return ret;
}



u64 unigine_get64(FILE *fd) {
    u8      tmp[8];

    u64     old_off = ftell(fd);
    myfr(fd, &tmp[7], 1);
    myfr(fd, &tmp[6], 1);
    myfr(fd, &tmp[4], 1);
    myfr(fd, &tmp[5], 1);
    myfr(fd, &tmp[3], 1);
    myfr(fd, &tmp[2], 1);
    myfr(fd, &tmp[0], 1);
    myfr(fd, &tmp[1], 1);

    unigine_seed_do(&tmp[5], unigine_seed, 0);  unigine_seed_next(1);
    unigine_seed_do(&tmp[7], unigine_seed, 1);  unigine_seed_next(1);
    unigine_seed_do(&tmp[4], unigine_seed, 0);  unigine_seed_next(1);
    unigine_seed_do(&tmp[6], unigine_seed, 1);  unigine_seed_next(1);
    unigine_seed_do(&tmp[1], unigine_seed, 0);  unigine_seed_next(1);
    unigine_seed_do(&tmp[3], unigine_seed, 1);  unigine_seed_next(1);
    unigine_seed_do(&tmp[2], unigine_seed, 0);  unigine_seed_next(1);
    unigine_seed_do(&tmp[0], unigine_seed, 1);  unigine_seed_next(1);
    tmp[7] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[6] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[4] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[5] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[3] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[0] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[2] ^= unigine_seed;                     unigine_seed_next(1);
    tmp[1] ^= unigine_seed;                     unigine_seed_next(1);

    u64 ret = getxx(tmp, sizeof(tmp));
    if(verbose) { printf("- get64  "); DBG_PRINT }
    return ret;
}



int unigine_getss(FILE *fd, u8 *data, int size) {
    int     len;
    u8      c,
            old = 0;

    u64 old_off = ftell(fd);
    size--; // NULL byte
    for(len = 0;; len++) {
        myfr(fd, &c, 1);

        unigine_seed_do(&c, unigine_seed + old, (len + old) & 1);
        c ^= (unigine_seed_next(0) + old);
        unigine_seed_next(0);
        old = c;

        if(len < size) data[len] = c;
        if(!c) break;
    }
    data[size] = 0; // useless, only in case len > size
    if(verbose) printf("- getss  %08"PRIx64": %s\n", old_off, data);
    return len;
}



int unigine_getmm(FILE *fd, u8 *data, int size, int is_encrypted) {
    int     i;
    u8      c,
            old = 0;

    myfr(fd, data, size);
    if(is_encrypted) {
        for(i = 0; i < size; i++) {
            c = data[i];

            if((i ^ old) & 1) {
                unigine_seed_do(&c, unigine_seed + old, 1);
            } else {
                unigine_seed_do(&c, unigine_seed - old, 0);
            }
            c ^= (unigine_seed_next(0) - old);
            unigine_seed_next(0);
            old = c;

            data[i] = c;
        }
    }
    return size;
}



int unigine_extract(FILE *fd, int is_encrypted) {
    uLongf  ztmp;
    FILE    *fd_key     = NULL;
    u64     offset,
            max_offset,
            next_offset;
    u32     name_crc,
            mycrc,
            zsize,
            bsize,
            size,
            mysize,
            files,
            in_size         = 0,
            out_size        = 0,
            extracted_files = 0,
            info_seed,
            data_seed,
            comtype         = UNIGINE_COMTYPE_ZLIB;
    int     t,
            try_key         = 0,
            try_key_mode    = 0;
    u8      fname[0x400 + 1],
            key_file[256 + 1],
            sign[4],
            *in             = NULL,
            *out            = NULL;

    fseek(fd, 0, SEEK_END);
    max_offset = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    myfr(fd, sign, 4);
    if(memcmp(sign, "ar", 2)) {
        printf("\nError: invalid signature (%2.2s), not an UNG archive\n", sign);
        exit(1);
    }

    ver = ((sign[2] - '0') * 10) + (sign[3] - '0');

    if(ver == 3) {
        comtype = UNIGINE_COMTYPE_ZLIB;

    } else if(ver == 4) {
        comtype = fgetxx(fd, 32);
        printf("- compression %d\n", comtype);
        fseek(fd, -8, SEEK_END);
        max_offset = ftell(fd);
        offset = fgetxx(fd, 64);
        fseek(fd, offset, SEEK_SET);

    } else {
        printf("\nError: archive version (%d) is not supported yet\n", ver);
        exit(1);
    }

    printf("\n"
        "  offset     filesize   filename\n"
        "--------------------------------\n");

    info_seed   = unigine_seed; // used for try_key
    data_seed   = unigine_seed; // used for ver >= 4
    for(files = 0;; files++) {
        offset = ftell(fd);
        if(offset >= max_offset) break;
        unigine_seed = info_seed;

        name_crc    = unigine_get32(fd);
        unigine_getss(fd, fname, sizeof(fname));

        mycrc = mycrc32(fname, strlen(fname));
        if(name_crc != mycrc) {
            if(files) {
                printf("\n"
                    "Error: the crc of a filename doesn't match the one in the file. Contact me.\n"
                    "\n");
                exit(1);
            }

            if(unigine_key) try_key_mode++;
            if(try_key_mode & 1) {
                set_unigine_key2(unigine_key);
            } else {
                try_key_mode = 0;
                if(try_key_file) {  // just a lame feature that costs me nothing to implement...
                    if(!fd_key) {
                        fd_key = fopen(try_key_file, "rb");
                        if(!fd_key) std_err();
                    }
                    if(!fgets(key_file, sizeof(key_file), fd_key)) {
                        printf("\nError: no key found in the provided list file %s\n", try_key_file);
                        fclose(fd_key);
                        exit(1);
                    }
                    for(t = strlen(key_file) - 1; t >= 0; t--) {
                        if(key_file[t] <= ' ') key_file[t] = 0; // trim \r \n
                    }
                    set_unigine_key(key_file);
                } else {
                    if(try_keys[try_key].name) {
                        set_unigine_key(try_keys[try_key].key);
                    } else {
                        printf("\n"
                            "Error: the crc of the filename doesn't match the one in the file.\n"
                            "       You must provide the correct key with the -k option.\n"
                            "\n");
                        exit(1);
                    }
                    try_key++;
                }
            }
            fseek(fd, offset, SEEK_SET);
            files--;
            continue;
        }

        size        = unigine_get32(fd);
        info_seed   = unigine_seed;
        zsize       = unigine_get32(fd);
        if(ver <= 3) {
            bsize   = unigine_get32(fd);
            // it's not clear what's the purpose of bsize, Unigine simply checks if bsize is equal than zsize and exits if different
            if(bsize < zsize) {
                t     = bsize;
                bsize = zsize;
                zsize = t;
            }
            /*crc =*/ unigine_get32(fd);    // not dependent by unigine_key_len, differently than ver 4
            offset      = ftell(fd);
            next_offset = offset + bsize;
            //info_seed   =
            data_seed   = unigine_seed;
        } else {
            offset      = unigine_get64(fd);
            next_offset = ftell(fd);
            info_seed   = unigine_seed;
            //data_seed   =
        }

        if(filter_files && (check_wildcard(fname, filter_files) < 0)) {
            // skip
        } else {
            printf("  %010"PRIx64" %-10u %s\n", offset, size, fname);   // 010 for offset is ok

            if(!list_only) {
                if(fseek(fd, offset, SEEK_SET)) std_err();
                myalloc(&in,  zsize, &in_size);

                unigine_seed = data_seed;
                if(ver <= 3) {
                    unigine_getmm(fd, in, zsize, is_encrypted);
                } else {
                    zsize   = unigine_get32(fd);
                    bsize   = unigine_get32(fd);
                    if(is_encrypted) {  // in the past I checked unigine_key_len but it was invalid
                        /*crc =*/ unigine_get32(fd);
                    }
                    unigine_getmm(fd, in, zsize, is_encrypted);
                    unigine_seed = data_seed;
                    data_seed = unigine_seed_next(1);
                }

                if(comtype == UNIGINE_COMTYPE_NONE) {

                    dumpa(fname, in, zsize);

                } else {

                    myalloc(&out, size,  &out_size);

                    // ALL the files are compressed so do NOT use the following
                    //if(size == zsize)

                    if(comtype == UNIGINE_COMTYPE_LZ4) {

                        mysize = LZ4_decompress_safe_partial(in, out, zsize, size, size);

                    } else if(comtype == UNIGINE_COMTYPE_ZLIB) {

                        ztmp = size;
                        if(uncompress(out, &ztmp, in, zsize) != Z_OK) ztmp = -1;
                        mysize = ztmp;

                    } else {

                        printf("\nError: compression %d is not supported yet. Contact me\n", comtype);
                        exit(1);

                    }

                    if(size != mysize) {
                        printf("\nError: something wrong with compression %d (%d %d). Contact me\n", comtype, size, mysize);
                        exit(1);
                    }

                    dumpa(fname, out, size);
                }
            }
            extracted_files++;
        }

        if(fseek(fd, next_offset, SEEK_SET)) std_err();
    }

    return extracted_files;
}



int dumpa(u8 *fname, u8 *data, int size) {
    FILE    *fdo;
    u8      *p;

    // the following is a set of filename cleaning instructions to avoid that files or data with special names are not saved
    if(fname) {
        if(fname[1] == ':') fname += 2;
        for(p = fname; *p && (*p != '\n') && (*p != '\r'); p++) {
            if(strchr("?%*:|\"<>", *p)) {    // invalid filename chars not supported by the most used file systems
                *p = '_';
            }
        }
        *p = 0;
        for(p--; (p >= fname) && ((*p == ' ') || (*p == '.')); p--) *p = 0;   // remove final spaces and dots
    }

    fname = create_dir(fname);
    if(check_overwrite(fname) < 0) return(0);
    fdo = fopen(fname, "wb");
    if(!fdo) std_err();
    myfw(fdo, data, size);
    fclose(fdo);
    return(0);
}



int check_wildcard(u8 *fname, u8 *wildcard) {
    u8      *f      = fname,
            *w      = wildcard,
            *last_w = NULL,
            *last_f = NULL;

    if(!fname) return -1;
    if(!wildcard) return -1;
    while(*f || *w) {
        if(!*w && !last_w) return -1;
        if(*w == '?') {
            if(!*f) break;
            w++;
            f++;
        } else if(*w == '*') {
            w++;
            last_w = w;
            last_f = f;
        } else {
            if(!*f) break;
            if(((*f == '\\') || (*f == '/')) && ((*w == '\\') || (*w == '/'))) {
                f++;
                w++;
            } else if(tolower(*f) != tolower(*w)) {
                if(!last_w) return -1;
                w = last_w;
                if(last_f) f = last_f;
                f++;
                if(last_f) last_f = f;
            } else {
                f++;
                w++;
            }
        }
    }
    if(*f || *w) return -1;
    return 0;
}



u8 *create_dir(u8 *fname) {
    u8      *p,
            *l;

    p = strchr(fname, ':'); // unused
    if(p) {
        *p = '_';
        fname = p + 1;
    }
    for(p = fname; *p && strchr("\\/. \t:", *p); p++) *p = '_';
    fname = p;

    for(p = fname; ; p = l + 1) {
        for(l = p; *l && (*l != '\\') && (*l != '/'); l++);
        if(!*l) break;
        *l = 0;

        if(!strcmp(p, "..")) {
            p[0] = '_';
            p[1] = '_';
        }

        make_dir(fname);
        *l = PATHSLASH;
    }
    return(fname);
}



int check_overwrite(u8 *fname) {
    FILE    *fd;
    u8      ans[16];

    if(force_overwrite) return(0);
    if(!fname) return(0);
    fd = fopen(fname, "rb");
    if(!fd) return(0);
    fclose(fd);
    printf("- the file \"%s\" already exists\n  do you want to overwrite it (y/N/all)? ", fname);
    fgets(ans, sizeof(ans), stdin);
    if(tolower(ans[0]) == 'y') return(0);
    if(tolower(ans[0]) == 'a') {
        force_overwrite = 1;
        return(0);
    }
    return(-1);
}



void myalloc(u8 **data, u32 wantsize, u32 *currsize) {
    if(!wantsize) return;
    if(wantsize <= *currsize) {
        if(*currsize > 0) return;
    }
    *data = realloc(*data, wantsize);
    if(!*data) std_err();
    *currsize = wantsize;
}



int myfr(FILE *fd, u8 *data, int size) {
    int     len;

    len = fread(data, 1, size, fd);
    if(len != size) {
        printf("\nError: incomplete input file, can't read %u bytes\n", size - len);
        exit(1);
    }
    return(len);
}



int myfw(FILE *fd, u8 *data, int size) {
    int     len;

    len = fwrite(data, 1, size, fd);
    if(len != size) {
        printf("\nError: impossible to write %u bytes\n", size - len);
        exit(1);
    }
    return(len);
}



int get_num(u8 *str) {
    int     offset;

    if(!strncmp(str, "0x", 2) || !strncmp(str, "0X", 2)) {
        sscanf(str + 2, "%x", &offset);
    } else {
        sscanf(str, "%u", &offset);
    }
    return(offset);
}



void std_err(void) {
    perror("Error");
    exit(1);
}



uint32_t mycrc32(unsigned char *data, int size) {
    const static uint32_t   crctable[] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
        0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
        0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
        0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
        0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
        0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
        0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
        0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
        0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
        0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
        0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
        0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
        0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
        0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
        0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
        0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
        0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
        0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
        0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
        0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
        0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
        0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
        0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
        0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
        0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
        0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
        0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
        0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
        0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
        0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
        0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
        0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
        0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
        0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
        0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
        0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
        0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
        0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
        0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d };
    uint32_t    crc = 0xffffffff;

    while(size--) {
        crc = crctable[*data ^ (crc & 0xff)] ^ (crc >> 8);
        data++;
    }
    return(~crc);
}



int unbase64(u8 *in, int insz, u8 *out, int outsz) {
    int     xlen,
            a   = 0,
            b   = 0,
            c,
            step;
    u8      *limit,
            *data,
            *p;
    static const u8 base[128] = {   // supports also the Gamespy base64 and URLs
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3e,0x00,0x3e,0x00,0x3f,
        0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
        0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x3e,0x00,0x3f,0x00,0x3f,
        0x00,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x00,0x00,0x00,0x00,0x00
    };

    if(insz < 0) insz = strlen(in);
    xlen = ((insz >> 2) * 3) + 1;    // NULL included in output for text
    if((in != out) && (outsz >= 0)) {
        if(outsz < xlen) return -1;
    } else {
        outsz = xlen;
    }
    data = in;

    p = out;
    limit = data + insz;

    for(step = 0; /* data < limit */; step++) {
        do {
            if(data >= limit) {
                c = 0;
                break;
            }
            c = *data;
            data++;
            if((c == '=') || (c == '_')) {  // supports also the Gamespy base64
                c = 0;
                break;
            }
        } while(c && ((c <= ' ') || (c > 0x7f)));
        if(!c) break;

        switch(step & 3) {
            case 0: {
                a = base[c];
                break;
            }
            case 1: {
                b = base[c];
                *p++ = (a << 2)        | (b >> 4);
                break;
            }
            case 2: {
                a = base[c];
                *p++ = ((b & 15) << 4) | (a >> 2);
                break;
            }
            case 3: {
                *p++ = ((a & 3) << 6)  | base[c];
                break;
            }
        }
    }
    *p = 0;
    return(p - out);
}
