/* Copyright 2021 Derek Pressnall
 *
 * This file is part of gne, the Tar Genie
 *
 * Gne is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 3
 * as published by the Free Software Foundation.
 *
 * Gne is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Gne.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <grp.h>
#ifdef XATTR
  #include <sys/xattr.h>
#endif
#include <pwd.h>
#include <sys/stat.h>
#include <ftw.h>
#include <utime.h>
#include <fnmatch.h>
#include "tarlib.h"
#include <libgen.h>

#ifndef st_mtimensec
    #ifdef __DARWIN_STRUCT_STAT64_TIMES
	#define st_mtimensec st_mtimespec.tv_nsec
    #else
	#define st_mtimensec st_mtim.tv_nsec
    #endif
#endif
#ifndef st_atimensec
    #ifdef __DARWIN_STRUCT_STAT64_TIMES
	#define st_atimensec st_atimespec.tv_nsec
    #else
	#define st_atimensec st_atim.tv_nsec
    #endif
#endif
#ifndef st_ctimensec
    #ifdef __DARWIN_STRUCT_STAT64_TIMES
	#define st_ctimensec st_ctimespec.tv_nsec
    #else
	#define st_ctimensec st_ctim.tv_nsec
    #endif
#endif

struct filespec fs;
#ifdef XATTR
static char *tmpxattrn = NULL;
#endif
int create_tar(int argc, char **argv);
int extracttar(int argc, char **argv);
int writeTarEntry(char *filename, struct stat *md, FILE *handle);
static int call_tar(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf);
int getargs(int argc, char **argv);
int writeGlobalHdr();
char *itoa(char *s, int n);
FILE *open_file(char *filename);
char *sanitize_filename(char *inname);
void vf_arg_process(char *optarg);
void create_tar_vf();
void *usage();
int mkdir_p(char *pathname, int mode);
void print_longtoc_entry(struct filespec *fs, size_t realsize, char *filename);
char *strunesc(char *src, char **target);
long int strtoln(char *nptr, char **endptr, int base, int len);
int help();
struct dirperms {
    struct dirperms *prev;
    char *filename;
    uid_t uid;
    gid_t gid;
    int mode;
    struct utimbuf tm;
};
int dirperms_cmp(const void *p1, const void *p2);
#define CREATE 1
#define EXTRACT 2
#define LIST 3
#define DIFF 4
#define GENKEY 5
struct vf {
    char *filepath;
    char *prog;
    int perms;
    uid_t uid;
    gid_t gid;
};

struct {
    int action;
    char *filename;
    char *files_from;
    size_t (*io_func)();
    void *io_handle;
    char *passphrase;
    char *keyfile;
    char *keycomment;
    int verbose;
    char *exclude;
    char *chdir;
    int no_cross_fs;
    int no_recursion;
    int absolute_names;
    size_t segment_size;
    struct vf *vf;
} args;
int numkeys = 0;
char *numkeys_string = NULL;
int keyfiles_len = 0;
int numexclude = 0;
int num_vf = 0;
int exclude_len = 0;
struct key_st *keys;

EVP_PKEY **evp_keypair;
unsigned char **hmac_keys;
int *hmac_keysz;
unsigned char **hmac;
unsigned int *hmac_len = NULL;
extern char *saved_passwords;

struct prev_link {
    dev_t dev;
    ino_t inode;
    char *filename;
    struct prev_link *next;
};
struct {
    struct prev_link *begin;
    struct prev_link *end;
} pls = {NULL, NULL};

void set_prev_link(dev_t dev, ino_t inode, char *filename);
struct prev_link *get_prev_link(dev_t dev, ino_t inode);

//void cleanups(int v, void *cleanup_objs);

int main(int argc, char **argv)
{
    int f;

    if ((f = getargs(argc, argv)) < 0)
	exit(1);

    if (args.chdir != NULL)
	if (chdir(args.chdir) != 0) {
	    fprintf(stderr, "Error changing to directory %s\n", args.chdir);
	    exit(1);
	}
    if (args.action == CREATE) {
	create_tar(argc - f, argv + f);
    }
    if (args.action == EXTRACT || args.action == LIST || args.action == DIFF) {
	extracttar(argc - f, argv + f);
    }
    if (args.action == GENKEY) {
	char *genkey_args[6];
	int i = 0;
	genkey_args[i++] = "genkey";
	if (args.filename != NULL) {
	    genkey_args[i++] = "-f";
	    genkey_args[i++] = args.filename;
	}
	if (args.keycomment != NULL) {
	    genkey_args[i++] = "-c";
	    genkey_args[i++] = args.keycomment;
	}
	genkey(i, genkey_args);
    }
    dfree(args.filename);
    dfree(args.passphrase);
    dfree(args.keyfile);
    dfree(args.keycomment);
    dfree(args.chdir);

    exit(0);
}

int getargs(int argc, char **argv)
{
    int optc;
    int longoptidx;

    struct option longopts[] = {
	{ "create", no_argument, NULL, 'c' }, 
	{ "extract", no_argument, NULL, 'x' },
	{ "list", no_argument, NULL, 't' },
	{ "diff", no_argument, NULL, 'd' },
	{ "compare", no_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "absolute-names", no_argument, NULL, 'P' },
	{ "directory", no_argument, NULL, 'C' },
	{ "files-from", no_argument, NULL, 'T' },
	{ "file", required_argument, NULL, 'f' },
	{ "passphrase", required_argument, NULL, 'D' },
	{ "encryptkey", required_argument, NULL, 'e'},
	{ "genkey", required_argument, NULL, 'E' },
	{ "help", no_argument, NULL, 'h' },
	{ "keycomment", required_argument, NULL, 0 },
	{ "exclude", required_argument, NULL, 0},
	{ "virtual-file", required_argument, NULL, 0},
	{ "segment-size", required_argument, NULL, 0},
	{ "one-file-system", no_argument, NULL, 0},
	{ "no-recursion", no_argument, NULL, 0},
	{ NULL, no_argument, NULL, 0 }

    };

    args.action = 0;
    args.filename = NULL;
    args.files_from = NULL;
    args.passphrase = NULL;
    args.keyfile = NULL;
    args.keycomment = NULL;
    args.verbose = 0;
    args.no_cross_fs = 0;
    args.exclude = NULL;
    args.chdir = NULL;
    args.no_recursion = 0;
    args.absolute_names = 0;
    args.segment_size = 1024 * 1024;
    args.vf = NULL;

    while ((optc = getopt_long(argc, argv, "cxtvhdT:C:E:f:D:e:", longopts, &longoptidx)) >= 0) {
	switch (optc) {
	    case 'c':
		if (args.action != 0) {
		    fprintf(stderr, "Specify only one of -c, -x, -t, -d, -E\n");
		    fprintf(stderr, "For help, use \"-h\" flag\n");
		    return(-1);
		}
		args.action = CREATE;
		break;
	    case 'x':
		if (args.action != 0) {
		    fprintf(stderr, "Specify only one of -c, -x, -t, -d, -E\n");
		    fprintf(stderr, "For help, use \"-h\" flag\n");
		    return(-1);
		}
		args.action = EXTRACT;
		break;
	    case 't':
		if (args.action != 0) {
		    fprintf(stderr, "Specify only one of -c, -x, -t, -d, -E\n");
		    fprintf(stderr, "For help, use \"-h\" flag\n");
		    return(-1);
		}
		args.action = LIST;
		break;
	    case 'd':
		if (args.action != 0) {
		    fprintf(stderr, "Specify only one of -c, -x, -t, -d, -E\n");
		    fprintf(stderr, "For help, use \"-h\" flag\n");
		    return(-1);
		}
		args.action = DIFF;
		break;
	    case 'C':
		strncpya0(&args.chdir, optarg, 0);
		break;
	    case 'E':
		if (args.action != 0) {
		    fprintf(stderr, "Specify only one of -c, -x, -t, -d, -E\n");
		    fprintf(stderr, "For help, use \"-h\" flag\n");
		    return(-1);
		}
		args.action = GENKEY;
		strncpya0(&args.filename, optarg, 0);
		break;
	    case 'v':
		args.verbose = 1;
		break;
	    case 'h':
		help();
		exit(0);
	    case 'P':
		args.absolute_names = 1;
		break;
	    case 'f':
		strncpya0(&args.filename, optarg, 0);
		break;
	    case 'T':
		strncpya0(&args.files_from, optarg, 0);
		break;
	    case 'D':
		strncpya0(&args.passphrase, optarg, 0);
		break;
	    case 'e':
		memcpyao((void **) &args.keyfile, optarg, strlen(optarg) + 1, keyfiles_len);
		keyfiles_len += strlen(optarg) + 1;
		numkeys++;
		break;
	    case 0:
		if (strcmp("keycomment", longopts[longoptidx].name) == 0) {
		    strncpya0(&args.keycomment, optarg, 0);
		}
		if (strcmp("exclude", longopts[longoptidx].name) == 0) {
		    memcpyao((void **) &args.exclude, optarg, strlen(optarg), exclude_len);
		    exclude_len += strlen(optarg);
		    memcpyao((void **) &args.exclude, "\0", 1, exclude_len);
		    exclude_len += 1;
		    numexclude++;

		    memcpyao((void **) &args.exclude, "*/", 2, exclude_len);
		    exclude_len += 2;
		    memcpyao((void **) &args.exclude, optarg, strlen(optarg), exclude_len);
		    exclude_len += strlen(optarg);
		    memcpyao((void **) &args.exclude, "\0", 1, exclude_len);
		    exclude_len += 1;
		    numexclude++;
		}
		if (strcmp("one-file-system", longopts[longoptidx].name) == 0) {
		    args.no_cross_fs = 1;
		}
		if (strcmp("no-recursion", longopts[longoptidx].name) == 0) {
		    args.no_recursion = 1;
		}
		if (strcmp("virtual-file", longopts[longoptidx].name) == 0) {
		    vf_arg_process(optarg);
		}
		if (strcmp("segment_size", longopts[longoptidx].name) == 0) {
		    args.segment_size = atol(optarg);
		}
		break;
	    default:
		usage();
		return(-1);
	}
    }
    return(optind);
}

void *usage()
{
    return(0);
}

void vf_arg_process(char *optarg)
{
    char *c;
    int n;
    char *filepath;
    char *prog;
    char *op;
    char **oplist = NULL;
    struct vf tmpvf;
    struct passwd *pw;
    struct group *gr;

    tmpvf.filepath = NULL;
    tmpvf.prog = NULL;
    tmpvf.perms = 0400;
    tmpvf.uid = getuid();
    tmpvf.gid = (int) getgid();
    if (! (c = strchr(optarg, '='))) {
	fprintf(stderr, "Error in virtual-file specification, no '=' detected\n");
	exit(1);
    }
    filepath = optarg;
    *c = '\0';
    prog = c + 1;

    if ((c = strchr(filepath, '['))) {
	if (filepath[strlen(filepath) - 1] != ']') {
	    fprintf(stderr, "Error in virtual-file specification, '[]' not  matched\n");
	    exit(1);
	}
	filepath[strlen(filepath) - 1] = '\0';
	*c = '\0';
	op = c + 1;
	n = parse(op, &oplist, ',');
	fflush(stderr);
	if (n > 0)
	    tmpvf.perms = strtol(oplist[0], 0, 8);
	if (n > 1) {
	    pw=getpwnam(oplist[1]);
	    if (pw != NULL)
		tmpvf.uid = pw->pw_uid;
	}
	if (n > 2) {
	    gr=getgrnam(oplist[2]);
	    if (gr != NULL)
		tmpvf.gid = gr->gr_gid;
	}
    }
    strncpya0(&tmpvf.filepath, filepath, 0);
    strncpya0(&tmpvf.prog, prog, 0);
    memcpyao((void **) &args.vf, &tmpvf, sizeof(tmpvf), num_vf++);

    return;
}

void create_tar_vf()
{
    struct stat sb;
    int p[2];
    FILE *f;

    for (int i = 0; i < num_vf; i++) {
	sb.st_dev = 0;
	sb.st_ino = 0;
	sb.st_mode = args.vf[i].perms;
	sb.st_uid = args.vf[i].uid;
	sb.st_gid = args.vf[i].gid;
	sb.st_size = 0;
	sb.st_blksize = 0;
	sb.st_blocks = 0;
	sb.st_mtim.tv_sec = time(NULL);
	sb.st_mtim.tv_nsec = 0;
	sb.st_ctim.tv_sec = sb.st_mtim.tv_sec;
	sb.st_ctim.tv_nsec = 0;
	sb.st_atim.tv_sec = sb.st_mtim.tv_sec;
	sb.st_atim.tv_nsec = 0;
	pipe(p);
	if (fork() == 0) {
	    dup2(p[1], 1);
	    close(p[0]);
	    close(p[1]);
	    execl("/bin/sh", "sh", "-c", args.vf[i].prog, NULL);
	    exit(0);
	}
	close(p[1]);
	f = fdopen(p[0], "r");
	writeTarEntry(args.vf[i].filepath, &sb, f);
    }
    return;
}

int create_tar(int argc, char **argv)
{
    int nftw_flags = 0;
    struct stat sb;
    FILE *ffh = NULL;
    char *fntext = NULL;
    char *fntextu = NULL;
    size_t fnalloc = 0;

    if (args.filename != NULL && strcmp(args.filename, "-") != 0) {
	args.io_func = fwrite;
	if ((args.io_handle = fopen(args.filename, "w")) == NULL) {
	    fprintf(stderr, "Error opening %s\n", args.filename);
	    exit(1);
	}
    }
    else {
	args.io_func = fwrite;
	args.io_handle = stdout;
    }
    if (args.keyfile != NULL)
	writeGlobalHdr();
    if (args.vf != NULL)
	create_tar_vf();
    nftw_flags |= FTW_PHYS;
    if (args.files_from != NULL) {
	ffh = fopen(args.files_from, "r");
    }
    if (args.no_recursion == 0) {
	if (args.no_cross_fs == 1)
	    nftw_flags |= FTW_MOUNT;
	for (int i = 0; i < argc; i++) {
	    // Walk the directory tree for each filename specified
	    nftw(argv[i], call_tar, 800, FTW_PHYS);
	}
	if (ffh != NULL) {
	    while (getline(&fntext, &fnalloc, ffh) > 0) {
		fntext[strlen(fntext) - 1] = '\0';
		strunesc(fntext, &fntextu);
		nftw(fntextu, call_tar, 800, FTW_PHYS);
	    }
	}
    }
    else {
	for (int i = 0; i < argc; i++)
	    if (lstat(argv[i], &sb) == 0)
		call_tar(argv[i], &sb, 0, NULL);
	if (ffh != NULL) {
	    while (getline(&fntext, &fnalloc, ffh) > 0) {
		fntext[strlen(fntext) - 1] = '\0';
		strunesc(fntext, &fntextu);
		nftw(fntextu, call_tar, 800, FTW_PHYS);
	    }
	}
    }
    fclose(args.io_handle);
    if (ffh != NULL)
	fclose(ffh);
    if (fnalloc > 0)
	free(fntext);
    if (numkeys > 0) {
	for (int i = 0; i < numkeys; i++) {
	    free(hmac[i]);
	    free(keys[i].keydata);
	    EVP_PKEY_free(evp_keypair[i]);
	}
	free(hmac_len);
	free(evp_keypair);
	free(hmac);
	free(hmac_keys);
	free(hmac_keysz);
	free(keys);
    }
    if (args.exclude != NULL)
	dfree(args.exclude);
    if (numkeys_string != NULL)
	dfree(numkeys_string);
    fsfree(&fs);
#ifdef XATTR
    dfree(tmpxattrn);
#endif
    return(0);
}

// Wrapper that calls writeTarEntry from nftw()
int call_tar(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf)
{
    char *curexclude = args.exclude;
    int exclude_this_file = 0;

    if (curexclude != NULL) {
	for (int i = 0; i < numexclude; i++) {
	    if (fnmatch(curexclude, fpath, 0) == 0) {
		exclude_this_file = 1;
		break;
	    }
	    curexclude += strlen(curexclude) + 1;
	}
    }

    if (exclude_this_file == 0)
	writeTarEntry((char *) fpath, (struct stat *) sb, NULL);
    return(0);
}

// Create global tar header

int writeGlobalHdr()
{
    struct filespec gh;
    char keyfilename[4096];
    int keynum = 0;
    unsigned char *pubkey_fp;
    char itoabuf1[32];
    char paxhdr_varstring[256];
    char *curkeyfile = NULL;

    fsinit(&gh);
    gh.io_func = args.io_func;
    gh.io_handle = args.io_handle;
    gh.ftype = 'g';
    strncpya0(&gh.filename, "././@xheader", 0);

    if (args.keyfile != NULL) {
	curkeyfile = args.keyfile;
	if (numkeys > 0)
	    keys = malloc(sizeof(struct key_st) * numkeys);
	for (int i = 0; i < numkeys; i++) {
	    strncpy(keyfilename, curkeyfile, 4095);
	    keyfilename[4095] = 0;
	    load_keyfile(keyfilename, &(keys[i]));
	    curkeyfile += strlen(curkeyfile) + 1;
	}
    }
    setpaxvar(&gh.xheader, &gh.xheaderlen, "TC.version", "1", 1);
    if (numkeys > 1) {
        strncpya0(&numkeys_string, itoa(itoabuf1, numkeys), 0);
        setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.numkeys", numkeys_string, strlen(numkeys_string));
        numkeys_string[0] = '\0';
        for (keynum = 0; keynum < numkeys; keynum++) {
            pubkey_fp = sha256_b64(keys[keynum].pubkey);
            sprintf(paxhdr_varstring, "TC.pubkey.fingerprint.%d", keynum);
            setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, (char *) pubkey_fp, strlen((const char *) pubkey_fp));
            sprintf(paxhdr_varstring, "TC.eprivkey.%d", keynum);
            setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].eprvkey, strlen(keys[keynum].eprvkey));
            sprintf(paxhdr_varstring, "TC.pubkey.%d", keynum);
            setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].pubkey, strlen(keys[keynum].pubkey));
            sprintf(paxhdr_varstring, "TC.hmackeyhash.%d", keynum);
            setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].hmac_hash_b64, strlen(keys[keynum].hmac_hash_b64));
            sprintf(paxhdr_varstring, "TC.keyfile.comment.%d", keynum);
            setpaxvar(&(gh.xheader), &(gh.xheaderlen), paxhdr_varstring, keys[keynum].comment, strlen(keys[keynum].comment));
            EVP_DecodeBlock(keys[keynum].hmac_key, (unsigned char *) keys[keynum].hmac_key_b64, 44);
            if (numkeys_string[0] == '\0')
                strncpya0(&numkeys_string, itoa(itoabuf1, keynum), 0);
            else {
                strcata(&numkeys_string, "|");
                strcata(&numkeys_string, itoa(itoabuf1, keynum));
            }
            free(pubkey_fp);
        }
        setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.keygroups", numkeys_string, strlen(numkeys_string));
    }
    else {
        keynum = 0;
        pubkey_fp = sha256_b64(keys[keynum].pubkey);
        setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.pubkey.fingerprint", (char *) pubkey_fp, strlen((const char *) pubkey_fp));
        setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.eprivkey", keys[keynum].eprvkey, strlen(keys[keynum].eprvkey));
        setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.pubkey", keys[keynum].pubkey, strlen(keys[keynum].pubkey));
        setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.hmackeyhash", keys[keynum].hmac_hash_b64, strlen(keys[keynum].hmac_hash_b64));
        setpaxvar(&(gh.xheader), &(gh.xheaderlen), "TC.keyfile.comment", keys[keynum].comment, strlen(keys[keynum].comment));
        EVP_DecodeBlock(keys[keynum].hmac_key, (unsigned char *) keys[keynum].hmac_key_b64, 44);
        free(pubkey_fp);
    }
    evp_keypair = malloc(sizeof(*evp_keypair) * numkeys);
    hmac_keys = malloc(sizeof(char *) * numkeys);
    hmac_keysz = malloc(sizeof(int) * numkeys);
    hmac = malloc(sizeof(unsigned char *) * numkeys);
    hmac_len = malloc(sizeof(int) * numkeys);
    for (int i = 0; i < numkeys; i++) {
        evp_keypair[i] = rsa_getkey('e', keys, i);
        hmac_keys[i] = keys[i].hmac_key;
        hmac_keysz[i] = 32;
        hmac[i] = malloc(EVP_MAX_MD_SIZE);
        memset(hmac[i], 0, EVP_MAX_MD_SIZE);
        hmac_len[i] = EVP_MAX_MD_SIZE;
    }
    tar_write_next_hdr(&gh);
    fsfree(&gh);
    return(0);
}

// Creates a tar entry
int writeTarEntry(char *filename, struct stat *md, FILE *handle)
{
    struct passwd *pwent;
    struct group *grent;
    char buf[512];
#ifdef XATTR
    ssize_t nxattrs;
    ssize_t szxattrv;
    char xattrs[1025];
    char xattrv[1025];
    char *xattrsp;
#endif
    static int first = 0;
    static int cached_uid = -1;
    static char cached_uname[32];
    static int cached_gid = -1;
    static char cached_gname[32];
    char tmptime[32];
    struct tarsplit_file *tsf = NULL;
    struct hmac_file *hmacf = NULL;
    struct lzop_file *lzf = NULL;
    struct rsa_file *rcf = NULL;
    size_t (*fwrite_func)();
    void *fwrite_handle;
    struct prev_link *prev_link;

    if (first == 0) {
	fsinit(&fs);
	fs.io_func = args.io_func;
	fs.io_handle = args.io_handle;
	first = 1;
    }

    strncpya0(&(fs.filename), filename, 0);

    if (handle == NULL) {
	if ((md->st_mode & S_IFMT) == S_IFREG && md->st_nlink > 1) {
	    if ((prev_link = get_prev_link(md->st_dev, md->st_ino)) != NULL) {
		fs.ftype = '1';
		strncpya0(&(fs.linktarget), prev_link->filename, 0);
		tar_write_next_hdr(&fs);
		return(0);
	    }
	    else
		set_prev_link(md->st_dev, md->st_ino, filename);
	}
	switch (md->st_mode & S_IFMT) {
	    case S_IFREG: fs.ftype = '0'; break;
	    case S_IFDIR: fs.ftype = '5'; break;
	    case S_IFLNK:
		fs.ftype = '2';
		char linkpath[4096];
		size_t llen;
		llen = readlink(filename, linkpath, 4095);
		linkpath[llen >= 0 ? llen : 0] = 0;
		strncpya0(&(fs.linktarget), linkpath, 0);
		break;
	    default:
		fs.ftype = '0';
	}

	if (fs.ftype == '0') {
	    fs.filesize = md->st_size;
	}
	else
	    fs.filesize = 0;
	fs.modtime = md->st_mtime;
	sprintf(tmptime, "%ld.%.9ld", md->st_mtime, md->st_mtimensec);
	setpaxvar(&fs.xheader, &fs.xheaderlen, "mtime", tmptime, strlen(tmptime));
	sprintf(tmptime, "%ld.%.9ld", md->st_atime, md->st_atimensec);
	setpaxvar(&fs.xheader, &fs.xheaderlen, "atime", tmptime, strlen(tmptime));
	sprintf(tmptime, "%ld.%.9ld", md->st_ctime, md->st_ctimensec);
	setpaxvar(&fs.xheader, &fs.xheaderlen, "ctime", tmptime, strlen(tmptime));

#ifdef XATTR
	memset(xattrv, 0, 1025);
	memset(xattrs, 0, 1025);
	nxattrs = llistxattr(filename, xattrs, 1024);
	xattrsp = xattrs;
	for (int i = 0; nxattrs > 0; i++) {
	    szxattrv = lgetxattr(filename, xattrsp, xattrv, 1024);
	    strncpya0(&tmpxattrn, "SCHILY.xattr.", 0);
	    strcata(&tmpxattrn, xattrsp);
	    setpaxvar(&(fs.xheader), &(fs.xheaderlen), tmpxattrn, xattrv, szxattrv);
	    nxattrs -= (strlen(xattrsp) + 1);
	    xattrsp += strlen(xattrsp) + 1;
	}
#endif
    }
    else {
	fs.ftype = '0';
    }
    fs.nuid = md->st_uid;
    fs.ngid = md->st_gid;
    fs.mode = md->st_mode & 07777;

    if (cached_uid >= 0 && md->st_uid == cached_uid) {
	strncpy(fs.auid, cached_uname, 32);
	fs.auid[31] = '\0';
    }
    else {
	if ((pwent = getpwuid(md->st_uid)) > 0) {
	    strncpy(cached_uname, pwent->pw_name, 32);
	    cached_uname[31] = 0;
	    strncpy(fs.auid, cached_uname, 32);
	    cached_uid = md->st_uid;
	}
    }
    if (cached_gid >= 0 && md->st_gid == cached_gid)
	strncpy(fs.agid, cached_gname, 32);
    else {
	if ((grent = getgrgid(md->st_gid)) > 0) {
	    strncpy(cached_gname, grent->gr_name, 32);
	    cached_gname[31] = 0;
	    strncpy(fs.agid, cached_gname, 32);
	    cached_gid = md->st_gid;
	}
    }
    if (args.verbose == 1) {
	fprintf(stderr, "%s\n", fs.filename);
    }
    if (fs.ftype == '0') {

	FILE *infile;
	size_t bytesread = 0;
	if (handle == NULL)
	    infile = fopen(filename, "r");
	else {
	    infile = handle;
	}
	if (infile == 0) {
	    fprintf(stderr, "Error opening file %s\n", filename);
	    return(0);
	}
	if (numkeys > 0) {
	    char paxdata[64];
	    setpaxvar(&fs.xheader, &fs.xheaderlen, "TC.compression", "lzop", 4);
	    setpaxvar(&fs.xheader, &fs.xheaderlen, "TC.cipher", "rsa-aes256-ctr", 14);
	    if (numkeys_string != NULL)
		setpaxvar(&fs.xheader, &fs.xheaderlen, "TC.keygroup", numkeys_string, strlen(numkeys_string));
	    tsf = tarsplit_init_w(fs.io_func, fs.io_handle, fs.filename, args.segment_size, &fs);
	    sprintf(paxdata, "%zd", md->st_size);
	    if (handle == NULL)
		setpaxvar(&tsf->xheader, &tsf->xheaderlen, "TC.original.size", paxdata, strlen(paxdata));
	    rcf = rsa_file_init('w', evp_keypair, numkeys, tarsplit_write, tsf);
	    lzf = lzop_init_w(rsa_write, rcf);
	    hmacf = hmac_file_init_w(lzop_write, lzf, hmac_keys, hmac_keysz, numkeys);
	    fwrite_func = hmac_file_write;
	    fwrite_handle = hmacf;
	}
	else {
	    if (handle != NULL) {
		tsf = tarsplit_init_w(fs.io_func, fs.io_handle, fs.filename, args.segment_size, &fs);
		fwrite_func = tarsplit_write;
		fwrite_handle = tsf;
	    }
	    else {
		fwrite_func = fs.io_func;
		fwrite_handle = fs.io_handle;
		tar_write_next_hdr(&fs);
	    }
	}
	size_t bytestoread = 0;
	if ((md->st_mode & S_IFMT) == S_IFREG)
	    bytestoread = md->st_size;
	else
	    bytestoread = 0;
	int blockpad = 512 - ((bytestoread - 1) % 512 + 1);

	if (handle != NULL) {
	    size_t c;
	    while ((c = fread(buf, 1, 512, infile))) {
		fwrite_func(buf, 1, c, fwrite_handle);
		bytesread += c;
	    }

	}
	else {
	    while (bytestoread > 0) {
		size_t c;
		c = fread(buf, 1, bytestoread > 512 ? 512 : bytestoread, infile);
		if (c == 0) {
		    break;
		}
		fwrite_func(buf, 1, c, fwrite_handle);
		bytestoread -= c;
		bytesread += c;
	    }
	}
	memset(buf, 0, 512);
	if (bytestoread > 0) {
	    fprintf(stderr, "Short read on %s, buffering with nulls\n", filename);
	    while (bytestoread > 0) {
		fwrite_func(buf, 1, bytestoread > 512 ? 512 : bytestoread, fwrite_handle);
		bytestoread -= (bytestoread > 512 ? 512 : bytestoread);
	    }
	}
	fclose(infile);
	if (tsf != NULL) {
	    char paxvar[256];
	    char hmac16[256];

	    if (hmacf != NULL) {
		hmac_finalize_w(hmacf, hmac, hmac_len);

		for (int i = 0; i < numkeys; i++) {
		    encode_block_16((unsigned char *) hmac16, hmac[i], hmac_len[i]);
		    if (numkeys > 1)
			sprintf(paxvar, "TC.hmac.%d", i);
		    else
			sprintf(paxvar, "TC.hmac");
		    setpaxvar(&tsf->xheader, &tsf->xheaderlen, paxvar, hmac16, strlen(hmac16));

		}
	    }
	    if (lzf != NULL)
		lzop_finalize_w(lzf);
	    if (rcf != NULL)
		rsa_file_finalize(rcf);
	    if (handle != NULL) {
		char paxdata[64];
		sprintf(paxdata, "%zd", bytesread);
		setpaxvar(&tsf->xheader, &tsf->xheaderlen, "TC.original.size", paxdata, strlen(paxdata));
	    }
	    tarsplit_finalize_w(tsf);
	}
	else {
	    fs.io_func(buf, 1, blockpad, fs.io_handle);
	}
    }
    else {
	tar_write_next_hdr(&fs);
    }
    fsclear(&fs);


    return(0);
}

char *itoa(char *s, int n)
{
    sprintf(s, "%d", n);
    return(s);
}

#define tf_encoding_ts 1
#define tf_encoding_compression 2
#define tf_encoding_cipher 4
#define tf_encoding_tmr 8
int extracttar(int argc, char **argv)
{
    struct filespec fs;
    size_t bufsize = 4096;
    char databuf[bufsize];
    char databuf2[bufsize];
    struct tarsplit_file *tsf = NULL;
    size_t sizeremaining = 0;
    size_t padding;
    char padblock[512];
    size_t c;
    struct tar_maxread_st *tmr = NULL;
    struct lzop_file *lzf = NULL;
    struct rsa_file *rcf = NULL;
    struct hmac_file *hmacf = NULL;
    static char *paxdata = NULL;
    int paxdatalen = 0;
    EVP_PKEY *evp_keypair = NULL;
    struct rsa_keys *rsa_keys = NULL;
    char *cur_fp = NULL;
    int keynum = 0;
    size_t (*next_c_fread)();
    void *next_c_read_handle;
    int tf_encoding = 0;
    char *pubkey_fingerprint = NULL;
    char *eprivkey = NULL;
    char *keycomment = NULL;
    char *hmachash = NULL;
    int numkeys = 0;
    char numkeys_a[16];
    char paxhdr_varstring[64];
    char *required_keys_str = NULL;
    char **required_keys_list = NULL;
    char **required_keys_group = NULL;
    unsigned char *hmac_keys;
    int hmac_keysz = 32;
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned char *hmacp = hmac;
    unsigned int hmac_len;
    unsigned char hmac_b64[EVP_MAX_MD_SIZE_b64];
    unsigned char in_hmac_b64[EVP_MAX_MD_SIZE_b64];
    FILE *outfile = NULL;
    FILE *infile = NULL;
    static int cached_uid = -1;
    static char cached_uname[64] = "\0";
    static int cached_gid = -1;
    static char cached_gname[64] = "\0";
    char *paxvarlist = NULL; 
    struct passwd *cached_pwent;
    struct group *cached_grent;
    struct dirperms *dirperms = NULL;
    struct dirperms *dirperms_p;
    int dirpermsc = 0;
    struct stat sb;
    struct stat sb2;
    char *filenamec = NULL;
    char *sanitized_filename = NULL;
    char *sanitized_linktarget = NULL;
    char filename[8192];

    fsinit(&fs);
    memset(padblock, 0, 512);

    if (args.filename != NULL) {
	args.io_func = fread;
	if ((args.io_handle = fopen(args.filename, "r")) == NULL) {
	    fprintf(stderr, "Error opening %s\n", args.filename);
	    exit(1);
	}
    }
    else {
	args.io_func = fread;
	args.io_handle = stdin;
    }
    fs.io_func = args.io_func;
    fs.io_handle = args.io_handle;

    while (tar_get_next_hdr(&fs)) {
	int encoded_tar = 0;
	int extract_this_file = 0;
	int has_segmented_header = 1;

	if (fs.ftype != 'g') {
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.original.filename", &paxdata, &paxdatalen) == 0) {
		strncpy(filename, paxdata, (paxdatalen - 1) > 8191 ? 8191 : (paxdatalen - 1));
		filename[(paxdatalen - 1) > 8191 ? 8191 : (paxdatalen - 1)] = '\0';
	    }
	    else {
		strncpy(filename, fs.filename, 8191);
		filename[8191] = '\0';
	    }
	    sanitized_filename = sanitize_filename(filename);
	    sanitized_linktarget = sanitize_filename(fs.linktarget);
	    if (argc > 0)
		extract_this_file = 0;
	    else
		extract_this_file = 1;
	    for (int i = 0; i < argc; i++) {
		if (strcmp(filename, argv[i]) == 0 || (strncmp(argv[i], filename, strlen(argv[i])) == 0 && filename[strlen(argv[i])] == '/'))
		    extract_this_file = 1;
	    }
	}

	if (fs.ftype == 'g') {
	    if (args.action != LIST) {
		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.numkeys", &paxdata, &paxdatalen) == 0) {
		    strncpy(numkeys_a, paxdata, paxdatalen <=15 ? paxdatalen : 15);
		    numkeys_a[paxdatalen < 15 ? paxdatalen : 15] = '\0';
		    numkeys = atoi(numkeys_a);
		    if (rsa_keys != NULL) {
			for (int i = 0; i < rsa_keys->numkeys; i++) {
			    dfree(rsa_keys->keys[i].comment);
			    dfree(rsa_keys->keys[i].fingerprint);
			    dfree(rsa_keys->keys[i].hmac_hash_b64);
			    dfree(rsa_keys->keys[i].eprvkey);
			    dfree(rsa_keys->keys[i].pubkey);
			    EVP_PKEY_free(rsa_keys->keys[i].evp_keypair);
			}
			free(rsa_keys->keys);
			free(rsa_keys);
		    }
		    rsa_keys = malloc(sizeof(struct rsa_keys));
		    rsa_keys->numkeys = numkeys;
		    rsa_keys->keys = malloc(sizeof(struct key_st) * numkeys);

		    for (keynum = 0; keynum < numkeys; keynum++) {
			rsa_keys->keys[keynum].fingerprint = NULL;
			rsa_keys->keys[keynum].comment = NULL;
			rsa_keys->keys[keynum].eprvkey = NULL;
			rsa_keys->keys[keynum].pubkey = NULL;
			rsa_keys->keys[keynum].hmac_hash_b64 = NULL;
			rsa_keys->keys[keynum].evp_keypair = NULL;

			sprintf(paxhdr_varstring, "TC.pubkey.fingerprint.%d", keynum);
			if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0)
			    strncpya0(&(rsa_keys->keys[keynum].fingerprint), paxdata, paxdatalen);
			sprintf(paxhdr_varstring, "TC.eprivkey.%d", keynum);
			if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0)
			    strncpya0(&(rsa_keys->keys[keynum].eprvkey), paxdata, paxdatalen);
			sprintf(paxhdr_varstring, "TC.pubkey.%d", keynum);
			if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0)
			    strncpya0(&(rsa_keys->keys[keynum].pubkey), paxdata, paxdatalen);
			sprintf(paxhdr_varstring, "TC.hmackeyhash.%d", keynum);
			if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0) {
			    strncpya0(&(rsa_keys->keys[keynum].hmac_hash_b64), paxdata, paxdatalen);
			}
			sprintf(paxhdr_varstring, "TC.keyfile.comment.%d", keynum);
			if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0)
			    strncpya0(&(rsa_keys->keys[keynum].comment), paxdata, paxdatalen);
		    }
		    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.keygroups", &paxdata, &paxdatalen) == 0) {
			strncpya0(&required_keys_str, paxdata, paxdatalen);
			parse(required_keys_str, &required_keys_list, ',');
			for (int i = 0; required_keys_list[i] != NULL; i++) {
			    parse(required_keys_list[i], &required_keys_group, '|');
			    decode_privkey(rsa_keys, required_keys_group);
			}
		    }
		}
		else if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.eprivkey", &paxdata, &paxdatalen) == 0) {
		    if (rsa_keys != NULL) {
			for (int i = 0; i < rsa_keys->numkeys; i++) {
			    dfree(rsa_keys->keys[i].comment);
			    dfree(rsa_keys->keys[i].fingerprint);
			    dfree(rsa_keys->keys[i].hmac_hash_b64);
			    dfree(rsa_keys->keys[i].eprvkey);
			    dfree(rsa_keys->keys[i].pubkey);
			    EVP_PKEY_free(rsa_keys->keys[i].evp_keypair);
			}
			free(rsa_keys->keys);
			free(rsa_keys);
		    }
		    keynum = 0;
		    numkeys = 1;
		    rsa_keys = malloc(sizeof(struct rsa_keys));
		    rsa_keys->numkeys = 1;
		    rsa_keys->keys = malloc(sizeof(struct key_st));
		    rsa_keys->keys[keynum].fingerprint = NULL;
		    rsa_keys->keys[keynum].comment = NULL;
		    rsa_keys->keys[keynum].eprvkey = NULL;
		    rsa_keys->keys[keynum].pubkey = NULL;
		    rsa_keys->keys[keynum].hmac_hash_b64 = NULL;
		    rsa_keys->keys[keynum].evp_keypair = NULL;
		    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.pubkey.fingerprint", &paxdata, &paxdatalen) == 0) {
			strncpya0(&(rsa_keys->keys[keynum].fingerprint), paxdata, paxdatalen);
			if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.eprivkey", &paxdata, &paxdatalen) == 0) {
			    strncpya0(&(rsa_keys->keys[keynum].eprvkey), paxdata, paxdatalen);
			    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.keyfile.comment", &paxdata, &paxdatalen) == 0) {
				strncpya0(&(rsa_keys->keys[keynum].comment), paxdata, paxdatalen);
			    }
			    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.pubkey", &paxdata, &paxdatalen) == 0) {
				strncpya0(&(rsa_keys->keys[keynum].pubkey), paxdata, paxdatalen);
			    }
			    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.hmackeyhash", &paxdata, &paxdatalen) == 0) {
				strncpya0(&(rsa_keys->keys[keynum].hmac_hash_b64), paxdata, paxdatalen);
			    }
			    strncpya0(&required_keys_str, "0", 1);
			    parse(required_keys_str, &required_keys_group, '|');
			    decode_privkey(rsa_keys, required_keys_group);
			}
		    }
		}
	    }
	    continue;
	}
	else if(fs.ftype == '0' || (has_segmented_header = getpaxvar(fs.xheader, fs.xheaderlen, "TC.segmented.header", &paxdata, &paxdatalen)) == 0) {
	    int differed_original_size = 0;
	    size_t original_size = 0;
	    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.segmented.header", &paxdata, &paxdatalen) == 0 ||
		getpaxvar(fs.xheader, fs.xheaderlen, "TC.cipher", &paxdata, &paxdatalen) == 0 ||
		getpaxvar(fs.xheader, fs.xheaderlen, "TC.compression", &paxdata, &paxdatalen) == 0) {
		encoded_tar = 1;

		next_c_fread = fs.io_func;
		next_c_read_handle = fs.io_handle;

		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.original.size", &paxdata, &paxdatalen) == 0) {
		    sizeremaining = strtoull(paxdata, 0, 10);
		}
		else {
		    differed_original_size = 1;
		}

		if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.segmented.header", &paxdata, &paxdatalen) == 0) {
		    tsf = tarsplit_init_r(next_c_fread, next_c_read_handle);
		    next_c_fread = tarsplit_read;
		    next_c_read_handle = tsf;
		    tf_encoding |= tf_encoding_ts;
		}
		else {
		    tmr = tar_maxread_init(fs.filesize + (512 - ((fs.filesize - 1) % 512 + 1)), next_c_fread, next_c_read_handle);
		    next_c_fread = tar_maxread;
		    next_c_read_handle = tmr;
		    tf_encoding |= tf_encoding_tmr;
		}
		if (args.action != LIST && getpaxvar(fs.xheader, fs.xheaderlen, "TC.cipher", &paxdata, &paxdatalen) == 0) {
		    if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.keygroup", &paxdata, &paxdatalen) == 0) {
			strncpya0(&required_keys_str, paxdata, paxdatalen);
			parse(required_keys_str, &required_keys_group, '|');
			keynum = -1;
			for (int i = 0; required_keys_group[i] != NULL; i++) {
			    if (rsa_keys->keys[atoi(required_keys_group[i])].evp_keypair != NULL) {
				keynum = atoi(required_keys_group[i]);
				break;
			    }
			}

			if (keynum < 0) {
			    fprintf(stderr, "Error -- ciphered file missing fingerprint header\n");
			    exit(1);
			}
		    }
		    else {
			if (rsa_keys->keys[0].evp_keypair != NULL)
			    keynum = 0;
		    }
		    if (keynum < 0) {
			fprintf(stderr, "Error -- ciphered file missing key\n");
			exit(1);
		    }
		    memset(in_hmac_b64, 0, EVP_MAX_MD_SIZE_b64);
		    if (numkeys > 1) {
			sprintf(paxhdr_varstring, "TC.hmac.%d", keynum);
			if (getpaxvar(fs.xheader, fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0) {
			    strncpy((char *) in_hmac_b64, paxdata, paxdatalen > EVP_MAX_MD_SIZE_b64 - 1 ? EVP_MAX_MD_SIZE_b64 - 1 : paxdatalen);
			    in_hmac_b64[EVP_MAX_MD_SIZE_b64 - 1] = '\0';
			}
		    }
		    else {
			if (getpaxvar(fs.xheader, fs.xheaderlen, "TC.hmac", &paxdata, &paxdatalen) == 0) {
			    strncpy((char *) in_hmac_b64, paxdata, paxdatalen > EVP_MAX_MD_SIZE_b64 - 1 ? EVP_MAX_MD_SIZE_b64 - 1 : paxdatalen);
			    in_hmac_b64[EVP_MAX_MD_SIZE_b64 - 1] = '\0';
			}
		    }
		    for (int i = EVP_MAX_MD_SIZE_b64 - 1; i >= 0; i--) {
			if (in_hmac_b64[i] == '\n') {
			    in_hmac_b64[i] = '\0';
			    break;
			}
		    }

		    evp_keypair = rsa_keys->keys[keynum].evp_keypair;
		    rcf = rsa_file_init('r', &evp_keypair, 0, next_c_fread, next_c_read_handle);
		    next_c_fread = rsa_read;
		    next_c_read_handle = rcf;
		    tf_encoding |= tf_encoding_cipher;
		}
		if (args.action != LIST && getpaxvar(fs.xheader, fs.xheaderlen, "TC.compression", &paxdata, &paxdatalen) == 0) {
		    lzf = lzop_init_r(next_c_fread, next_c_read_handle);
		    next_c_fread = lzop_read;
		    next_c_read_handle = lzf;
		    tf_encoding |= tf_encoding_compression;
		}
		if (args.action != LIST && ((tf_encoding & tf_encoding_cipher) != 0)) {
		    hmac_keys = rsa_keys->keys[keynum].hmac_key;
		    hmacf = hmac_file_init_r(next_c_fread, next_c_read_handle, &hmac_keys, &hmac_keysz, 1);
		    next_c_fread = hmac_file_read;
		    next_c_read_handle = hmacf;
		}
	    }
	    else {
		next_c_fread = fs.io_func;
		next_c_read_handle = fs.io_handle;
		encoded_tar = 0;
		sizeremaining = fs.filesize;
	    }


	    if (args.verbose == 1 && extract_this_file == 1) {
		if (sizeremaining != 0)
		    print_longtoc_entry(&fs, sizeremaining, filename);
	    }
	    else if (extract_this_file == 1 && args.action == LIST)
		printf("%s\n", filename);

	    if (*cached_uname == 0 || strcmp(cached_uname, fs.auid) != 0) {
		strncpy(cached_uname, fs.auid, 63);
		cached_uname[63] = '\0';
		if ((cached_pwent = getpwnam(fs.auid)) != NULL)
		    cached_uid = cached_pwent->pw_uid;
		else
		    cached_uid = -1;
	    }
	    if (*cached_gname == 0 || strcmp(cached_gname, fs.agid) != 0) {
		strncpy(cached_gname, fs.agid, 63);
		cached_gname[63] = '\0';
		if ((cached_grent = getgrnam(fs.agid)) != NULL)
		    cached_gid = cached_grent->gr_gid;
		else
		    cached_gid = -1; 
	    }
	    padding = 512 - ((sizeremaining - 1) % 512 + 1);
	    if (args.action == DIFF && extract_this_file == 1) {
		if (lstat(sanitized_filename, &sb) == 0) {
		    if (sb.st_size != sizeremaining) {
			fprintf(stderr, "%s size differs\n", sanitized_filename);
			extract_this_file = 0;
		    }
		    if ((sb.st_mode & S_IFMT) == S_IFDIR) {
			fprintf(stderr, "%s exists but is a directory\n", sanitized_filename);
			extract_this_file = 0;
		    }
		    if ((sb.st_mode & 07777) != fs.mode) {
			fprintf(stderr, "File permission doesn't match\n");
		    }
		    if (sb.st_uid  != (cached_uid >= 0 ? cached_uid : fs.nuid)) {
			fprintf(stderr, "User ID doesn't match\n");
		    }
		    if (sb.st_gid  != (cached_gid >= 0 ? cached_gid : fs.ngid)) {
			fprintf(stderr, "Group ID doesn't match\n");
		    }
		}
		else {
		    fprintf(stderr, "%s not found\n", sanitized_filename);
		}
	    }

	    outfile = NULL;
	    infile = NULL;
	    if (extract_this_file == 1) {
		if (args.action == EXTRACT) {
		    mkdir_p(dirname(strncpya0(&filenamec, sanitized_filename, 0)), 0777);
		    outfile = fopen(sanitized_filename, "w");
		}
		else if (args.action == DIFF) {
		    infile = fopen(sanitized_filename, "r");
		}
	    }
	    if (sizeremaining == 0 && encoded_tar == 1) {
		while ((c = next_c_fread(databuf, 1, bufsize, next_c_read_handle))) {
		    if (args.action == EXTRACT && outfile != NULL)
			fwrite(databuf, 1, c, outfile);
		    else if (args.action == DIFF && infile != NULL) {
			fread(databuf2, 1, c, infile);
			if (memcmp(databuf, databuf2, c) != 0) {
			    fclose(infile);
			    infile = NULL;
			    fprintf(stderr, "%s differs\n", sanitized_filename);
			}
		    }
		}
	    }
	    else {
		while (sizeremaining > 0 || (args.action == LIST && encoded_tar == 1)) {
		    c = next_c_fread(databuf, 1, sizeremaining < bufsize ? sizeremaining : bufsize, next_c_read_handle);
		    if (args.action == EXTRACT && outfile != NULL)
			fwrite(databuf, 1, c, outfile);
		    else if (args.action == DIFF && infile != NULL) {
			fread(databuf2, 1, c, infile);
			if (memcmp(databuf, databuf2, c) != 0) {
			    fclose(infile);
			    infile = NULL;
			    fprintf(stderr, "%s differs\n", sanitized_filename);
			}
		    }
		    if (args.action != LIST || encoded_tar == 0) {
			sizeremaining -= c;
			if (sizeremaining > 0 && c == 0) {
			    fprintf(stderr, "Problem reading input, aborting.\n");
			    exit(1);
			}
		    }
		    else if (c <= 0)
			break;
		}
	    }
	    if (encoded_tar == 0 && padding > 0) {
		c = next_c_fread(padblock, 1, padding, next_c_read_handle);
	    }
	    if (outfile != NULL) {
		fclose(outfile);

		chown(sanitized_filename, cached_uid >= 0 ? cached_uid : fs.nuid, cached_gid >= 0 ? cached_gid : fs.ngid);
		chmod(sanitized_filename, fs.mode);
		struct utimbuf tm;
		tm.actime = fs.modtime;
		tm.modtime = fs.modtime;
		utime(sanitized_filename, &tm);
#ifdef XATTR
		int z = getpaxvarlist(fs.xheader, fs.xheaderlen, &paxvarlist);
		char *p = paxvarlist;
		for (int i = 0; i < z; i++) {
		    if (strcmp("SCHILY.xattr.", p) == 0) {
			getpaxvar(fs.xheader, fs.xheaderlen, p, &paxdata, &paxdatalen);
			lsetxattr(sanitized_filename, p + strlen("SCHILY.xattr."), paxdata, paxdatalen, 0);
		    }
		    p += strlen(p) + 1;
		}
#endif

	    }
	    if (infile != NULL)
		fclose(infile);

	    if (hmacf != NULL) {
		hmac_finalize_r(hmacf, &hmacp, &hmac_len);
		encode_block_16(hmac_b64, hmac, hmac_len);
		memset(in_hmac_b64, 0, EVP_MAX_MD_SIZE_b64);
		if (numkeys > 1) {
		    sprintf(paxhdr_varstring, "TC.hmac.%d", keynum);
		    if (getpaxvar(tsf != NULL ? tsf->xheader: fs.xheader, tsf != NULL ? tsf->xheaderlen : fs.xheaderlen, paxhdr_varstring, &paxdata, &paxdatalen) == 0) {
			strncpy((char *) in_hmac_b64, paxdata, paxdatalen > EVP_MAX_MD_SIZE_b64 - 1 ? EVP_MAX_MD_SIZE_b64 - 1 : paxdatalen);
			in_hmac_b64[EVP_MAX_MD_SIZE_b64 - 1] = '\0';
		    }
		}
		else {
		    if (getpaxvar(tsf != NULL ? tsf->xheader : fs.xheader, tsf != NULL ? tsf->xheaderlen : fs.xheaderlen, "TC.hmac", &paxdata, &paxdatalen) == 0) {
			strncpy((char *) in_hmac_b64, paxdata, paxdatalen > EVP_MAX_MD_SIZE_b64 - 1 ? EVP_MAX_MD_SIZE_b64 - 1 : paxdatalen);
			in_hmac_b64[EVP_MAX_MD_SIZE_b64 - 1] = '\0';
		    }
		}
		for (int i = EVP_MAX_MD_SIZE_b64 - 1; i >= 0; i--) {
		    if (in_hmac_b64[i] == '\n') {
			in_hmac_b64[i] = '\0';
			break;
		    }
		}

		if (strcmp((char *) in_hmac_b64, (char *) hmac_b64) != 0)
		    fprintf(stderr, "Warning: HMAC failed verification\n%s\n%s\n%s\n", sanitized_filename, (char *) in_hmac_b64, (char *) hmac_b64);
	    }
	    if (lzf != NULL)
		lzop_finalize_r(lzf);
	    if (rcf != NULL)
		rsa_file_finalize(rcf);
	    if (tsf != NULL) {
		if (getpaxvar(tsf->xheader, tsf->xheaderlen, "TC.original.size", &paxdata, &paxdatalen) == 0)
		    original_size = strtoull(paxdata, 0, 10);
		tarsplit_finalize_r(tsf);
	    }

	    if (differed_original_size == 1)
		print_longtoc_entry(&fs, original_size, filename);

	}
	else if (fs.ftype == '5') {
            if (args.verbose == 1 && extract_this_file == 1)
                print_longtoc_entry(&fs, sizeremaining, filename);
	    else if (extract_this_file == 1 && args.action == LIST)
		printf("%s\n", filename);
	    if (args.action == EXTRACT) {
		if (mkdir_p(sanitized_filename, 0777) == 0) {
		    if (*cached_uname == 0 || strcmp(cached_uname, fs.auid) != 0) {
			strncpy(cached_uname, fs.auid, 63);
			cached_uname[63] = '\0';
			if ((cached_pwent = getpwnam(fs.auid)) != NULL)
			    cached_uid = cached_pwent->pw_uid;
			else
			    cached_uid = -1;
		    }
		    if (*cached_gname == 0 || strcmp(cached_gname, fs.agid) != 0) {
			strncpy(cached_gname, fs.agid, 63);
			cached_gname[63] = '\0';
			if ((cached_grent = getgrnam(fs.agid)) != NULL)
			    cached_gid = cached_grent->gr_gid;
			else
			    cached_gid = -1; 
		    }

		    dirpermsc++;
		    if (dirperms == NULL) {
			dirperms_p = NULL;
			dirperms = malloc(sizeof(struct dirperms));
		    }
		    else {
			dirperms_p = dirperms;
			dirperms = malloc(sizeof(struct dirperms));
		    }
		    dirperms->prev = dirperms_p;
		    dirperms->filename = malloc(strlen(sanitized_filename) + 1);
		    strcpy(dirperms->filename, sanitized_filename);
		    dirperms->uid = (cached_uid >= 0 ? cached_uid : fs.nuid);
		    dirperms->gid = (cached_gid >= 0 ? cached_gid : fs.ngid);
		    dirperms->mode = fs.mode;
		    dirperms->tm.actime = fs.modtime;
		    dirperms->tm.modtime = fs.modtime;
		}
		else {
		    fprintf(stderr, "Failed to create directory %s\n", sanitized_filename);
		}
	    }
	}
	else if (fs.ftype == '1') {
            if (args.verbose == 1 && extract_this_file == 1)
                print_longtoc_entry(&fs, sizeremaining, filename);
	    else if (extract_this_file == 1 && args.action == LIST)
		printf("%s\n", filename);
	    if (args.action == EXTRACT) {
		if (lstat(sanitized_filename, &sb) == 0) {
		    if (lstat(sanitize_filename(sanitized_linktarget), &sb2) == 0) {
			if (sb2.st_dev != sb.st_dev || sb2.st_ino != sb.st_ino) {
			    if (unlink(sanitized_filename) == 0) {
				if (link(sanitize_filename(sanitized_linktarget), sanitized_filename) != 0) {
				    fprintf(stderr, "Link: failed to create link %s\n", sanitized_filename);
				}
				else {
				}
			    }
			    else
				fprintf(stderr, "Link: Unable to unlink existing file %s\n", sanitized_filename);
			}
			else {
			}
		    }
		}
		else {
		    if (link(sanitized_linktarget, sanitized_filename) != 0) {
			fprintf(stderr, "Link: failed to create link %s\n", sanitized_filename);
		    }
		}
	    }
	}
	else if (fs.ftype == '2') {
            if (args.verbose == 1 && extract_this_file == 1)
                print_longtoc_entry(&fs, sizeremaining, filename);
	    else if (extract_this_file == 1 && args.action == LIST)
		printf("%s\n", filename);
	    if (args.action == EXTRACT) {
		if (lstat(sanitized_filename, &sb) == 0) {
		    if (unlink(sanitized_filename) == 0) {
			if (symlink(sanitized_linktarget, sanitized_filename) != 0) {
			    fprintf(stderr, "Link: failed to create link %s\n", sanitized_filename);
			}
		    }
		    else
			fprintf(stderr, "Link: Unable to unlink existing file %s\n", sanitized_filename);
		}
		else {
		    if (symlink(sanitized_linktarget, sanitized_filename) != 0) {
			fprintf(stderr, "Link: failed to create link %s\n", sanitized_filename);
		    }
		}
		chown(sanitized_filename, cached_uid >= 0 ? cached_uid : fs.nuid, cached_gid >= 0 ? cached_gid : fs.ngid);
		chmod(sanitized_filename, fs.mode);
		struct utimbuf tm;
		tm.actime = fs.modtime;
		tm.modtime = fs.modtime;
		utime(sanitized_filename, &tm);
#ifdef XATTR
		int z = getpaxvarlist(fs.xheader, fs.xheaderlen, &paxvarlist);
		char *p = paxvarlist;
		for (int i = 0; i < z; i++) {
		    if (strcmp("SCHILY.xattr.", p) == 0) {
			getpaxvar(fs.xheader, fs.xheaderlen, p, &paxdata, &paxdatalen);
			lsetxattr(sanitized_filename, p + strlen("SCHILY.xattr."), paxdata, paxdatalen, 0);
		    }
		    p += strlen(p) + 1;
		}
#endif
	    }
	}
	else
	    fprintf(stderr, "Skipping file type %c for %s\n", fs.ftype, sanitized_filename);
    }
    fclose(args.io_handle);
    dirperms_p = dirperms;
    struct dirperms **dirperms_a = malloc(dirpermsc * sizeof(struct dirperms));
    {
	int i = 0;
	while (dirperms_p != NULL && i < dirpermsc) {
	    dirperms_a[i++] = dirperms_p;
	    dirperms_p = dirperms_p->prev;
	}
	qsort(dirperms_a, i, sizeof(struct dirperms *), dirperms_cmp);
	while (i > 0) {
	    i--;
	    chown(dirperms_a[i]->filename, dirperms_a[i]->uid, dirperms_a[i]->gid);
	    chmod(dirperms_a[i]->filename, dirperms_a[i]->mode);
	    utime(dirperms_a[i]->filename, &(dirperms_a[i]->tm));
	    free(dirperms_a[i]->filename);
	    free(dirperms_a[i]);
	}
    }

    if (rsa_keys != NULL) {
	for (int i = 0; i < rsa_keys->numkeys; i++) {
	    dfree(rsa_keys->keys[i].comment);
	    dfree(rsa_keys->keys[i].fingerprint);
	    dfree(rsa_keys->keys[i].hmac_hash_b64);
	    dfree(rsa_keys->keys[i].eprvkey);
	    dfree(rsa_keys->keys[i].pubkey);
	    EVP_PKEY_free(rsa_keys->keys[i].evp_keypair);
	}
	free(rsa_keys->keys);
	free(rsa_keys);
    }
    fsfree(&fs);
    dfree(pubkey_fingerprint);
    dfree(eprivkey);
    dfree(keycomment);
    dfree(hmachash);
    dfree(cur_fp);
    dfree(required_keys_group);
    dfree(required_keys_list);
    dfree(required_keys_str);
    free(dirperms_a);
    if (saved_passwords != NULL)
	dfree(saved_passwords);
    if (paxvarlist != NULL)
	dfree(paxvarlist);
    if (filenamec != NULL)
	dfree(filenamec);
    return(0);
}

FILE *open_file(char *filename)
{
    char **filename_parts = NULL;
    char *filenamec = NULL;
    int n;
    struct stat sb;
    char *dirname = NULL;
    int i;
    strncpya0(&filenamec, filename, 0);
    n = parse(sanitize_filename(filenamec), &filename_parts, '/');
    for (i = 0; i < n - 1; i++) {
	if (dirname == NULL || *dirname == '\0')
	    strcata(&dirname, filename_parts[i]);
	else {
	    strcata(&dirname, "/");
	    strcata(&dirname, filename_parts[i]);
	}
	if (lstat(dirname, &sb) != 0) {
	    if (mkdir(dirname, 0777) != 0) {
		fprintf(stderr, "Failed to create directory %s\n", dirname);
		return(NULL);
	    }
	}
	else if ((sb.st_mode & S_IFMT) != S_IFDIR) {
	    fprintf(stderr, "%s exists and is not a directory\n", dirname);
	    return(NULL);
	}
    }
    if (*(filename_parts[i]) != '\0') {
	if (i != 0)
	    strcata(&dirname, "/");
	strcata(&dirname, filename_parts[i]);
    }
    return(fopen(dirname, "w"));
}

char *sanitize_filename(char *inname)
{
    char *p;
    char *s = inname;

    if (args.absolute_names == 1)
	return(s);
    if (strncmp(s, "../", 3) == 0)
	s += 3;
    while ((p = strstr(s, "/../")) != NULL)
        s = p + 4;
    while (*s == '/' && *s != '\0') {
        s++;
    }
    return(s);
}
void set_prev_link(dev_t dev, ino_t inode, char *filename)
{
    if (pls.begin  == NULL) {
	pls.begin = malloc(sizeof(struct prev_link));
	pls.end = pls.begin;
    }
    else {
	pls.end->next = malloc(sizeof(struct prev_link));
	pls.end = pls.end->next;
    }

    pls.end->dev = dev;
    pls.end->inode = inode;
    pls.end->filename = malloc(strlen(filename) + 1);
    strcpy(pls.end->filename, filename);
    pls.end->next = NULL;
    return;
}
struct prev_link *get_prev_link(dev_t dev, ino_t inode)
{
    struct prev_link *p = pls.begin;
    if (p == NULL)
	return(NULL);
    while (p->dev != dev && p->inode != inode && p->next != NULL) {
	p = p->next;
    }
    if (p->dev == dev && p->inode == inode)
	return(p);
    else
	return(NULL);
}

int mkdir_p(char *pathname, int mode)
{
    char *p = pathname;
    char c[8192];
    struct stat sb;
    while ((p = strchr(p, '/')) != NULL) {
        if (p - pathname > 8191) {
	    fprintf(stderr, "%s is to long at %ld\n", pathname, p - pathname);
            return(1);
	}
        strncpy(c, pathname, p - pathname);
        c[p - pathname] = '\0';
        if (lstat(c, &sb) != 0) {
            if (mkdir(c, 0777) != 0) {
                fprintf(stderr, "Failed to create directory %s\n", c);
                return(1);
            }
        }
        else if ((sb.st_mode & S_IFMT) != S_IFDIR) {
            fprintf(stderr, "%s exists and is not a directory\n", c);
	    return(1);
        }
	p++;
    }
    if (pathname[strlen(pathname)] != '/') {
        if (lstat(pathname, &sb) != 0) {
            if (mkdir(pathname, 0777) != 0) {
                fprintf(stderr, "Failed to create directory %s\n", pathname);
                return(1);
            }
        }
        else if ((sb.st_mode & S_IFMT) != S_IFDIR) {
            fprintf(stderr, "%s exists and is not a directory\n", pathname);
            return(1);
        }
    }
    return(0);
}

int dirperms_cmp(const void *p1, const void *p2)
{
    return strcmp((*(struct dirperms **) p1)->filename, (*(struct dirperms **) p2)->filename);
}
void print_longtoc_entry(struct filespec *fs, size_t realsize, char *filename)
{
	    if (args.verbose == 1) {
		char modstr[11] = "?rwxrwxrwx";
		struct tm *filetime;
		char filetimebuf[64];
		if (fs->ftype == '0')
		    modstr[0] = '-';
		else if (fs->ftype == '1')
		    modstr[0] = 'h';
		else if (fs->ftype == '2')
		    modstr[0] = 'l';
		else if (fs->ftype == '5')
		    modstr[0] = 'd';
		for (int i = 0; i < 9; i++)
		    if (((fs->mode >> i) & 1) == 0)
			modstr[9 - i] = '-';
		filetime = localtime(&(fs->modtime));
		strftime(filetimebuf, 64, "%Y-%m-%d %H:%M", filetime);
		if (fs->ftype == '1' || fs->ftype == '2')
		    fprintf(stderr, "%s %s/%s %5lu %s %s %s %s\n", modstr, fs->auid, fs->agid, realsize, filetimebuf, filename, fs->ftype == '1' ? "link to" : fs->ftype == '2' ? "->" : "", fs->linktarget);
		else 
		    fprintf(stderr, "%s %s/%s %5lu %s %s\n", modstr, fs->auid, fs->agid, realsize, filetimebuf, filename);
	    }
}

char *strunesc(char *src, char **target)
{
    char b;
    int i = 0, j = 0, k = 0;

    if (*target == NULL)
        *target = dmalloc(strlen(src) + 1);
    else if (dmalloc_size(*target) < strlen(src) + 1)
        *target = drealloc(*target, strlen(src) + 1);
    (*target)[0] = 0;
    while (i < strlen(src)) {
        for (; i < strlen(src) && src[i] != 92; i++)
            ;
        memcpyao((void **) target, src + k, i - k, j);
        j += (i - k);
        if (i < strlen(src)) {
            i++;
            b = (char) strtoln(src + i, NULL, 8, 3);
            memcpyao((void **) target, &b, 1, j);
            i += 3;
            k = i;
            j += 1;
        }
    }
    memcpyao((void **) target, "\0", 1, j);
    return(*target);
}

long int strtoln(char *nptr, char **endptr, int base, int len)
{
    char scratch[20];
    strncpy(scratch, nptr, len);
    scratch[len] = (char) 0;
    return(strtol((scratch), endptr, base));
}

int help()
{
    printf(
        "gne - Implementation of tar with public key encryption extensions\n"
        "\n"
        "Usage:\n"
        "  gne [-c | -x | -d | -t] [-f FILE ] [-T FILE] [--exclude PATTERN] [FILE [...]]\n"
        "      [-v] [-C DIRECTORY] [-P] [--one-file-system]\n"
        "\n"
        "  gne -E KEYFILE\n"
        "\n"
        "OPTIONS\n"
        "   Primary arguments\n"
        "       Specify only one of the following upon command invocation.\n"
        "\n"
        "       -c, --create FILE [...]       Creates a new tar archive.\n"
        "\n"
        "       -x, --extract [FILE [...]]    Extracts members from a tar archive.\n"
        "\n"
        "       -d, --diff [FILE [...]]       Compares members from a tar archive to\n"
        "                                     files on disk.\n"
        "\n"
        "       -t, --list [FILE [...]]       Displays a table of contents of a tar\n"
        "                                     archive.\n"
        "\n"
        "       -E, --genkey KEYFILE          Generates a public key encryption key\n"
        "                                     file\n"
        "\n"
        "   Additional arguments\n"
        "       The following are used in conjunction with one or more of the Primary\n"
        "       options\n"
        "\n"
        "       -v, --verbose                 Verbose output\n"
        "\n"
        "       -C, --directory DIRECTORY     Changes to DIRECTORY before performing\n"
        "                                     any operations.\n"
        "\n"
        "       -P, --absolute-names          Do not strip out leading \"/\" on path\n"
        "                                     names when extracting archive.\n"
        "\n"
        "       --one-file-system             Do not cross mount points.\n"
        "\n"
        "       -e, --encryptkey KEYFILE      Encrypt archive members using KEYFILE\n"
        "\n"
        "       --keycomment COMMENT          Used with -E (--genkey), optionally\n"
        "                                     provides a comment to be recorded in the\n"
        "                                     KEYFILE.\n"
        "\n"
        "       --passhprase PASSPHRASE       Optionally specify a passphrase on the\n"
        "                                     command line.\n"
        "\n"
        "       -T, --files-from FILE         Process files from the given FILE instead\n"
        "                                     of the command line.\n"
        "\n"
        "       --exclude PATTERN             Exclude files matching the pattern\n"
        "                                     specified by PATTERN.\n"
        "\n"
	"       --virtual-file PATH[PERMISSION,OWNER,GROUP]=PROGRAM\n"
        "                                     Executes the given PROGRAM, using its\n"
	"                                     output to  appear  in  the archive  as\n"
	"                                     file name PATH.  If the size of the output\n"
	"                                     stream of PROGRAM is larger than segment\n"
	"                                     size, the file will appear in the archive\n"
	"                                     as a multi-segment file.\n"
	"\n"
	"       --segment-size NUMBER         Sets the segment size of segmented files.\n"
	"\n"

    );
    return 0;
}
