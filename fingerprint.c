#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ripemd.h>
#include <openssl/whrlpool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

union U_IN
{
	int		fd;
	unsigned char	*string;
};

typedef union U_IN u_in;

void errors(void) __attribute__ ((__noreturn__));
void dump(u_in *, size_t, const char *hash, int FLAG) __THROW __nonnull ((1,3));
void docrc32(u_in *, size_t, int) __THROW __nonnull ((1));

static int				INFILE;
static unsigned char			*BLOCK = NULL, *digest = NULL;

int
main(int argc, char *argv[])
{
	static struct stat		statb;
	u_in				uin;
	int				fd;
	size_t				len;
	char				c;

	if (argc < 2)
	  { fprintf(stderr, "fingerprint [-f/-s] <path/to/file>/<string>\n"); exit(0xff); }

	INFILE = 0;
	while ((c = getopt(argc, argv, "f:hs:")) != -1)
	  {
		switch(c)
		  {
			case(0x68):
	  		fprintf(stderr, "fingerprint [-f/-s] <path/to/file>/<string>\n");
			exit(EXIT_SUCCESS);
			break;
			case(0x66):
			if (access(optarg, F_OK) != 0)
			  { fprintf(stderr, "%s does not exist\n", optarg); exit(EXIT_FAILURE); }
			if (access(optarg, R_OK) != 0)
			  { fprintf(stderr, "you do not have permission to read %s\n", optarg); exit(EXIT_FAILURE); }
			memset(&statb, 0, sizeof(statb));
			if (lstat(optarg, &statb) < 0)
			  { fprintf(stderr, "main(): lstat error (%s)\n", strerror(errno)); exit(EXIT_FAILURE); }
			if ((fd = open(optarg, O_RDONLY)) < 0)
			  { fprintf(stderr, "main(): error opening file (%s)\n", strerror(errno)); exit(EXIT_FAILURE); }
			uin.fd = fd;
			INFILE = 1;

			printf("\n Fingerprints for file \e[1;02m\e[1;31m\"%s\"\e[m\n\n", optarg);
			printf("\e[1;32m%10s\e[m  ", "CRC32");
			docrc32(&uin, statb.st_size, INFILE);
			lseek(fd, 0, SEEK_SET);
		#ifndef OPENSSL_NO_MD2
			printf("\e[1;32m%10s\e[m  ", "MD2");
			dump(&uin, statb.st_size, (const char *)"md2", INFILE);
			lseek(fd, 0, SEEK_SET);
		#endif
		#ifndef OPENSSL_NO_MD4
			printf("\e[1;32m%10s\e[m  ", "MD4");
			dump(&uin, statb.st_size, (const char *)"md4", INFILE);
			lseek(fd, 0, SEEK_SET);
		#endif
		#ifndef OPENSSL_NO_MD5
			printf("\e[1;32m%10s\e[m  ", "MD5");
			dump(&uin, statb.st_size, (const char *)"md5", INFILE);
			lseek(fd, 0, SEEK_SET);
		#endif
		#ifndef OPENSSL_NO_RIPEMD
			printf("\e[1;32m%10s\e[m  ", "RIPEMD160");
			dump(&uin, statb.st_size, (const char *)"ripemd160", INFILE);
			lseek(fd, 0, SEEK_SET);
		#endif
		#ifndef OPENSSL_NO_SHA
			printf("\e[1;32m%10s\e[m  ", "SHA");
			dump(&uin, statb.st_size, (const char *)"sha", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "SHA1");
			dump(&uin, statb.st_size, (const char *)"sha1", INFILE);
			lseek(fd, 0, SEEK_SET);
		#endif
		#ifndef OPENSSL_NO_SHA256
			printf("\e[1;32m%10s\e[m  ", "SHA224");
			dump(&uin, statb.st_size, (const char *)"sha224", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "SHA256");
			dump(&uin, statb.st_size, (const char *)"sha256", INFILE);
			lseek(fd, 0, SEEK_SET);
		#endif
		#ifndef OPENSSL_NO_SHA512
			printf("\e[1;32m%10s\e[m  ", "SHA384");
			dump(&uin, statb.st_size, (const char *)"sha384", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "SHA512");
			dump(&uin, statb.st_size, (const char *)"sha512", INFILE);
			lseek(fd, 0, SEEK_SET);
		#endif
		#ifndef OPENSSL_NO_MDC2
			printf("\e[1;32m%10s\e[m  ", "MDC2");
			dump(&uin, statb.st_size, (const char *)"mdc2", INFILE);
			lseek(fd, 0, SEEK_SET);
		#endif
		#ifndef OPENSSL_NO_WHIRLPOOL
			printf("\e[1;32m%10s\e[m  ", "WHIRLPOOL");
			dump(&uin, statb.st_size, (const char *)"whirlpool", INFILE);
			lseek(fd, 0, SEEK_SET);
		#endif
			exit(EXIT_SUCCESS);
			break;
			case(0x73):
			INFILE = 0;
			len = strlen((char *)optarg);
			uin.string = calloc(len+1, sizeof(unsigned char));
			if (!uin.string)
			  { fprintf(stderr, "main(): failed to allocate memory for string (%s)\n", strerror(errno)); exit(0xff); }
			strncpy((char *)uin.string, optarg, len);
			uin.string[len] = 0;
			printf("\n Fingerprints for string \e[1;02m\e[1;31m\"%s\"\e[m\n\n", optarg);
			printf("\e[1;32m%10s\e[m  ", "CRC32");
			docrc32(&uin, len, INFILE);
		#ifndef OPENSSL_NO_MD2
			printf("\e[1;32m%10s\e[m  ", "MD2");
			dump(&uin, statb.st_size, (const char *)"md2", INFILE);
		#endif
		#ifndef OPENSSL_NO_MD4
			printf("\e[1;32m%10s\e[m  ", "MD4");
			dump(&uin, statb.st_size, (const char *)"md4", INFILE);
		#endif
		#ifndef OPENSSL_NO_MD5
			printf("\e[1;32m%10s\e[m  ", "MD5");
			dump(&uin, statb.st_size, (const char *)"md5", INFILE);
		#endif
		#ifndef OPENSSL_NO_RIPEMD
			printf("\e[1;32m%10s\e[m  ", "RIPEMD160");
			dump(&uin, statb.st_size, (const char *)"ripemd160", INFILE);
		#endif
		#ifndef OPENSSL_NO_SHA
			printf("\e[1;32m%10s\e[m  ", "SHA");
			dump(&uin, statb.st_size, (const char *)"sha", INFILE);
			printf("\e[1;32m%10s\e[m  ", "SHA1");
			dump(&uin, statb.st_size, (const char *)"sha1", INFILE);
		#endif
		#ifndef OPENSSL_NO_SHA256
			printf("\e[1;32m%10s\e[m  ", "SHA224");
			dump(&uin, statb.st_size, (const char *)"sha224", INFILE);
			printf("\e[1;32m%10s\e[m  ", "SHA256");
			dump(&uin, statb.st_size, (const char *)"sha256", INFILE);
		#endif
		#ifndef OPENSSL_NO_SHA512
			printf("\e[1;32m%10s\e[m  ", "SHA384");
			dump(&uin, statb.st_size, (const char *)"sha384", INFILE);
			printf("\e[1;32m%10s\e[m  ", "SHA512");
			dump(&uin, statb.st_size, (const char *)"sha512", INFILE);
		#endif
		#ifndef OPENSSL_NO_MDC2
			printf("\e[1;32m%10s\e[m  ", "MDC2");
			dump(&uin, statb.st_size, (const char *)"mdc2", INFILE);
		#endif
		#ifndef OPENSSL_NO_WHIRLPOOL
			printf("\e[1;32m%10s\e[m  ", "WHIRLPOOL");
			dump(&uin, statb.st_size, (const char *)"whirlpool", INFILE);
		#endif
			exit(EXIT_SUCCESS);
		  }
	  }
}

void
errors(void)
{
	ERR_print_errors_fp(stderr);
	if (digest != NULL) OPENSSL_free(digest);
	if (BLOCK != NULL) free(BLOCK);
	abort();
}

void
dump(u_in *uin, size_t size, const char *hash, int FLAG)
{
	static size_t		nbytes, position;
	EVP_MD_CTX		*ctx = NULL;
	static int		digest_len, i;

	if (FLAG)
	  {
		if ((BLOCK = (unsigned char *)calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char))) == NULL)
	  	  { fprintf(stderr, "do_digest(): error allocating memory for BLOCK (%s)\n", strerror(errno)); exit(0xff); }
		memset(BLOCK, 0, EVP_MAX_MD_SIZE);
		lseek(uin->fd, 0, SEEK_SET);
		position &= ~position;
	  }

	if ((ctx = EVP_MD_CTX_create()) == NULL)
		errors();

	// DETERMINE THE TYPE OF HASH DIGEST WE HAVE TO CARRY OUT
#ifndef OPENSSL_NO_MD2
	if (strncmp("md2", hash, 3) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_md2(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_md2()))) == NULL)
			errors();
	  }
#endif
#ifndef OPENSSL_NO_MD4
	if (strncmp("md4", hash, 3) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_md4(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_md4()))) == NULL)
			errors();
	  }
#endif
#ifndef OPENSSL_NO_MD5
	if (strncmp("md5", hash, 3) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_md5()))) == NULL)
			errors();
	  }
#endif
#ifndef OPENSSL_NO_SHA
	if (strncmp("sha", hash, 3) == 0 && strncmp("sha1", hash, 4) != 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_sha()))) == NULL)
			errors();
	  }
	if (strncmp("sha1", hash, 4) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_sha1()))) == NULL)
			errors();
	  }
#endif
#ifndef OPENSSL_NO_SHA256
	if (strncmp("sha224", hash, 6) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha224(), NULL))
			errors();
		if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha224()))) == NULL)
			errors();
	  }
	if (strncmp("sha256", hash, 6) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
			errors();
	  }
#endif
#ifndef OPENSSL_NO_SHA512
	if (strncmp("sha384", hash, 6) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha384(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_sha384()))) == NULL)
			errors();
	  }
#endif
#ifndef OPENSSL_NO_MDC2
	if (strncmp("mdc2", hash, 4) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_mdc2(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_mdc2()))) == NULL)
			errors();
	  }
#endif
#ifndef OPENSSL_NO_RIPEMD
	if (strncmp("ripemd160", hash, 9) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_ripemd160()))) == NULL)
			errors();
	  }
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	if (strncmp("whirlpool", hash, 9) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_whirlpool(), NULL))
			errors();
		if ((digest = OPENSSL_malloc(EVP_MD_size(EVP_whirlpool()))) == NULL)
			errors();
	  }
#endif
#ifndef OPENSSL_NO_SHA512
	if (strncmp("sha512", hash, 6) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha512(), NULL))
			errors();
		if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha512()))) == NULL)
			errors();
	  }
#endif

	// CARRY OUT HASH DIGEST ON EITHER THE FILE OR THE STRING PROVIDED
	if (FLAG)
	  {
		for (;;)
	  	  {
			nbytes &= ~nbytes;
			if ((nbytes = read(uin->fd, BLOCK, EVP_MAX_MD_SIZE)) < 0)
		  	  { fprintf(stderr, "do_digest(): error reading from file (%s)\n", strerror(errno)); exit(0xff); }
			if (nbytes == 0)
				break;
			position += nbytes;
			if (1 != EVP_DigestUpdate(ctx, BLOCK, nbytes))
				errors();
		  }
	  }
	else
	  {
		if (1 != EVP_DigestUpdate(ctx, uin->string, strlen((char *)uin->string)))
			errors();
	  }

	if (1 != EVP_DigestFinal_ex(ctx, digest, &digest_len))
		errors();
	for (i = 0; i < digest_len; ++i)
		printf("%02hhx", digest[i]);
	putchar('\n');

	__end:
	if (ctx != NULL) EVP_MD_CTX_destroy(ctx);
	if (digest != NULL) OPENSSL_free(digest);
	if (BLOCK != NULL) free(BLOCK);
	return;

	__err:
	if (ctx != NULL) EVP_MD_CTX_destroy(ctx);
	if (strncmp("ripemd160", hash, 9) == 0 ||
	    strncmp("whirlpool", hash, 9) == 0)
	  {
		if (digest != NULL) free(digest);
	  }
	else
	  {
		if (digest != NULL) OPENSSL_free(digest);
	  }
	if (BLOCK != NULL) free(BLOCK);
	exit(0xff);
}

void
docrc32(u_in *uin, size_t len, int FLAG)
{

	static void		*start = NULL;
	static unsigned char	*p = NULL;
	static size_t		l;
	static uint32_t		crc, crc_tableau[256], polynomial = 0xedb88320, r;
	static int		i, bit;

	// créer le tableau des restes
	for (i = 0; i < 256; ++i)
	  {
		r = i;
		for (bit = 0; bit < 8; ++bit)
		  {
			if (r & 1)
			  {
				r = ((r >> 1) ^ polynomial);
			  }
			else
			  {
				r = (r >> 1);
			  }
		  }
		crc_tableau[i] = r;
	  }

	crc = 0xffffffff; l = len;
	if (FLAG)
	  {
		if ((start = mmap(NULL, len, PROT_READ, MAP_PRIVATE, uin->fd, 0)) == MAP_FAILED)
	  	  { fprintf(stderr, "docrc32(): failed to map file into memory (%s)\n", strerror(errno)); exit(0xff); }
		p = (unsigned char *)start;
		for ( ; l > 0; --l)
		  {
			crc = (crc_tableau[(crc & 0xff) ^ *p++] ^ (crc >> 8));
		  }
		if (start != NULL) munmap(start, len);
	  }
	else
	  {
		p = (unsigned char *)uin->string;
		for( ; l > 0; --l)
		  {
			crc = (crc_tableau[(crc & 0xff) ^ *p++] ^ (crc >> 8));
		  }
	  }
	printf("%0x\n", ~crc);
	return;
}
