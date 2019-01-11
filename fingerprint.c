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
void dump(u_in *, size_t, const char *hash, int FLAG) __THROW __nonnull ((3));
void docrc32(u_in *, size_t, int) __THROW __nonnull ((1));
uint32_t reflect(uint32_t);

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
	while ((c = getopt(argc, argv, "f:s:")) != -1)
	  {
		switch(c)
		  {
			case(0x66):
			if (access(optarg, R_OK))
			  { fprintf(stderr, "main(): you do not have read permission for \"%s\"\n", optarg); exit(0xff); }
			memset(&statb, 0, sizeof(statb));
			if (lstat(optarg, &statb) < 0)
			  { fprintf(stderr, "main(): lstat error (%s)\n", strerror(errno)); exit(0xff); }
			if ((fd = open(optarg, O_RDONLY)) < 0)
			  { fprintf(stderr, "main(): error opening file (%s)\n", strerror(errno)); exit(0xff); }
			uin.fd = fd;
			INFILE = 1;

			printf("\n Fingerprints for file \e[1;02m\e[1;31m\"%s\"\e[m\n\n", optarg);
			printf("\e[1;32m%10s\e[m  ", "CRC32");
			docrc32(&uin, statb.st_size, INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "MD4");
			dump(&uin, statb.st_size, (const char *)"md4", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "MD5");
			dump(&uin, statb.st_size, (const char *)"md5", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "RIPEMD160");
			dump(&uin, statb.st_size, (const char *)"ripemd160", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "SHA1");
			dump(&uin, statb.st_size, (const char *)"sha1", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "SHA224");
			dump(&uin, statb.st_size, (const char *)"sha224", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "SHA256");
			dump(&uin, statb.st_size, (const char *)"sha256", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "SHA384");
			dump(&uin, statb.st_size, (const char *)"sha384", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "SHA512");
			dump(&uin, statb.st_size, (const char *)"sha512", INFILE);
			lseek(fd, 0, SEEK_SET);
			printf("\e[1;32m%10s\e[m  ", "WHIRLPOOL");
			dump(&uin, statb.st_size, (const char *)"whirlpool", INFILE);

			exit(0);
			break;
			case(0x73):
			INFILE = 0;
			len = strlen((char *)optarg);
			uin.string = (unsigned char *)calloc(len+1, sizeof(unsigned char));
			if (!uin.string)
			  { fprintf(stderr, "main(): failed to allocate memory for string (%s)\n", strerror(errno)); exit(0xff); }
			strncpy((char *)uin.string, optarg, len);
			uin.string[len] = 0;
			printf("\n Fingerprints for string \e[1;02m\e[1;31m\"%s\"\e[m\n\n", optarg);
			printf("\e[1;32m%10s\e[m  ", "CRC32");
			docrc32(&uin, len, INFILE);
			printf("\e[1;32m%10s\e[m  ", "MD4");
			dump(&uin, len, (const char *)"md4", INFILE);
			printf("\e[1;32m%10s\e[m  ", "MD5");
			dump(&uin, len, (const char *)"md5", INFILE);
			printf("\e[1;32m%10s\e[m  ", "RIPEMD160");
			dump(&uin, len, (const char *)"ripemd160", INFILE);
			printf("\e[1;32m%10s\e[m  ", "SHA1");
			dump(&uin, len, (const char *)"sha1", INFILE);
			printf("\e[1;32m%10s\e[m  ", "SHA224");
			dump(&uin, len, (const char *)"sha224", INFILE);
			printf("\e[1;32m%10s\e[m  ", "SHA256");
			dump(&uin, len, (const char *)"sha256", INFILE);
			printf("\e[1;32m%10s\e[m  ", "SHA384");
			dump(&uin, len, (const char *)"sha384", INFILE);
			printf("\e[1;32m%10s\e[m  ", "SHA512");
			dump(&uin, len, (const char *)"sha512", INFILE);
			printf("\e[1;32m%10s\e[m  ", "WHIRLPOOL");
			dump(&uin, len, (const char *)"whirlpool", INFILE);

			exit(0);
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
	RIPEMD160_CTX		rctx;
	WHIRLPOOL_CTX		wctx;
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
	if (strncmp("md4", hash, 3) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_md4(), NULL))
			errors();
		if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md4()))) == NULL)
			errors();
	  }
	else if (strncmp("md5", hash, 3) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL))
			errors();
		if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_md5()))) == NULL)
			errors();
	  }
	else if (strncmp("sha1", hash, 4) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
			errors();
		if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha1()))) == NULL)
			errors();
	  }
	else if (strncmp("sha224", hash, 6) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha224(), NULL))
			errors();
		if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha224()))) == NULL)
			errors();
	  }
	else if (strncmp("sha256", hash, 6) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
			errors();
		if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
			errors();
	  }
	else if (strncmp("sha384", hash, 6) == 0)
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha384(), NULL))
			errors();
		if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha384()))) == NULL)
			errors();
	  }
	else if (strncmp("ripemd160", hash, 9) == 0)
	  {
		if (RIPEMD160_Init(&rctx) < 0)
			errors();
		if ((digest = (unsigned char *)calloc(RIPEMD160_DIGEST_LENGTH, sizeof(unsigned char))) == NULL)
		  { fprintf(stderr, "dump(): error allocating memory for digest (%s)\n", strerror(errno)); exit(0xff);}
		if (FLAG)
		  {
			nbytes &= ~nbytes;
			for (;;)
			  {
				if ((nbytes = read(uin->fd, BLOCK, RIPEMD160_DIGEST_LENGTH)) < 0)
				  { fprintf(stderr, "dump(): read error (%s)\n", strerror(errno)); exit(0xff); }
				if (nbytes == 0)
					break;
				if (RIPEMD160_Update(&rctx, BLOCK, nbytes) < 0)
					errors();
			  }
			if (RIPEMD160_Final(digest, &rctx) < 0)
				errors();
		  }
		else
		  {
			if (RIPEMD160_Update(&rctx, uin->string, strlen((char *)uin->string)) < 0)
			  { fprintf(stderr, "dump(): RIPEMD160_Update: %s\n", strerror(errno)); goto __err; }
			if (RIPEMD160_Final(digest, &rctx) < 0)
			  { fprintf(stderr, "dump(): RIPEMD160_Final: %s\n", strerror(errno)); goto __err; }
		  }
		for (i = 0; i < strlen((char *)digest); ++i)
			printf("%02hhx", digest[i]);
		putchar(0x0a);

		goto __end;
	  }
	else if (strncmp("whirlpool", hash, 9) == 0)
	  {
		if (WHIRLPOOL_Init(&wctx) < 0)
			errors();
		if ((digest = (unsigned char *)calloc(WHIRLPOOL_DIGEST_LENGTH, sizeof(unsigned char))) == NULL)
		  { fprintf(stderr, "dump(): error allocating memory for digest (%s)\n", strerror(errno)); exit(0xff); }
		if (FLAG)
		  {
			nbytes &= ~nbytes;
			for (;;)
			  {
				if ((nbytes = read(uin->fd, BLOCK, WHIRLPOOL_DIGEST_LENGTH)) < 0)
				  { fprintf(stderr, "dump(): read error (%s)\n", strerror(errno)); exit(0xff); }
				if (nbytes == 0)
					break;
				if (WHIRLPOOL_Update(&wctx, BLOCK, nbytes) < 0)
					errors();
			  }
			if (WHIRLPOOL_Final(digest, &wctx) < 0)
				errors();
		  }
		else
		  {
			if (WHIRLPOOL_Update(&wctx, uin->string, strlen((char *)uin->string)) < 0)
				errors();
			if (WHIRLPOOL_Final(digest, &wctx) < 0)
				errors();
		  }
		for (i = 0; i < strlen((char *)digest); ++i)
			printf("%02hhx", digest[i]);
		putchar(0x0a);

		goto __end;
	  }
	else
	  {
		if (1 != EVP_DigestInit_ex(ctx, EVP_sha512(), NULL))
			errors();
		if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha512()))) == NULL)
			errors();
	  }

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

uint32_t
reflect(uint32_t x)
{
	uint32_t		t;
	static uint32_t		top;
	static int		i;

	t &= ~t; top = (1 << 31);
	for (i = 0; i < 32; ++i)
	  {
		if ((x & (1 << i)) != 0)
			t |= (top >> i);
	  }
	return(t);
}

void
docrc32(u_in *uin, size_t len, int FLAG)
{

	static void		*start = NULL;
	static unsigned char	*p = NULL;
	static size_t		l;
	static uint32_t		crc, crc_tableau[256], polynomial = 0xedb88320, r;
	static int		top_bit = (1 << 31), i, bit;

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
			//crc = ((crc << 8) ^ crc_tableau[(((crc >> 24) ^ *p++) & 0xff)]);
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
