#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include "fastq.h"
#include <pthread.h>

#pragma warning(disable : 4996)



struct fastx_buffer_s
{
	char* data;
	uint64_t length;
	uint64_t alloc;
	uint64_t position;
};

struct fastx_s
{
	bool is_pipe;
	bool is_fastq;
	bool is_empty;

	FILE* fp;

	struct fastx_buffer_s file_buffer;

	struct fastx_buffer_s header_buffer;
	struct fastx_buffer_s sequence_buffer;
	struct fastx_buffer_s plusline_buffer;
	struct fastx_buffer_s quality_buffer;

	uint64_t file_size;
	uint64_t file_position;

	uint64_t lineno;
	uint64_t lineno_start;
	int64_t seqno;

	uint64_t stripped_all;
	uint64_t stripped[256];

	int format;
};



#ifndef exp10
#define exp10(x) (pow(10.0,(x)))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif




#define __stat64 _stat64 // For legacy compatibility
typedef struct __stat64 xstat_t;


void buffer_init(struct fastx_buffer_s* buffer, uint64_t alloc);

fastx_handle fastx_open(const char* filename);

int xfstat(int fd, xstat_t* buf);

void* realloc(void* ptr, size_t size);

void buffer_makespace(struct fastx_buffer_s* buffer, uint64_t x);

void buffer_extend(struct fastx_buffer_s* dest_buffer,
	char* source_buf,
	uint64_t len);

uint64_t xftello(FILE* stream);

uint64_t fastx_file_fill_buffer(fastx_handle h);

enum state_enum
{
	empty,
	filled,
	inprogress,
	processed
};
enum reason_enum
{
	undefined,
	ok,
	minlen,
	maxlen,
	maxns,
	minovlen,
	maxdiffs,
	maxdiffpct,
	staggered,
	indel,
	repeat,
	minmergelen,
	maxmergelen,
	maxee,
	minscore,
	nokmers
};


typedef struct merge_data_s
{
	char* fwd_header;
	char* rev_header;
	char* fwd_sequence;
	char* rev_sequence;
	char* fwd_quality;
	char* rev_quality;
	int64_t header_alloc;
	int64_t seq_alloc;
	int64_t fwd_length;
	int64_t rev_length;
	int64_t fwd_trunc;
	int64_t rev_trunc;
	int64_t pair_no;
	char* merged_sequence;
	char* merged_quality;

	int64_t merged_length;
	int64_t merged_seq_alloc;
	double ee_merged;
	double ee_fwd;
	double ee_rev;
	int64_t fwd_errors;
	int64_t rev_errors;
	int64_t offset;
	bool merged;
	reason_enum reason;
	state_enum state;
	char* khdiags;

} merge_data_t;

typedef struct chunk_s
{
	int size; /* size of merge_data = number of pairs of reads */
	state_enum state; /* state of chunk: empty, read, processed */
	merge_data_t* merge_data; /* data for merging */
} chunk_t;

static chunk_t* chunks; /* pointer to array of chunks */

static int chunk_count;
static int chunk_read_next;
static int chunk_process_next;
static int chunk_write_next;
static bool finished_reading = false;
static bool finished_all = false;
static int pairs_read = 0;
static int pairs_written = 0;

static pthread_mutex_t mutex_chunks;
static pthread_cond_t cond_chunks;


inline void kh_insert_kmer(struct kh_handle_s* kh,
	int k,
	unsigned int kmer,
	unsigned int pos);
void kh_exit(struct kh_handle_s* kh);
static const int chunk_size = 500; /* read pairs per chunk */
static const int chunk_factor = 2; /* chunks per thread */