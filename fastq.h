//#pragma once
//bool fastq_next(fastx_handle h,
//    bool truncateatspace,
//    const unsigned char* char_mapping);

#define HASH CityHash64

extern unsigned int char_header_action[256];
extern unsigned int char_fasta_action[256];
extern unsigned int char_fq_action_seq[256];
extern unsigned int char_fq_action_qual[256];
extern unsigned int chrmap_2bit[256];
extern unsigned int chrmap_4bit[256];
extern unsigned int chrmap_mask_ambig[256];
extern unsigned int chrmap_mask_lower[256];
extern const unsigned char chrmap_complement[256];
extern const unsigned char chrmap_normalize[256];
extern const unsigned char chrmap_upcase[256];
extern const unsigned char chrmap_no_change[256];
extern const unsigned char chrmap_identity[256];
void progress_init(const char* prompt, uint64_t size);
typedef struct fastx_s* fastx_handle;

bool fastq_next(fastx_handle h,
    bool truncateatspace,
    const unsigned char* char_mapping);

void kh_find_diagonals(struct kh_handle_s* kh,
    int k,
    char* seq,
    int len,
    int* diags);
void kh_insert_kmers(struct kh_handle_s* kh, int k, char* seq, int len);


