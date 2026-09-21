#ifndef RUSTFRIDA_HIDE_SOINFO_H
#define RUSTFRIDA_HIDE_SOINFO_H

#include <stdint.h>
#include <stddef.h>

#define HIDE_RESULT_VERSION 1

#define HIDE_STAGE_NONE 0
#define HIDE_STAGE_LOAD 1
#define HIDE_STAGE_RESOLVE 2
#define HIDE_STAGE_WRITE_SOINFO 3
#define HIDE_STAGE_WRITE_LINKMAP 4
#define HIDE_STAGE_CONFIRM 5
#define HIDE_STAGE_DONE 6

#define CHAIN_UNTOUCHED 0
#define CHAIN_HIDDEN 1
#define CHAIN_FAILED 2
#define CHAIN_ROLLED_BACK 3

#define HIDE_WROTE_NONE 0
#define HIDE_WROTE_SOINFO 1
#define HIDE_WROTE_LINKMAP 2

struct hide_result {
    int32_t version;        /* 0 */
    int32_t stage;          /* 4 */
    int32_t status;         /* 8: 0=未请求, 1=双链成功, 负=失败码 */
    int32_t next_offset;    /* 12 */
    int32_t entries_scanned;/* 16 */
    int32_t sym_matched;    /* 20 */
    int32_t soinfo_state;   /* 24 */
    int32_t link_map_state; /* 28 */
    int32_t wrote;          /* 32: bitmask */
    int32_t _pad;           /* 36: 对齐 head_ptr */
    uint64_t head_ptr;      /* 40 */
    uint64_t target_ptr;    /* 48 */
    char error[128];        /* 56 */
    char target_path[128];  /* 184 */
    char head_path[128];    /* 312 */
};

typedef struct {
    uint64_t solist_get_head;
    uint64_t solist;
    uint64_t solist_head;
    uint64_t solist_tail;
    uint64_t solist_add_soinfo;
    uint64_t solist_remove_soinfo;
    uint64_t find_containing_library;
    uint64_t soinfo_get_path;
    uint64_t r_debug;
    uint64_t r_debug_tail;
} linker_syms_t;

typedef const char *(*get_path_fn)(void *);
typedef void *(*get_head_fn)(void);
typedef void (*remove_soinfo_fn)(void *);
typedef void (*add_soinfo_fn)(void *);
/* linker 内部用地址区间把任意地址反查回所属 soinfo，dlsym 也走同一条路径。 */
typedef void *(*find_containing_fn)(const void *);

struct link_map_entry {
    uint64_t l_addr;
    char *l_name;
    uint64_t l_ld;
    struct link_map_entry *l_next;
    struct link_map_entry *l_prev;
};

struct hide_plan {
    linker_syms_t syms;
    get_path_fn get_path;
    void *head;
    void *target;
    void *soinfo_prev;
    void *soinfo_next;
    int next_off;
    uint64_t *r_map_ptr;
    struct link_map_entry *lm;
    uint64_t self_map_start;
    uint64_t self_load_bias;
    uint64_t *sonext_ptr;
};

extern struct hide_result g_hide_result;
extern char g_identity_marker;
extern int g_hide_pending;

int find_linker64(uint64_t *base, char *path, size_t path_size);
uint64_t compute_load_bias(uint64_t base);
int resolve_linker_syms(const char *path, uint64_t base, linker_syms_t *out);
int derive_next_offset(uint64_t fn_addr);
uint64_t derive_sonext_ptr(uint64_t fn_addr);
uint64_t map_start_containing(const void *addr);
int hide_prepare(void *handle, struct hide_plan *plan);
int hide_commit(struct hide_plan *plan);

#endif
