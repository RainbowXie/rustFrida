/*
 * 独立枚举探针：用公开的 dl_iterate_phdr 从外部确认注入库是否真的不在链上。
 *
 * 为什么单独成文件：HideResult 是 agent 自报，可能因逻辑错误而说谎。这里不引用
 * 任何 hide 代码，只调用 bionic 公开 API，其内部的 do_dl_iterate_phdr 从
 * solist_get_head 沿 [+0x28] 遍历——正是 hide 事务要摘除的那条链表。若两条
 * 证据一致，说明“不在 soinfo 链上”是外部可观测事实。
 *
 * 探针自身也是用同一个 memfd 名（wwb_so）加载的，因此必须按 load bias 排掉自己，
 * 否则永远至少匹配到 1 个，无法判断 agent 是否真的被摘下来。
 *
 * 两条链都要查：dl_iterate_phdr 走的是 solist（soinfo 链），而 _r_debug.r_map
 * 是调试器看到的另一条链；hide 事务必须同时摘除两者。r_debug 通过析构器拿不到，
 * 所以由 host 把已解析的 r_map 头地址传进来。
 *
 * 结果通过字段写回，由 host 读取后判断，探针自身不下结论。
 */

typedef int (*dl_iterate_cb)(void *info, unsigned long size, void *data);

extern int dl_iterate_phdr(dl_iterate_cb callback, void *data);
extern int dladdr(const void *addr, void *info);

/* 与 bionic link.h 的 struct link_map 一致。 */
struct probe_link_map {
    unsigned long long l_addr;
    char *l_name;
    void *l_ld;
    struct probe_link_map *l_next;
    struct probe_link_map *l_prev;
};

/* 与 bionic 的 dl_phdr_info 前缀布局一致；只用到前三个字段。 */
struct probe_phdr_info {
    unsigned long long dlpi_addr;
    const char *dlpi_name;
    const void *dlpi_phdr;
};

/* 与 bionic 的 Dl_info 一致；只用到前两个字段。 */
struct probe_dl_info {
    const char *dli_fname;
    void *dli_fbase;
    const char *dli_sname;
    void *dli_saddr;
};

struct probe_result {
    /* 版本，便于 host 校验探针与 host 结构一致。 */
    int version;
    /* 遍历到的库总数。 */
    int total;
    /* 名字含 wwb_so 且不是探针自身的库数量（期望 0）。 */
    int wwb_matches;
    /* 因命中自身而跳过的数量（期望 1，否则自身隔离有问题）。 */
    int self_skipped;
    /* 探针自身的 load bias，与 dlpi_addr 同一坐标系。 */
    unsigned long long self_addr;
    /* _r_debug.r_map 链上的节点总数。 */
    int rmap_total;
    /* _r_debug.r_map 上名字含 wwb_so 且非自身的数量（期望 0）。 */
    int rmap_wwb_matches;
    /* 首个非自身匹配的名字，用于定位（可为空）。 */
    char matched_name[256];
};

#define PROBE_VERSION 1

static int name_contains(const char *s, const char *needle) {
    if (!s)
        return 0;
    for (; *s; s++) {
        const char *a = s;
        const char *b = needle;
        while (*a && *b && *a == *b) {
            a++;
            b++;
        }
        if (!*b)
            return 1;
    }
    return 0;
}

static int probe_cb(struct probe_phdr_info *info, unsigned long size, void *data) {
    struct probe_result *out = (struct probe_result *)data;
    (void)size;
    out->total++;
    if (!name_contains(info->dlpi_name, "wwb_so"))
        return 0;
    if (out->self_addr != 0 && info->dlpi_addr == out->self_addr) {
        out->self_skipped++;
        return 0;
    }
    out->wwb_matches++;
    if (out->matched_name[0] == 0 && info->dlpi_name) {
        int i = 0;
        while (info->dlpi_name[i] && i < (int)sizeof(out->matched_name) - 1) {
            out->matched_name[i] = info->dlpi_name[i];
            i++;
        }
        out->matched_name[i] = 0;
    }
    return 0;
}

__attribute__((visibility("default")))
int probe_solist_visibility(void *r_map_head, struct probe_result *out) {
    if (!out)
        return -1;
    out->version = PROBE_VERSION;
    out->total = 0;
    out->wwb_matches = 0;
    out->self_skipped = 0;
    out->self_addr = 0;
    out->rmap_total = 0;
    out->rmap_wwb_matches = 0;
    out->matched_name[0] = 0;
    struct probe_dl_info self;
    self.dli_fname = 0;
    self.dli_fbase = 0;
    self.dli_sname = 0;
    self.dli_saddr = 0;
    if (dladdr((const void *)&probe_solist_visibility, &self))
        out->self_addr = (unsigned long long)self.dli_fbase;

    /* 链一：公开 API，内部从 solist_get_head 沿 sonext 遍历。 */
    dl_iterate_phdr((dl_iterate_cb)probe_cb, out);

    /* 链二：调试器链 _r_debug.r_map。头地址由 host 从目标 linker 符号表解出后传入。 */
    if (r_map_head) {
        struct probe_link_map *lm = (struct probe_link_map *)r_map_head;
        int guard = 0;
        while (lm && guard++ < 4096) {
            out->rmap_total++;
            if (name_contains(lm->l_name, "wwb_so") &&
                !(out->self_addr != 0 && lm->l_addr == out->self_addr)) {
                out->rmap_wwb_matches++;
                if (out->matched_name[0] == 0 && lm->l_name) {
                    int i = 0;
                    while (lm->l_name[i] && i < (int)sizeof(out->matched_name) - 1) {
                        out->matched_name[i] = lm->l_name[i];
                        i++;
                    }
                    out->matched_name[i] = 0;
                }
            }
            lm = lm->l_next;
        }
    }
    return 0;
}
