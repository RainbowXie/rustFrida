#include "hide_soinfo.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int fail_stage(int stage, int code, const char *msg) {
    g_hide_result.stage = stage;
    g_hide_result.status = code;
    strncpy(g_hide_result.error, msg, sizeof(g_hide_result.error) - 1);
    return code;
}

static void *soinfo_next(void *node, int next_off) {
    return *(void **)((char *)node + next_off);
}

static int soinfo_visible(void *head, void *target, int next_off, int *scanned) {
    void *cur = head;
    int count = 0;
    while (cur && count < 4096) {
        count++;
        if (cur == target) {
            if (scanned)
                *scanned = count;
            return 1;
        }
        cur = soinfo_next(cur, next_off);
    }
    if (scanned)
        *scanned = count;
    return 0;
}

static int link_map_visible(uint64_t *r_map_ptr, struct link_map_entry *target) {
    if (!r_map_ptr)
        return 0;
    struct link_map_entry *lm = (struct link_map_entry *)(*r_map_ptr);
    int count = 0;
    while (lm && count < 4096) {
        count++;
        if (lm == target)
            return 1;
        lm = lm->l_next;
    }
    return 0;
}

static int ptr_writable(void *p);
static int page_prot(const void *p);

/* 双链摘除要改多个槽位，任一写失败都必须能回到改前的世界状态。
   逐槽记录原值，失败时逆序写回。 */
#define HIDE_MAX_WRITES 8

struct write_journal {
    struct {
        void *slot;
        void *old_value;
    } items[HIDE_MAX_WRITES];
    int count;
    int failed;
};

static struct link_map_entry *find_unique_link_map(
    uint64_t *r_map_ptr,
    uint64_t load_bias
) {
    if (!r_map_ptr || !load_bias)
        return NULL;
    struct link_map_entry *lm = (struct link_map_entry *)(*r_map_ptr);
    int count = 0;
    while (lm && count < 4096) {
        count++;
        /* l_addr 就是 load bias，每次加载唯一；严格按本次加载的 load bias 匹配，杜绝名称回退。 */
        if (lm->l_addr == load_bias)
            return lm;
        lm = lm->l_next;
    }
    return NULL;
}

int hide_prepare(void *handle, struct hide_plan *plan) {
    memset(plan, 0, sizeof(*plan));
    g_hide_result.stage = HIDE_STAGE_RESOLVE;
    g_hide_result.next_offset = -1;

    if (!handle)
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "hide handle is NULL");

    uint64_t linker_base = 0;
    char linker_path[256] = {0};
    if (find_linker64(&linker_base, linker_path, sizeof(linker_path)) != 0)
        return fail_stage(HIDE_STAGE_RESOLVE, -1, "find_linker64 failed");

    if (resolve_linker_syms(linker_path, linker_base, &plan->syms) != 0)
        return fail_stage(HIDE_STAGE_RESOLVE, -2, "resolve_linker_syms failed");
    if (!plan->syms.soinfo_get_path)
        return fail_stage(HIDE_STAGE_RESOLVE, -3, "soinfo_get_path not found");
    if (!plan->syms.solist_add_soinfo)
        return fail_stage(HIDE_STAGE_RESOLVE, -4, "solist_add_soinfo not found");
    if (!plan->syms.solist_remove_soinfo)
        return fail_stage(HIDE_STAGE_RESOLVE, -5, "solist_remove_soinfo not found");
    if (!plan->syms.solist && !plan->syms.solist_head && !plan->syms.solist_get_head)
        return fail_stage(HIDE_STAGE_RESOLVE, -6, "neither solist_head nor solist found");

    int next_off = derive_next_offset(plan->syms.solist_add_soinfo);
    g_hide_result.next_offset = next_off;
    if (next_off < 0 || next_off > 0x400)
        return fail_stage(HIDE_STAGE_RESOLVE, -7, "derive_next_offset failed");
    plan->next_off = next_off;
    uint64_t sonext = derive_sonext_ptr(plan->syms.solist_add_soinfo);
    if (sonext)
        plan->sonext_ptr = (uint64_t *)sonext;

    plan->get_path = (get_path_fn)plan->syms.soinfo_get_path;
    /* Android 16 的 solist_get_head 实际返回 sonext 尾指针，不能当链表头。 */
    if (plan->syms.solist_head)
        plan->head = *(void **)plan->syms.solist_head;
    else if (plan->syms.solist)
        plan->head = *(void **)plan->syms.solist;
    else if (plan->syms.solist_get_head)
        plan->head = ((get_head_fn)plan->syms.solist_get_head)();
    if (!plan->head)
        return fail_stage(HIDE_STAGE_RESOLVE, -8, "solist head is NULL");
    g_hide_result.head_ptr = (uint64_t)plan->head;
    const char *hp = plan->get_path(plan->head);
    if (hp)
        strncpy(g_hide_result.head_path, hp, sizeof(g_hide_result.head_path) - 1);

    plan->self_map_start = map_start_containing(&g_identity_marker);
    if (!plan->self_map_start)
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "current library mapping not found");
    Dl_info self_info;
    memset(&self_info, 0, sizeof(self_info));
    const char *self_path = NULL;
    if (dladdr(&g_identity_marker, &self_info)) {
        if (self_info.dli_fname)
            self_path = self_info.dli_fname;
        plan->self_load_bias = (uint64_t)self_info.dli_fbase;
    }
    (void)self_path;
    if (!plan->self_load_bias)
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "self load bias not resolved");

    /* 同一进程可先后加载多个同名 memfd（路径字符串完全相同），按名字匹配会把
       历史节点也算进来。linker 自己是用地址区间反查节点的，这里调用同一个
       find_containing_library，得到的是唯一且必然属于本次加载的 soinfo。 */
    if (!plan->syms.find_containing_library)
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "find_containing_library not found");
    void *target = ((find_containing_fn)plan->syms.find_containing_library)(&g_identity_marker);
    if (!target)
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "find_containing_library returned NULL");

    /* 目标必须真的在即将摘除的链表里；否则改写前后指针会破坏无关节点。 */
    void *cur = plan->head;
    int count = 0;
    int found = 0;
    while (cur && count < 4096) {
        count++;
        if (cur == target) {
            found = 1;
            break;
        }
        cur = soinfo_next(cur, next_off);
    }
    g_hide_result.entries_scanned = count;
    if (!found)
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "target soinfo not present in solist");
    plan->target = target;
    plan->soinfo_next = soinfo_next(target, next_off);

    /* 再走一遍找 prev：需要 prev 才能把前驱的 next 指针改成 target->next。 */
    plan->soinfo_prev = NULL;
    cur = plan->head;
    count = 0;
    while (cur && count < 4096) {
        count++;
        void *nxt = soinfo_next(cur, next_off);
        if (nxt == plan->target) {
            plan->soinfo_prev = cur;
            break;
        }
        if (cur == plan->target)
            break;
        cur = nxt;
    }

    const char *path = plan->get_path(plan->target);
    if (!path)
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "target path is NULL");
    strncpy(g_hide_result.target_path, path, sizeof(g_hide_result.target_path) - 1);
    g_hide_result.target_ptr = (uint64_t)plan->target;

    if (plan->syms.r_debug) {
        plan->r_map_ptr = (uint64_t *)(plan->syms.r_debug + 0x08);
        plan->lm = find_unique_link_map(plan->r_map_ptr, plan->self_load_bias);
        if (!plan->lm)
            return fail_stage(HIDE_STAGE_RESOLVE, -9, "unique link_map node not found");
    } else {
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "_r_debug not found");
    }
    return 0;
}


static void *current_solist_head(struct hide_plan *plan) {
    if (plan->syms.solist_head)
        return *(void **)plan->syms.solist_head;
    if (plan->syms.solist)
        return *(void **)plan->syms.solist;
    if (plan->syms.solist_get_head)
        return ((get_head_fn)plan->syms.solist_get_head)();
    return plan->head;
}

/* 返回 0 成功，-1 失败。
 * 页大小必须是正数、2 的幂且在合理范围，否则视为未知，绝不猜 4096：
 * 在 16 KB 页设备上猜错会让 mprotect 操作错误范围或直接失败。 */
static int get_page_size(size_t *out) {
    static size_t cached_sz = 0;
    if (cached_sz == 0) {
        long sz = sysconf(_SC_PAGESIZE);
        if (sz <= 0 || sz > (1 << 20) || ((size_t)sz & ((size_t)sz - 1)) != 0)
            return -1;
        cached_sz = (size_t)sz;
    }
    *out = cached_sz;
    return 0;
}

static uint64_t page_align_down(uint64_t addr, size_t page_size) {
    return addr & ~(uint64_t)(page_size - 1);
}

static int ptr_writable(void *p) {
    if (!p)
        return 0;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[512];
    int ok = 0;
    while (fgets(line, sizeof(line), f)) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3)
            continue;
        if ((uint64_t)p >= start && (uint64_t)p < end) {
            ok = perms[1] == 'w';
            break;
        }
    }
    fclose(f);
    return ok;
}

static int store_ptr(void *slot, void *value) {
    if (!slot)
        return -1;
    if (ptr_writable(slot)) {
        *(void **)slot = value;
        return 0;
    }
    /* linker soinfo 可能落在 RELRO 页；临时打开写权限才能摘链。
       使用动态页大小与掩码对齐，支持 Android 16 的 16 KB 页架构。 */
    size_t page_size;
    if (get_page_size(&page_size) != 0)
        return -1;
    uint64_t page = page_align_down((uint64_t)slot, page_size);
    int orig = page_prot(slot);
    if (orig < 0)
        return -1;
    if (mprotect((void *)page, page_size, orig | PROT_WRITE) != 0)
        return -1;
    void *old_val = *(void **)slot;
    *(void **)slot = value;
    /* 不恢复会让 RELRO 页永久可写，扩大攻击面且污染重复注入的初始状态。 */
    if (mprotect((void *)page, page_size, orig) != 0) {
        /* 权限恢复失败：趁页面此时仍处于可写状态，立即还原原值，并再次尝试恢复权限 */
        *(void **)slot = old_val;
        (void)mprotect((void *)page, page_size, orig);
        return -1;
    }
    return 0;
}

/* 读目标页当前保护位；失败返回 -1（不返回 0，否则会被当成可写）。 */
static int page_prot(const void *p) {
    if (!p)
        return -1;
    uint64_t addr = (uint64_t)p;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return -1;
    char line[512];
    int prot = -1;
    while (fgets(line, sizeof(line), f)) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3)
            continue;
        if (addr >= start && addr < end) {
            prot = 0;
            if (perms[0] == 'r')
                prot |= PROT_READ;
            if (perms[1] == 'w')
                prot |= PROT_WRITE;
            if (perms[2] == 'x')
                prot |= PROT_EXEC;
            break;
        }
    }
    fclose(f);
    return prot;
}

static uint64_t *solist_head_slot(struct hide_plan *plan) {
    if (plan->syms.solist_head)
        return (uint64_t *)plan->syms.solist_head;
    if (plan->syms.solist)
        return (uint64_t *)plan->syms.solist;
    return NULL;
}

static uint64_t *solist_tail_slot(struct hide_plan *plan) {
    if (plan->syms.solist_tail)
        return (uint64_t *)plan->syms.solist_tail;
    return plan->sonext_ptr;
}

/* 在尝试任何写入前先将槽位与旧值登记到日志账本，确保任何写入失败时 rollback 均在账上。 */
static int journal_store(struct write_journal *j, void *slot, void *value) {
    if (!slot)
        return -1;
    if (j->count >= HIDE_MAX_WRITES) {
        j->failed = 1;
        return -1;
    }
    void *old = *(void **)slot;
    int idx = j->count;
    j->items[idx].slot = slot;
    j->items[idx].old_value = old;
    j->count++;

    if (store_ptr(slot, value) != 0) {
        j->failed = 1;
        return -1;
    }
    return 0;
}

static void journal_rollback(struct write_journal *j) {
    for (int i = j->count - 1; i >= 0; i--) {
        if (store_ptr(j->items[i].slot, j->items[i].old_value) != 0) {
            /* 回滚失败意味着世界状态可能不一致，留下痕迹供上层报告。 */
            j->failed = 1;
        }
    }
    j->count = 0;
}

static int unlink_soinfo(struct hide_plan *plan, struct write_journal *j) {
    uint64_t *head_slot = solist_head_slot(plan);
    uint64_t *tail_slot = solist_tail_slot(plan);
    if (plan->soinfo_prev) {
        void *slot = (char *)plan->soinfo_prev + plan->next_off;
        if (*(void **)slot != plan->target)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "prev->next is not the target soinfo");
        if (journal_store(j, slot, plan->soinfo_next) != 0)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "cannot write soinfo prev->next");
    } else if (head_slot) {
        if (journal_store(j, head_slot, plan->soinfo_next) != 0)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "cannot write solist_head");
    } else {
        return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "no soinfo head slot");
    }
    if (head_slot && *head_slot == (uint64_t)plan->target) {
        if (journal_store(j, head_slot, plan->soinfo_next) != 0)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "cannot rewrite solist_head");
    }
    if (tail_slot && *tail_slot == (uint64_t)plan->target) {
        if (journal_store(j, tail_slot, plan->soinfo_prev) != 0)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "cannot write solist_tail");
    }
    return 0;
}

static int unlink_link_map(struct hide_plan *plan, struct write_journal *j) {
    struct link_map_entry *lm = plan->lm;
    if (lm->l_prev) {
        if (journal_store(j, &lm->l_prev->l_next, lm->l_next) != 0)
            return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "cannot write link_map prev->next");
    } else if (journal_store(j, plan->r_map_ptr, lm->l_next) != 0) {
        return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "cannot write r_map head");
    }
    if (lm->l_next) {
        if (journal_store(j, &lm->l_next->l_prev, lm->l_prev) != 0)
            return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "cannot write link_map next->prev");
    }
    if (plan->syms.r_debug_tail) {
        uint64_t *tail_ptr = (uint64_t *)plan->syms.r_debug_tail;
        if (*tail_ptr == (uint64_t)lm && journal_store(j, tail_ptr, lm->l_prev) != 0)
            return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "cannot write r_debug_tail");
    }
    return 0;
}

int hide_commit(struct hide_plan *plan) {
    struct write_journal journal;
    memset(&journal, 0, sizeof(journal));

    g_hide_result.stage = HIDE_STAGE_WRITE_SOINFO;
    if (unlink_soinfo(plan, &journal) != 0) {
        journal_rollback(&journal);
        if (journal.failed)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "soinfo write failed and rollback incomplete");
        g_hide_result.soinfo_state = CHAIN_ROLLED_BACK;
        g_hide_result.wrote = HIDE_WROTE_NONE;
        return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "soinfo write failed; rolled back");
    }
    g_hide_result.wrote |= HIDE_WROTE_SOINFO;
    void *head_now = current_solist_head(plan);
    if (soinfo_visible(head_now, plan->target, plan->next_off, &g_hide_result.entries_scanned)) {
        journal_rollback(&journal);
        g_hide_result.soinfo_state = CHAIN_ROLLED_BACK;
        g_hide_result.wrote = HIDE_WROTE_NONE;
        return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "soinfo still visible after remove; rolled back");
    }
    g_hide_result.soinfo_state = CHAIN_HIDDEN;

#ifdef HIDE_FAULT_INJECTION
    /* 测试故障注入：soinfo 摘除成功、link_map 尚未写入时强制失败，
       用来验证部分写入状态能被完整回滚。生产构建不编译本块。 */
    if (g_hide_fault_stage == FAULT_STAGE_HIDE_PARTIAL) {
        journal_rollback(&journal);
        g_hide_result.soinfo_state = CHAIN_ROLLED_BACK;
        g_hide_result.wrote = HIDE_WROTE_NONE;
        return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "FAULT@hide_partial: injected");
    }
#endif
    g_hide_result.stage = HIDE_STAGE_WRITE_LINKMAP;
    if (unlink_link_map(plan, &journal) != 0) {
        journal_rollback(&journal);
        if (journal.failed)
            return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "link_map write failed and rollback incomplete");
        g_hide_result.soinfo_state = CHAIN_ROLLED_BACK;
        g_hide_result.link_map_state = CHAIN_ROLLED_BACK;
        g_hide_result.wrote = HIDE_WROTE_NONE;
        return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "link_map write failed; rolled back");
    }
    g_hide_result.wrote |= HIDE_WROTE_LINKMAP;
    if (link_map_visible(plan->r_map_ptr, plan->lm)) {
        journal_rollback(&journal);
        g_hide_result.link_map_state = CHAIN_ROLLED_BACK;
        g_hide_result.soinfo_state = CHAIN_ROLLED_BACK;
        g_hide_result.wrote = HIDE_WROTE_NONE;
        return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "link_map still visible; rolled back");
    }
    g_hide_result.link_map_state = CHAIN_HIDDEN;

    g_hide_result.stage = HIDE_STAGE_CONFIRM;
    if (soinfo_visible(head_now, plan->target, plan->next_off, NULL) || link_map_visible(plan->r_map_ptr, plan->lm)) {
        journal_rollback(&journal);
        g_hide_result.soinfo_state = CHAIN_ROLLED_BACK;
        g_hide_result.link_map_state = CHAIN_ROLLED_BACK;
        g_hide_result.wrote = HIDE_WROTE_NONE;
        return fail_stage(HIDE_STAGE_CONFIRM, -11, "confirm failed; rolled back");
    }

    g_hide_result.stage = HIDE_STAGE_DONE;
    g_hide_result.status = 1;
    g_hide_pending = 0;
    return 1;
}
