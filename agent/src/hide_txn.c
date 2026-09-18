#include "hide_soinfo.h"

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

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

static int path_is_self(const char *path, const char *self_path, uint64_t map_start) {
    if (!path)
        return 0;
    if (self_path && self_path[0] && strcmp(path, self_path) == 0)
        return 1;
    /* 同名 memfd 必须再核对当前映射，避免摘掉历史 wwb_so。 */
    if (map_start && strstr(path, "wwb_so")) {
        Dl_info info;
        if (dladdr((void *)(uintptr_t)map_start, &info) && info.dli_fname && strcmp(info.dli_fname, path) == 0)
            return 1;
    }
    return 0;
}

static struct link_map_entry *find_unique_link_map(
    uint64_t *r_map_ptr,
    const char *path,
    const char *self_path,
    uint64_t load_bias
) {
    if (!r_map_ptr)
        return NULL;
    struct link_map_entry *lm = (struct link_map_entry *)(*r_map_ptr);
    struct link_map_entry *matched = NULL;
    int matches = 0;
    int count = 0;
    while (lm && count < 4096) {
        count++;
        int by_addr = load_bias && lm->l_addr == load_bias;
        int by_name = 0;
        if (lm->l_name) {
            if (path && strcmp(lm->l_name, path) == 0)
                by_name = 1;
            else if (self_path && strcmp(lm->l_name, self_path) == 0)
                by_name = 1;
        }
        /* 同名 memfd 必须同时命中当前 load bias，避免摘掉历史节点。 */
        if (by_addr || (by_name && (!load_bias || lm->l_addr == load_bias || lm->l_addr == 0))) {
            matches++;
            matched = lm;
            if (by_addr)
                return lm;
        }
        lm = lm->l_next;
    }
    return matches == 1 ? matched : NULL;
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
    void *prev = NULL;
    void *cur = plan->head;
    int count = 0;
    int matches = 0;
    void *matched = NULL;
    void *matched_prev = NULL;
    while (cur && count < 4096) {
        count++;
        const char *path = plan->get_path(cur);
        int by_handle = (cur == handle);
        int by_path = path_is_self(path, self_path, plan->self_map_start);
        if (by_handle || by_path) {
            matches++;
            matched = cur;
            matched_prev = prev;
            if (by_handle && by_path)
                break;
        }
        prev = cur;
        cur = soinfo_next(cur, next_off);
    }
    g_hide_result.entries_scanned = count;
    if (matches != 1 || !matched)
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "current soinfo node is not unique");
    plan->target = matched;
    plan->soinfo_next = soinfo_next(matched, next_off);
    /* 再走一遍找 prev：扫描时的 matched_prev 可能因环/重复节点不可写。 */
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
    (void)matched_prev;

    const char *path = plan->get_path(plan->target);
    if (!path)
        return fail_stage(HIDE_STAGE_RESOLVE, -9, "target path is NULL");
    strncpy(g_hide_result.target_path, path, sizeof(g_hide_result.target_path) - 1);
    g_hide_result.target_ptr = (uint64_t)plan->target;

    if (plan->syms.r_debug) {
        plan->r_map_ptr = (uint64_t *)(plan->syms.r_debug + 0x08);
        plan->lm = find_unique_link_map(plan->r_map_ptr, path, self_path, plan->self_load_bias);
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

static int ptr_writable(void *p) {
    if (!p)
        return 0;
    uint64_t page = (uint64_t)p & ~0xFFFULL;
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
        (void)page;
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
    uint64_t page = (uint64_t)slot & ~0xFFFULL;
    /* linker soinfo 可能落在 RELRO 页；必须临时打开写权限才能摘链。 */
    if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE) != 0)
        return -1;
    *(void **)slot = value;
    return 0;
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

static int unlink_soinfo(struct hide_plan *plan) {
    uint64_t *head_slot = solist_head_slot(plan);
    uint64_t *tail_slot = solist_tail_slot(plan);
    if (plan->soinfo_prev) {
        void *slot = (char *)plan->soinfo_prev + plan->next_off;
        if (*(void **)slot != plan->target)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "prev->next is not the target soinfo");
        if (store_ptr(slot, plan->soinfo_next) != 0)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "cannot write soinfo prev->next");
    } else if (head_slot) {
        if (store_ptr(head_slot, plan->soinfo_next) != 0)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "cannot write solist_head");
    } else {
        return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "no soinfo head slot");
    }
    if (head_slot && *head_slot == (uint64_t)plan->target) {
        if (store_ptr(head_slot, plan->soinfo_next) != 0)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "cannot rewrite solist_head");
    }
    if (tail_slot && *tail_slot == (uint64_t)plan->target) {
        if (store_ptr(tail_slot, plan->soinfo_prev) != 0)
            return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "cannot write solist_tail");
    }
    return 0;
}

static void relink_soinfo(struct hide_plan *plan) {
    uint64_t *head_slot = solist_head_slot(plan);
    uint64_t *tail_slot = solist_tail_slot(plan);
    if (plan->soinfo_prev) {
        void *slot = (char *)plan->soinfo_prev + plan->next_off;
        if (ptr_writable(slot))
            *(void **)slot = plan->target;
    } else if (head_slot) {
        *head_slot = (uint64_t)plan->target;
    }
    if (ptr_writable((char *)plan->target + plan->next_off))
        *(void **)((char *)plan->target + plan->next_off) = plan->soinfo_next;
    if (tail_slot && !plan->soinfo_next)
        *tail_slot = (uint64_t)plan->target;
}

static int unlink_link_map(struct hide_plan *plan) {
    struct link_map_entry *lm = plan->lm;
    if (lm->l_prev) {
        if (store_ptr(&lm->l_prev->l_next, lm->l_next) != 0)
            return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "cannot write link_map prev->next");
    } else if (store_ptr(plan->r_map_ptr, lm->l_next) != 0) {
        return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "cannot write r_map head");
    }
    if (lm->l_next) {
        if (store_ptr(&lm->l_next->l_prev, lm->l_prev) != 0)
            return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "cannot write link_map next->prev");
    }
    if (plan->syms.r_debug_tail) {
        uint64_t *tail_ptr = (uint64_t *)plan->syms.r_debug_tail;
        if (*tail_ptr == (uint64_t)lm && store_ptr(tail_ptr, lm->l_prev) != 0)
            return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "cannot write r_debug_tail");
    }
    return 0;
}

static void relink_link_map(struct hide_plan *plan) {
    struct link_map_entry *lm = plan->lm;
    if (lm->l_prev)
        store_ptr(&lm->l_prev->l_next, lm);
    else
        store_ptr(plan->r_map_ptr, lm);
    if (lm->l_next)
        store_ptr(&lm->l_next->l_prev, lm);
    if (plan->syms.r_debug_tail) {
        uint64_t *tail_ptr = (uint64_t *)plan->syms.r_debug_tail;
        if (!lm->l_next)
            store_ptr(tail_ptr, lm);
    }
}

int hide_commit(struct hide_plan *plan) {
    add_soinfo_fn do_add = (add_soinfo_fn)plan->syms.solist_add_soinfo;

    g_hide_result.stage = HIDE_STAGE_WRITE_SOINFO;
    {
        int unlinked = unlink_soinfo(plan);
        if (unlinked != 0)
            return unlinked;
    }
    g_hide_result.wrote |= HIDE_WROTE_SOINFO;
    void *head_now = current_solist_head(plan);
    if (soinfo_visible(head_now, plan->target, plan->next_off, &g_hide_result.entries_scanned)) {
        g_hide_result.soinfo_state = CHAIN_FAILED;
        return fail_stage(HIDE_STAGE_WRITE_SOINFO, -10, "soinfo still visible after remove");
    }
    g_hide_result.soinfo_state = CHAIN_HIDDEN;

    g_hide_result.stage = HIDE_STAGE_WRITE_LINKMAP;
    {
        int unlinked = unlink_link_map(plan);
        if (unlinked != 0)
            return unlinked;
    }
    g_hide_result.wrote |= HIDE_WROTE_LINKMAP;
    if (link_map_visible(plan->r_map_ptr, plan->lm)) {
        relink_link_map(plan);
        relink_soinfo(plan);
        (void)do_add;
        g_hide_result.link_map_state = CHAIN_FAILED;
        g_hide_result.soinfo_state = CHAIN_ROLLED_BACK;
        g_hide_result.wrote = HIDE_WROTE_NONE;
        return fail_stage(HIDE_STAGE_WRITE_LINKMAP, -11, "link_map still visible; rolled back");
    }
    g_hide_result.link_map_state = CHAIN_HIDDEN;

    g_hide_result.stage = HIDE_STAGE_CONFIRM;
    if (soinfo_visible(head_now, plan->target, plan->next_off, NULL) || link_map_visible(plan->r_map_ptr, plan->lm)) {
        relink_link_map(plan);
        relink_soinfo(plan);
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
