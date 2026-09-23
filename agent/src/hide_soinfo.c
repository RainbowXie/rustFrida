/**
 * hide_soinfo.c — 加载完成后显式隐藏注入库。
 *
 * 构造函数只登记当前库身份；linker 链表写入必须在 android_dlopen_ext()
 * 返回之后由 hide_from_solist(handle) 执行，否则 Android 16 会在构造期内
 * 继续使用已被摘除的 soinfo。
 */

#include "hide_soinfo.h"

#include <string.h>

struct hide_result g_hide_result = { .version = HIDE_RESULT_VERSION };
char g_identity_marker = 1;
int g_hide_pending = 0;
#ifdef HIDE_FAULT_INJECTION
int g_hide_fault_stage = 0;

__attribute__((visibility("default")))
void set_hide_fault_stage(int stage) {
    g_hide_fault_stage = stage;
}
#endif

__attribute__((visibility("default")))
struct hide_result *get_hide_result(void) {
    return &g_hide_result;
}

__attribute__((constructor))
static void hide_soinfo_register(void) {
    /* 构造阶段只登记待隐藏；写 soinfo/_r_debug 会打断 Android 16 加载锁。 */
    g_hide_result.version = HIDE_RESULT_VERSION;
    g_hide_result.stage = HIDE_STAGE_LOAD;
    g_hide_result.status = 0;
    g_hide_pending = 1;
}

__attribute__((visibility("default")))
int hide_from_solist(void *handle) {
    g_hide_result.version = HIDE_RESULT_VERSION;
    struct hide_plan plan;
    int prepared = hide_prepare(handle, &plan);
    if (prepared != 0)
        return prepared;
    return hide_commit(&plan);
}
