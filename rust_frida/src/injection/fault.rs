//! 测试专用故障注入点。
//!
//! 只有在设置了 RUSTFRIDA_FAULT_STAGE 环境变量时才生效，
//! 用来在真实目标上按注入阶段精确制造失败，
//! 验证每个资源获取后失败路径的清理与重试。

/// 注入路径的关键阶段标识；脚本按这些名字断言命中点。
pub(crate) const FAULT_ATTACH_DONE: &str = "attach_done";
pub(crate) const FAULT_SOCKETPAIR_CREATED: &str = "socketpair_created";
pub(crate) const FAULT_MEMFD_CREATED: &str = "memfd_created";
pub(crate) const FAULT_DLOPEN_DONE: &str = "dlopen_done";
pub(crate) const FAULT_HIDE_PARTIAL: &str = "hide_partial";

/// 查询注入阶段是否命中（不返回错误），供需要在目标内设置故障标志的调用方判断。
pub(crate) fn wants_stage(stage: &str) -> bool {
    matches!(
        std::env::var("RUSTFRIDA_FAULT_STAGE"),
        Ok(ref v) if !v.is_empty() && v == stage
    )
}

/// C 侧 g_hide_fault_stage 的取值，与 agent/src/hide_soinfo.h 保持一致。
pub(crate) const FAULT_STAGE_HIDE_PARTIAL: i32 = 1;

/// 命中指定阶段时返回结构化错误；错误串带 FAULT@stage 前缀供脚本断言。
pub(crate) fn maybe_fail(stage: &str) -> Result<(), String> {
    let wanted = match std::env::var("RUSTFRIDA_FAULT_STAGE") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(()),
    };
    if wanted == stage {
        Err(format!("FAULT@{}: 测试故障注入命中阶段 {}", stage, stage))
    } else {
        Ok(())
    }
}
