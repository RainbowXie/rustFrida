//! 测试专用故障注入点。
//!
//! 仅在 fault-injection feature（test artifact）下编译真实实现；正式发布构建
//! 编译为空操作桩，二进制不携带 RUSTFRIDA_FAULT_STAGE / FAULT@ 控制面字符串，
//! 发布门禁（release.sh）会断言这一点。
//!
//! 真实现以 RUSTFRIDA_FAULT_STAGE 环境变量命中注入阶段，在真实目标上按阶段
//! 精确制造失败，验证每个资源获取后失败路径的清理与重试。

/// 注入路径的关键阶段标识；脚本按这些名字断言命中点。
pub(crate) const FAULT_ATTACH_DONE: &str = "attach_done";
pub(crate) const FAULT_SOCKETPAIR_CREATED: &str = "socketpair_created";
pub(crate) const FAULT_MEMFD_CREATED: &str = "memfd_created";
pub(crate) const FAULT_DLOPEN_DONE: &str = "dlopen_done";
pub(crate) const FAULT_HIDE_PARTIAL: &str = "hide_partial";
/// 正常注入分支覆盖：shellcode 返回非 1（截断 blob 迫使 dlopen 失败）。
pub(crate) const FAULT_SHELLCODE_RET: &str = "shellcode_ret";
/// 正常注入分支覆盖：agent blob 已送达但 sender 上报错误（Ok(Err) 分支）。
pub(crate) const FAULT_SENDER_ERROR: &str = "sender_error";
/// 正常注入分支覆盖：远程调用本身抛错（Err 分支）。
pub(crate) const FAULT_REMOTE_CALL: &str = "remote_call";

/// C 侧 g_hide_fault_stage 的取值，与 agent/src/hide_soinfo.h 保持一致。
pub(crate) const FAULT_STAGE_HIDE_PARTIAL: i32 = 1;

#[cfg(feature = "fault-injection")]
mod imp {
    /// 查询注入阶段是否命中（不返回错误），供需要预置状态的调用方判断。
    pub(crate) fn wants_stage(stage: &str) -> bool {
        matches!(
            std::env::var("RUSTFRIDA_FAULT_STAGE"),
            Ok(ref v) if !v.is_empty() && v == stage
        )
    }

    /// 命中指定阶段时返回结构化错误；错误串带 FAULT@stage 前缀供脚本断言。
    pub(crate) fn maybe_fail(stage: &str) -> Result<(), String> {
        if wants_stage(stage) {
            Err(format!("FAULT@{}: 测试故障注入命中阶段 {}", stage, stage))
        } else {
            Ok(())
        }
    }

    /// 远程调用异常分支的替代返回值（仅 FAULT_REMOTE_CALL 命中时构造）。
    pub(crate) fn remote_call_error() -> String {
        "FAULT@remote_call: 测试故障注入命中阶段 remote_call".to_string()
    }

    /// 命中分支的可观测标记日志；FAULT@ 前缀仅在门控内构造，
    /// 保证发布产物不含控制面字符串。
    pub(crate) fn note_marker(stage: &str, msg: &str) {
        crate::log_error!("FAULT@{}: {}", stage, msg);
    }
}

#[cfg(not(feature = "fault-injection"))]
mod imp {
    // 发布构建的空操作桩：不读环境变量、不携带任何控制面字符串。
    // 保持调用点签名一致，让注入路径代码无需条件编译。
    pub(crate) fn wants_stage(_stage: &str) -> bool {
        false
    }

    pub(crate) fn maybe_fail(_stage: &str) -> Result<(), String> {
        Ok(())
    }

    /// 永不可达（wants_stage 恒 false）；保留仅为调用点类型完备，
    /// 文本刻意不含测试控制面前缀。
    pub(crate) fn remote_call_error() -> String {
        "remote call fault requested but fault-injection is disabled".to_string()
    }

    /// 空操作：发布构建不输出任何故障标记。
    pub(crate) fn note_marker(_stage: &str, _msg: &str) {}
}

pub(crate) use imp::{maybe_fail, note_marker, remote_call_error, wants_stage};
