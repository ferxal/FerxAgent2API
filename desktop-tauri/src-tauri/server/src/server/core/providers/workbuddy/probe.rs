//! WorkBuddy 模型可用性探测：候选枚举 + 逐个探活 + TTL 分档 + 逻辑层禁用。
//!
//! 从参考项目 workbuddy-openai-proxy 的 `src/catalog.mjs` / `src/upstream.mjs`
//! 移植（Rust 版），语义逐条对齐：
//!
//! - 探测只回答「这个 id 对**本账号**此刻能不能用」， official 清单只证明
//!   「id 存在」，不证明「本账号能用」（`gpt-6-astra` 在清单里，但实测回
//!   `11158` 无权限）。
//! - 判定按**官方业务码**，不按 HTTP 状态 —— `11102`（不存在）与 `11158`
//!   （无权限）都是 400，只有 code 能区分；混淆会把「升级套餐就能用」的
//!   模型永久禁用。
//! - 「没探测过」≠「可用」：枚举出来的名字在探测成功前不进目录，
//!   否则 `/v1/models` 被上百个猜测名污染。
//! - 禁用 ≠ 删除：保留结论与原因，TTL 到期重探。结构性结论（不存在/无
//!   权限/MaaS）缓存久，瞬时结论（限流/上游故障）缓存短。
//! - `UNKNOWN` 不禁用：一次怪响应不该让模型被长期拉黑。

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::region::Region;

// ─── 探测结论 ────────────────────────────────────────────────

/// 单模型可用性探测的结果分类（与官方报错码一一对应）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProbeState {
    /// 200 + 流：存在且当前可用
    Ok,
    /// 11102：这名字根本不存在
    NoSuchModel,
    /// 11158：存在，但当前账号类型无权
    NeedsPro,
    /// 11134：存在，上游临时故障
    UpstreamBroken,
    /// 14003 / 429：存在，限流
    RateLimited,
    /// 11103：存在，但走 MaaS（图像/视频），不支持 chat
    Maas,
    /// 其它情况，无法判定
    Unknown,
}

impl ProbeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProbeState::Ok => "ok",
            ProbeState::NoSuchModel => "no_such_model",
            ProbeState::NeedsPro => "needs_pro",
            ProbeState::UpstreamBroken => "upstream_broken",
            ProbeState::RateLimited => "rate_limited",
            ProbeState::Maas => "maas",
            ProbeState::Unknown => "unknown",
        }
    }
}

/// 各探测结论的缓存时长。结构性结论缓存久，瞬时结论缓存短。
fn ttl_of(state: ProbeState) -> Duration {
    match state {
        ProbeState::Ok => Duration::from_secs(30 * 60),
        ProbeState::NoSuchModel => Duration::from_secs(24 * 60 * 60),
        ProbeState::Maas => Duration::from_secs(24 * 60 * 60),
        ProbeState::NeedsPro => Duration::from_secs(6 * 60 * 60),
        ProbeState::UpstreamBroken => Duration::from_secs(30 * 60),
        ProbeState::RateLimited => Duration::from_secs(10 * 60),
        ProbeState::Unknown => Duration::from_secs(15 * 60),
    }
}

/// 判定一个模型当前是否应「在逻辑层禁用」。
///
/// `Ok` 与 `Unknown` **不在其中**：可用自然放行；「说不清」的结论不能当
/// 「不可用」，否则上游偶发的一次怪响应会把模型长期拉黑。
pub fn is_blocking(state: ProbeState) -> bool {
    matches!(
        state,
        ProbeState::NoSuchModel
            | ProbeState::NeedsPro
            | ProbeState::Maas
            | ProbeState::UpstreamBroken
            | ProbeState::RateLimited
    )
}

// ─── 官方业务码 → 结论 ────────────────────────────────────────

/// 把一次探测的原始结果映射到 [`ProbeState`]。
///
/// 判定依据是官方业务码，而不是 HTTP 状态 —— 400 既可能是「不存在」
/// 也可能是「无权限」，只有 code 能区分。code 缺失时退回文本特征，
/// 尽量别把「不存在」误判成「可用」。
pub fn classify_probe(status: u16, code: Option<i64>, message: &str) -> ProbeState {
    if status == 200 {
        return ProbeState::Ok;
    }
    if code == Some(11102) {
        return ProbeState::NoSuchModel;
    }
    if code == Some(11158) {
        return ProbeState::NeedsPro;
    }
    if code == Some(11134) {
        return ProbeState::UpstreamBroken;
    }
    if code == Some(11103) {
        return ProbeState::Maas;
    }
    if code == Some(14003) || status == 429 {
        return ProbeState::RateLimited;
    }
    let msg = message.to_lowercase();
    if msg.contains("service info not found") || msg.contains("no such model") || msg.contains("not found") {
        return ProbeState::NoSuchModel;
    }
    if msg.contains("not allowed for user type") || msg.contains("permission") {
        return ProbeState::NeedsPro;
    }
    if msg.contains("temporarily unavailable") || msg.contains("provider is ") && msg.contains("unavailable") {
        return ProbeState::UpstreamBroken;
    }
    if msg.contains("backend [") && msg.contains("maas") && msg.contains("not supported") {
        return ProbeState::Maas;
    }
    ProbeState::Unknown
}

// ─── 候选名枚举 ──────────────────────────────────────────────

/// 厂商命名规律（结构性知识，不是模型清单）。
///
/// 按规律生成而不是写死一张表：上游上新/下线时不必改代码，符合惯例的
/// 新模型能被自动发现；探测失败的猜测会被丢掉，不会污染目录。
fn candidate_names() -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |id: String| {
        if !id.is_empty() && seen.insert(id.clone()) {
            out.push(id);
        }
    };

    // {能力档}-model 家族（实测 30 个前缀只命中 5 个，但保留几个低成本的猜测位）
    for tier in ["default", "fast", "balanced", "primary", "max", "mini", "lite", "smart", "basic", "advanced"] {
        push(format!("{tier}-model"));
    }

    // claude-{tier}-{ver}
    for tier in ["sonnet", "opus", "haiku"] {
        for ver in ["4", "4.0", "4.1", "4.5", "4.6", "4.7", "4.8", "5", "5.5"] {
            push(format!("claude-{tier}-{ver}"));
        }
    }
    // claude-{ver}-{tier}
    for ver in ["3.5", "3.7"] {
        for tier in ["sonnet", "opus", "haiku"] {
            push(format!("claude-{ver}-{tier}"));
        }
    }
    // gpt-{ver}
    for ver in ["5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "6", "6.0", "6.1"] {
        push(format!("gpt-{ver}"));
    }
    // gpt-{ver}-{suffix}
    for ver in ["5.4", "5.5", "5.6", "6", "6.1"] {
        for suffix in ["sol", "terra", "luna", "astra", "codex", "mini"] {
            push(format!("gpt-{ver}-{suffix}"));
        }
    }
    // gemini-{ver}-{tier}
    for ver in ["2.5", "3.0", "3.1", "3.5", "3.8"] {
        for tier in ["pro", "flash", "flash-lite"] {
            push(format!("gemini-{ver}-{tier}"));
        }
    }
    // glm-{ver}
    for ver in ["4.6", "5", "5.0", "5.1", "5.2", "5.3", "5.4"] {
        push(format!("glm-{ver}"));
    }
    // glm-{ver}-{suffix}
    for ver in ["5", "5.0", "5.1", "5.2", "5.3", "5.4"] {
        for suffix in ["flash", "air", "pro"] {
            push(format!("glm-{ver}-{suffix}"));
        }
    }
    // kimi-{ver}
    for ver in ["k1", "k2", "k2.5", "k2.6", "k2.7", "k3", "k3.1"] {
        push(format!("kimi-{ver}"));
    }
    // kimi-{ver}-{suffix}
    for ver in ["k3.1", "k3"] {
        for suffix in ["pro", "pro-highspeed", "highspeed", "turbo"] {
            push(format!("kimi-{ver}-{suffix}"));
        }
    }
    // deepseek-{ver}
    for ver in ["v3", "v3.1", "v3.2", "v4", "v4.0", "v4.1", "r1"] {
        push(format!("deepseek-{ver}"));
    }
    // deepseek-{ver}-{suffix}
    for ver in ["v4.1", "v4"] {
        for suffix in ["flash", "pro", "flash-sg"] {
            push(format!("deepseek-{ver}-{suffix}"));
        }
    }
    // minimax-{ver} / minimax-{ver}-{suffix}
    for ver in ["m2", "m2.5", "m3", "m3.1"] {
        push(format!("minimax-{ver}"));
    }
    for ver in ["m3", "m3.1"] {
        for suffix in ["flash", "pro"] {
            push(format!("minimax-{ver}-{suffix}"));
        }
    }
    // hy{ver} / hy{ver}-{suffix}
    for ver in ["2", "3", "4"] {
        push(format!("hy{ver}"));
    }
    for ver in ["3", "4"] {
        for suffix in ["preview", "turbo", "pro"] {
            push(format!("hy{ver}-{suffix}"));
        }
    }
    // grok-{ver}
    for ver in ["4", "4.5", "4.6", "4.7", "5"] {
        push(format!("grok-{ver}"));
    }
    // qwen-{ver}-{tier}
    for ver in ["3", "3.5"] {
        for tier in ["max", "plus", "turbo", "coder"] {
            push(format!("qwen-{ver}-{tier}"));
        }
    }
    out.sort();
    out
}

// ─── 探测状态存储 ─────────────────────────────────────────────

/// 单条探测结论
#[derive(Clone, Debug)]
pub struct ProbeRecord {
    pub state: ProbeState,
    /// 探测时间（毫秒 epoch）
    pub at: i64,
    pub code: Option<i64>,
    pub msg: String,
    pub ms: u64,
}

impl ProbeRecord {
    fn expired(&self, now: i64) -> bool {
        now.saturating_sub(self.at) >= ttl_of(self.state).as_millis() as i64
    }
}

/// 探测状态的进程级存储：`region.provider_id()` → `{model id → record}`。
///
/// 用进程内存而不是落盘：探测结论可以随时重建，不值得引入 IO 依赖；
/// 进程重启即重置 —— 额度本来就可能已重置，正好。
fn store() -> &'static Mutex<HashMap<String, HashMap<String, ProbeRecord>>> {
    static STORE: std::sync::OnceLock<Mutex<HashMap<String, HashMap<String, ProbeRecord>>>> =
        std::sync::OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 记录一条探测结论
fn record(site: &str, model: &str, rec: ProbeRecord) {
    if let Ok(mut map) = store().lock() {
        map.entry(site.to_string())
            .or_default()
            .insert(model.to_string(), rec);
    }
}

/// 该模型此刻是否被「逻辑层禁用」。`None` = 没被禁用（含未探测/已过期/结论不拦截）。
pub fn disabled_reason(site: &str, model: &str) -> Option<ProbeState> {
    let now = now_ms();
    let map = store().lock().ok()?;
    let rec = map.get(site)?.get(model)?;
    if rec.expired(now) {
        return None;
    }
    if is_blocking(rec.state) {
        Some(rec.state)
    } else {
        None
    }
}

/// 已探测确认可用的模型 id 集合
#[allow(dead_code)]
pub fn confirmed_ids(site: &str) -> Vec<String> {
    let now = now_ms();
    let mut out = Vec::new();
    if let Ok(map) = store().lock() {
        if let Some(models) = map.get(site) {
            for (id, rec) in models {
                if rec.state == ProbeState::Ok && !rec.expired(now) {
                    out.push(id.clone());
                }
            }
        }
    }
    out.sort();
    out
}

/// 当前已记录的探测条数（日志与状态展示用）
pub fn recorded_count(site: &str) -> usize {
    store().lock().ok().and_then(|m| m.get(site)).map_or(0, HashMap::len)
}

/// 把探测结论应用到目录：从 `models` 里剔除被禁用的 id。
///
/// 调用方传完整的目录数组，返回过滤后的数组 —— 不直接持有目录句柄，
/// 避免 `providers/workbuddy` 与 `core::models` 循环依赖。
///
/// 「没探过」与「UNKNOWN」**保留**：探测是增量的，第一次跑完之前目录
/// 不能为空；一次怪响应也不该让模型被长期拉黑。
pub fn filter_models(models: &[Value], site: &str) -> Vec<Value> {
    models
        .iter()
        .filter(|model| {
            let id = model.get("id").and_then(Value::as_str).unwrap_or_default();
            if id.is_empty() {
                return true;
            }
            disabled_reason(site, id).is_none()
        })
        .cloned()
        .collect()
}

// ─── 单模型探测 ──────────────────────────────────────────────

/// 探测请求的兜底 system 消息。探测不关心模型行为，只要上游肯回 200。
/// 与 adapter 的 `DEFAULT_SYSTEM_PROMPT` 语义相同但不共享 —— 那是私有 const，
/// 探测只有一个诉求「首条必须是 system，否则 11128」，不值得为此改可见性。
const PROBE_SYSTEM_PROMPT: &str = "你是一个得力助手";

/// 单模型探测结果
#[derive(Clone, Debug)]
pub struct ProbeOutcome {
    pub model: String,
    pub status: u16,
    pub code: Option<i64>,
    pub state: ProbeState,
    pub msg: String,
    pub ms: u64,
}

/// 探测单个模型：发一次最小化的流式请求，只读状态与首个错误帧。
///
/// 语义与参考项目 `probeModelRaw` 一致：
/// - 不走对话链路（那带上下文压缩重试、账号轮换、代理降级，一次探测可能
///   连打三个账号并消耗大量额度）；探测只需要「上游怎么回这一次」。
/// - 复用对话请求头（含三个 `X-Conversation-*`），确保与真实调用同形。
/// - `max_tokens` 默认 32 而不是 1：思考类模型会把预算烧在 `reasoning_tokens`
///   上，1 个 token 会拿到空内容，把可用模型误判成异常。
/// - 连接级失败（ECONNRESET 等）按 `upstream_retry` 的次数与退避重试；
///   超时不重试 —— 探测是串行的，重试超时会把整批拖到分钟级。
///
/// `session` 是一条账号会话（与 `chat_headers` / `chat_completions_url` 同形）；
/// `proxy` 透传给出网层；`retry_attempts` / `retry_backoff_ms` 对应配置里的
/// `upstreamRetry`。
pub async fn probe_model(
    session: &Value,
    region: Region,
    model: &str,
    proxy: Option<&crate::server::core::proxies::ResolvedProxy>,
    max_tokens: i64,
    timeout_ms: u64,
    retry_attempts: usize,
    retry_backoff_ms: &[u64],
) -> ProbeOutcome {
    let t0 = std::time::Instant::now();
    let url = super::adapter::chat_completions_url(session, region);
    let headers = super::adapter::chat_headers(session, region, Some("text/event-stream"));
    let payload = json!({
        "model": model,
        "stream": true,
        "max_tokens": max_tokens.max(1),
        "messages": [
            { "role": "system", "content": PROBE_SYSTEM_PROMPT },
            { "role": "user", "content": "ping" },
        ],
    });

    let attempts = retry_attempts.max(1);
    let mut last_error: Option<String> = None;
    let mut response: Option<crate::server::core::auth_http::ApiResponse> = None;

    for attempt in 1..=attempts {
        match crate::server::core::auth_http::send_raw(
            "POST",
            &url,
            Some(&payload),
            &headers,
            proxy,
            Some(timeout_ms),
        )
        .await
        {
            Ok(resp) => {
                response = Some(resp);
                break;
            }
            Err(error) => {
                last_error = Some(error.to_string());
                // 超时是有结论的失败（上游就是没答），重试只会再等一个完整超时窗口。
                let text = error.to_string();
                if text.contains("timeout") || text.contains("aborted") || text.contains("timed out") {
                    break;
                }
                if attempt < attempts {
                    let backoff = retry_backoff_ms
                        .get(attempt.saturating_sub(1))
                        .copied()
                        .unwrap_or(500);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
            }
        }
    }

    let ms = t0.elapsed().as_millis() as u64;
    let Some(resp) = response else {
        return ProbeOutcome {
            model: model.to_string(),
            status: 0,
            code: None,
            state: ProbeState::Unknown,
            msg: last_error.unwrap_or_else(|| "transport error".into()),
            ms,
        };
    };

    let status = resp.status;
    let body_text = resp.text.unwrap_or_default();
    let payload_json: Option<Value> = serde_json::from_str(&body_text).ok();

    // SSE 流里可能直接给出错误帧；非 200 通常是 JSON 错误体。
    let mut code: Option<i64> = None;
    let mut msg = String::new();
    let mut streamed = false;

    if let Some(obj) = payload_json.as_ref() {
        if obj.get("choices").is_some() {
            streamed = true;
        } else {
            code = obj
                .get("code")
                .and_then(Value::as_i64)
                .or_else(|| obj.pointer("/error/code").and_then(Value::as_i64));
            msg = obj
                .get("msg")
                .and_then(Value::as_str)
                .or_else(|| obj.pointer("/error/message").and_then(Value::as_str))
                .or_else(|| obj.get("message").and_then(Value::as_str))
                .unwrap_or("")
                .to_string();
        }
    } else {
        // 逐行扫 SSE 帧（上游错误有时只在流里出现）
        for line in body_text.lines() {
            let Some(data) = line.strip_prefix("data:") else { continue };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            let Ok(obj) = serde_json::from_str::<Value>(data) else { continue };
            if obj.get("choices").is_some() {
                streamed = true;
                break;
            }
            if obj.get("code").is_some() || obj.get("error").is_some() {
                code = obj
                    .get("code")
                    .and_then(Value::as_i64)
                    .or_else(|| obj.pointer("/error/code").and_then(Value::as_i64));
                msg = obj
                    .get("msg")
                    .and_then(Value::as_str)
                    .or_else(|| obj.pointer("/error/message").and_then(Value::as_str))
                    .unwrap_or("")
                    .to_string();
                break;
            }
        }
    }

    let mut state = classify_probe(status, code, &msg);
    // 200 但流里一个 chunk 都没有 → 判不了，按 unknown 处理
    if state == ProbeState::Ok && !streamed {
        state = ProbeState::Unknown;
    }

    ProbeOutcome {
        model: model.to_string(),
        status,
        code,
        state,
        msg: if msg.is_empty() && status == 200 { "ok".into() } else { msg },
        ms,
    }
}

// ─── 批量探测（官方清单 + 枚举候选）──────────────────────────

/// 探测一批模型并记录。单条失败不影响其余（与参考项目 `runLimited` 隔离
/// 修复后的语义一致）。
///
/// `known_ids` 是官方清单 + 已确认可用的 id —— 这些**也要探**：清单只证明
/// id 存在，不证明本账号能用。`max_official` 限制官方清单探测数（0 = 不限），
/// `max_candidates` 限制枚举候选探测数（0 = 不限）。
pub async fn probe_site(
    session: &Value,
    region: Region,
    proxy: Option<&crate::server::core::proxies::ResolvedProxy>,
    official_ids: &[String],
    concurrency: usize,
    max_tokens: i64,
    timeout_ms: u64,
    retry_attempts: usize,
    retry_backoff_ms: &[u64],
) -> Vec<ProbeOutcome> {
    let site = region.provider_id();

    // 已知清单在前、枚举猜测在后：中途被打断时只有队首探完了，而用户在意的
    // 是目录里那些模型能不能用。
    let mut queue: Vec<String> = official_ids.to_vec();
    let known: std::collections::HashSet<&String> = official_ids.iter().collect();
    for id in candidate_names() {
        if !known.contains(&id) {
            queue.push(id);
        }
    }
    queue.sort();
    queue.dedup();

    // 并发受限地跑；单个失败只影响那一条
    let semaphore = tokio::sync::Semaphore::new(concurrency.max(1));
    let mut handles = Vec::with_capacity(queue.len());
    for model in queue {
        let permit = semaphore.clone().acquire_owned().await;
        let session = session.clone();
        let proxy = proxy.cloned();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            probe_model(
                &session,
                region,
                &model,
                proxy.as_ref(),
                max_tokens,
                timeout_ms,
                retry_attempts,
                retry_backoff_ms,
            )
            .await
        }));
    }

    let mut outcomes = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(outcome) = handle.await {
            record(
                site,
                &outcome.model,
                ProbeRecord {
                    state: outcome.state,
                    at: now_ms(),
                    code: outcome.code,
                    msg: outcome.msg.chars().take(200).collect(),
                    ms: outcome.ms,
                },
            );
            outcomes.push(outcome);
        }
    }
    outcomes
}
