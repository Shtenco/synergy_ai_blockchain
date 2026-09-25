#![forbid(unsafe_code)]

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};
use synergy_agent_fabric::{AgentSpec, SwarmScheduler, TaskSpec};

fn strings(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

fn response(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message.into()}})
}

fn agent_from(params: &Value) -> Result<AgentSpec, String> {
    Ok(AgentSpec {
        id: params.get("id").and_then(Value::as_str).ok_or("agent id required")?.to_string(),
        role: params.get("role").and_then(Value::as_str).unwrap_or("generic").to_string(),
        cpu_millis: params.get("cpu_millis").and_then(Value::as_u64).unwrap_or(1000) as u32,
        memory_mib: params.get("memory_mib").and_then(Value::as_u64).unwrap_or(1024) as u32,
        tools: strings(params.get("tools")),
        remote: params.get("remote").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn task_from(params: &Value) -> Result<TaskSpec, String> {
    Ok(TaskSpec {
        id: params.get("id").and_then(Value::as_str).ok_or("task id required")?.to_string(),
        goal: params.get("goal").and_then(Value::as_str).ok_or("goal required")?.to_string(),
        required_role: params.get("required_role").and_then(Value::as_str).map(str::to_string),
        required_tools: strings(params.get("required_tools")),
        cpu_millis: params.get("cpu_millis").and_then(Value::as_u64).unwrap_or(500) as u32,
        memory_mib: params.get("memory_mib").and_then(Value::as_u64).unwrap_or(512) as u32,
        allow_remote: params.get("allow_remote").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn handle(scheduler: &mut SwarmScheduler, req: Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
    match method {
        "initialize" => response(id, json!({
            "schema":"synergy.worker.v1",
            "service":"synergy-agent-fabric",
            "version":"0.1.0"
        })),
        "agent/register" => match agent_from(&params) {
            Ok(agent) => response(id, json!({"registered":scheduler.register(agent)})),
            Err(message) => error(id, -32602, message),
        },
        "task/lease" => match task_from(&params) {
            Ok(task) => {
                let epoch = params.get("epoch").and_then(Value::as_u64).unwrap_or(1);
                match scheduler.lease(&task, epoch) {
                    Some(lease) => response(id, serde_json::to_value(lease).expect("lease serializes")),
                    None => error(id, 409, "no eligible idle agent"),
                }
            }
            Err(message) => error(id, -32602, message),
        },
        "task/release" => {
            let task_id = params.get("task_id").and_then(Value::as_str).unwrap_or("");
            response(id, json!({"released":scheduler.release(task_id)}))
        }
        "leases/expire" => {
            let epoch = params.get("epoch").and_then(Value::as_u64).unwrap_or(0);
            response(id, json!({"expired":scheduler.expire_leases(epoch)}))
        }
        _ => error(id, -32601, format!("method not found: {method}")),
    }
}

fn main() -> io::Result<()> {
    let mut scheduler = SwarmScheduler::default();
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let out = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle(&mut scheduler, req),
            Err(error_value) => error(Value::Null, -32700, format!("parse error: {error_value}")),
        };
        serde_json::to_writer(&mut stdout, &out)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
