#![forbid(unsafe_code)]

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use synergy_commander_core::{ensure_capability, Capability, ToolPolicy};

struct ManagedProcess {
    child: Child,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
}

struct Runtime {
    policy: ToolPolicy,
    processes: BTreeMap<u64, ManagedProcess>,
    next_process_id: u64,
}

impl Runtime {
    fn new(policy: ToolPolicy) -> Self {
        Self {
            policy,
            processes: BTreeMap::new(),
            next_process_id: 1,
        }
    }

    fn start_process(&mut self, program: &str, argv: &[&str]) -> Result<u64, String> {
        ensure_capability(&self.policy, Capability::RunCommand).map_err(|e| format!("{e:?}"))?;
        self.policy
            .validate_command(program)
            .map_err(|e| format!("{e:?}"))?;
        let mut child = Command::new(program)
            .args(argv)
            .current_dir(&self.policy.workspace_root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let out = Arc::new(Mutex::new(String::new()));
        let err = Arc::new(Mutex::new(String::new()));
        if let Some(mut stdout) = child.stdout.take() {
            let buf = Arc::clone(&out);
            thread::spawn(move || {
                let mut s = String::new();
                let _ = stdout.read_to_string(&mut s);
                if let Ok(mut dst) = buf.lock() {
                    dst.push_str(&s);
                }
            });
        }
        if let Some(mut stderr) = child.stderr.take() {
            let buf = Arc::clone(&err);
            thread::spawn(move || {
                let mut s = String::new();
                let _ = stderr.read_to_string(&mut s);
                if let Ok(mut dst) = buf.lock() {
                    dst.push_str(&s);
                }
            });
        }
        let id = self.next_process_id;
        self.next_process_id = self.next_process_id.saturating_add(1);
        self.processes.insert(
            id,
            ManagedProcess {
                child,
                stdout: out,
                stderr: err,
            },
        );
        Ok(id)
    }
}

fn response(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

fn error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message.into()}})
}

fn tool_specs() -> Value {
    json!([
      {"name":"read_file","description":"Read UTF-8 text from a path inside the configured workspace.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}},
      {"name":"write_file","description":"Write UTF-8 text inside the configured workspace.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]}},
      {"name":"list_directory","description":"List a directory inside the configured workspace.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}},
      {"name":"run_command","description":"Run one allowlisted executable synchronously with explicit argv.","inputSchema":{"type":"object","properties":{"program":{"type":"string"},"args":{"type":"array","items":{"type":"string"}}},"required":["program"]}},
      {"name":"start_process","description":"Start an allowlisted long-running process and return a process session id.","inputSchema":{"type":"object","properties":{"program":{"type":"string"},"args":{"type":"array","items":{"type":"string"}}},"required":["program"]}},
      {"name":"read_process_output","description":"Read accumulated stdout/stderr and current status for a process session.","inputSchema":{"type":"object","properties":{"process_id":{"type":"integer"}},"required":["process_id"]}},
      {"name":"list_processes","description":"List process sessions owned by this commander instance.","inputSchema":{"type":"object","properties":{}}},
      {"name":"kill_process","description":"Terminate a process session owned by this commander instance.","inputSchema":{"type":"object","properties":{"process_id":{"type":"integer"}},"required":["process_id"]}},
      {"name":"system_info","description":"Return minimal local node OS/architecture information.","inputSchema":{"type":"object","properties":{}}}
    ])
}

fn text_result(text: impl Into<String>) -> Value {
    json!({"content":[{"type":"text","text":text.into()}]})
}

fn argv(args: &Value) -> Vec<&str> {
    args.get("args")
        .and_then(Value::as_array)
        .map(|xs| xs.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn call_tool(runtime: &mut Runtime, name: &str, args: &Value) -> Result<Value, String> {
    let policy = &runtime.policy;
    match name {
        "read_file" => {
            ensure_capability(policy, Capability::ReadFile).map_err(|e| format!("{e:?}"))?;
            let p = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or("path required")?;
            let path = policy
                .resolve_workspace_path(p)
                .map_err(|e| format!("{e:?}"))?;
            Ok(text_result(
                fs::read_to_string(path).map_err(|e| e.to_string())?,
            ))
        }
        "write_file" => {
            ensure_capability(policy, Capability::WriteFile).map_err(|e| format!("{e:?}"))?;
            let p = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or("path required")?;
            let content = args
                .get("content")
                .and_then(Value::as_str)
                .ok_or("content required")?;
            if content.len() > policy.max_write_bytes {
                return Err("write exceeds policy max_write_bytes".into());
            }
            let path = policy
                .resolve_workspace_path(p)
                .map_err(|e| format!("{e:?}"))?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(path, content).map_err(|e| e.to_string())?;
            Ok(text_result("OK"))
        }
        "list_directory" => {
            ensure_capability(policy, Capability::ListDirectory).map_err(|e| format!("{e:?}"))?;
            let p = args.get("path").and_then(Value::as_str).unwrap_or("");
            let path = policy
                .resolve_workspace_path(p)
                .map_err(|e| format!("{e:?}"))?;
            let mut names = Vec::new();
            for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
                names.push(
                    entry
                        .map_err(|e| e.to_string())?
                        .file_name()
                        .to_string_lossy()
                        .to_string(),
                );
            }
            names.sort();
            Ok(text_result(names.join("\n")))
        }
        "run_command" => {
            ensure_capability(policy, Capability::RunCommand).map_err(|e| format!("{e:?}"))?;
            let program = args
                .get("program")
                .and_then(Value::as_str)
                .ok_or("program required")?;
            policy
                .validate_command(program)
                .map_err(|e| format!("{e:?}"))?;
            let output = Command::new(program)
                .args(argv(args))
                .current_dir(&policy.workspace_root)
                .output()
                .map_err(|e| e.to_string())?;
            Ok(text_result(format!(
                "exit_code={}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                output
                    .status
                    .code()
                    .map_or_else(|| "signal".into(), |c| c.to_string()),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )))
        }
        "start_process" => {
            let program = args
                .get("program")
                .and_then(Value::as_str)
                .ok_or("program required")?;
            let id = runtime.start_process(program, &argv(args))?;
            Ok(text_result(format!("process_id={id}")))
        }
        "read_process_output" => {
            ensure_capability(policy, Capability::InspectProcess).map_err(|e| format!("{e:?}"))?;
            let id = args
                .get("process_id")
                .and_then(Value::as_u64)
                .ok_or("process_id required")?;
            let proc = runtime.processes.get_mut(&id).ok_or("unknown process_id")?;
            let status = proc.child.try_wait().map_err(|e| e.to_string())?;
            let stdout = proc
                .stdout
                .lock()
                .map_err(|_| "stdout lock poisoned")?
                .clone();
            let stderr = proc
                .stderr
                .lock()
                .map_err(|_| "stderr lock poisoned")?
                .clone();
            Ok(text_result(format!(
                "status={}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                status.map_or_else(|| "running".into(), |s| format!("exited:{:?}", s.code())),
                stdout,
                stderr
            )))
        }
        "list_processes" => {
            ensure_capability(policy, Capability::InspectProcess).map_err(|e| format!("{e:?}"))?;
            let mut lines = Vec::new();
            for (id, proc) in &mut runtime.processes {
                let state = proc
                    .child
                    .try_wait()
                    .map_err(|e| e.to_string())?
                    .map_or_else(|| "running".into(), |s| format!("exited:{:?}", s.code()));
                lines.push(format!("{id}\t{state}"));
            }
            Ok(text_result(lines.join("\n")))
        }
        "kill_process" => {
            ensure_capability(policy, Capability::KillProcess).map_err(|e| format!("{e:?}"))?;
            let id = args
                .get("process_id")
                .and_then(Value::as_u64)
                .ok_or("process_id required")?;
            let proc = runtime.processes.get_mut(&id).ok_or("unknown process_id")?;
            proc.child.kill().map_err(|e| e.to_string())?;
            Ok(text_result("OK"))
        }
        "system_info" => {
            ensure_capability(policy, Capability::SystemInfo).map_err(|e| format!("{e:?}"))?;
            Ok(text_result(format!(
                "os={} arch={}",
                env::consts::OS,
                env::consts::ARCH
            )))
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn handle(runtime: &mut Runtime, req: Value) -> Option<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str)?;
    match method {
        "initialize" => Some(response(
            id,
            json!({
                "protocolVersion":"2025-06-18",
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"synergy-node-commander","version":"0.1.0"}
            }),
        )),
        "notifications/initialized" => None,
        "tools/list" => Some(response(id, json!({"tools":tool_specs()}))),
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            Some(match call_tool(runtime, name, &args) {
                Ok(v) => response(id, v),
                Err(e) => response(
                    id,
                    json!({"content":[{"type":"text","text":e}],"isError":true}),
                ),
            })
        }
        _ => Some(error(id, -32601, format!("method not found: {method}"))),
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) != Some("mcp")
        || args.get(2).map(String::as_str) != Some("--stdio")
    {
        eprintln!("usage: synergy-node mcp --stdio");
        std::process::exit(2);
    }

    let workspace = env::var_os("SYNERGY_WORKSPACE")
        .map(PathBuf::from)
        .unwrap_or(env::current_dir()?);
    let mut runtime = Runtime::new(ToolPolicy::developer_default(workspace));

    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let out = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle(&mut runtime, req),
            Err(e) => Some(error(Value::Null, -32700, format!("parse error: {e}"))),
        };
        if let Some(out) = out {
            serde_json::to_writer(&mut stdout, &out)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}
