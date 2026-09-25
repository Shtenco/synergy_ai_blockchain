#![forbid(unsafe_code)]

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use synergy_commander_core::{ensure_capability, Capability, ToolPolicy};

const MAX_READ_LINES: usize = 5_000;
const MAX_SEARCH_RESULTS: usize = 200;
const MAX_SEARCH_FILE_BYTES: u64 = 1024 * 1024;

struct ManagedProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    stdout_offset: usize,
    stderr_offset: usize,
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let stdin = child.stdin.take();
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
                stdin,
                stdout: out,
                stderr: err,
                stdout_offset: 0,
                stderr_offset: 0,
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
      {"name":"read_file","description":"Read UTF-8 text inside the workspace, optionally by line range.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"offset_line":{"type":"integer","minimum":0},"max_lines":{"type":"integer","minimum":1,"maximum":5000}},"required":["path"]}},
      {"name":"write_file","description":"Rewrite or append UTF-8 text inside the workspace.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"},"mode":{"type":"string","enum":["rewrite","append"]}},"required":["path","content"]}},
      {"name":"edit_file","description":"Replace exactly one occurrence of old_string in a UTF-8 workspace file.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"old_string":{"type":"string"},"new_string":{"type":"string"}},"required":["path","old_string","new_string"]}},
      {"name":"list_directory","description":"List entries in a workspace directory with basic type metadata.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}},
      {"name":"search_files","description":"Recursively search UTF-8 files under a workspace directory without following symlinks.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"query":{"type":"string"},"max_results":{"type":"integer","minimum":1,"maximum":200}},"required":["query"]}},
      {"name":"create_directory","description":"Create a directory tree inside the workspace.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}},
      {"name":"move_path","description":"Rename or move a file/directory inside the workspace.","inputSchema":{"type":"object","properties":{"source":{"type":"string"},"destination":{"type":"string"}},"required":["source","destination"]}},
      {"name":"file_info","description":"Return metadata for a file or directory inside the workspace.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}},
      {"name":"run_command","description":"Run one allowlisted executable synchronously with explicit argv.","inputSchema":{"type":"object","properties":{"program":{"type":"string"},"args":{"type":"array","items":{"type":"string"}}},"required":["program"]}},
      {"name":"start_process","description":"Start an allowlisted long-running process and return a commander-owned process id.","inputSchema":{"type":"object","properties":{"program":{"type":"string"},"args":{"type":"array","items":{"type":"string"}}},"required":["program"]}},
      {"name":"read_process_output","description":"Read new stdout/stderr accumulated since the previous read.","inputSchema":{"type":"object","properties":{"process_id":{"type":"integer"}},"required":["process_id"]}},
      {"name":"send_process_input","description":"Write UTF-8 input to a commander-owned process stdin.","inputSchema":{"type":"object","properties":{"process_id":{"type":"integer"},"input":{"type":"string"}},"required":["process_id","input"]}},
      {"name":"list_processes","description":"List process sessions owned by this commander instance.","inputSchema":{"type":"object","properties":{}}},
      {"name":"kill_process","description":"Terminate a process session owned by this commander instance.","inputSchema":{"type":"object","properties":{"process_id":{"type":"integer"}},"required":["process_id"]}},
      {"name":"system_info","description":"Return local node OS/architecture and workspace boundary.","inputSchema":{"type":"object","properties":{}}}
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

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} required"))
}

fn line_slice(data: &str, offset: usize, max_lines: usize) -> String {
    data.lines()
        .skip(offset)
        .take(max_lines.min(MAX_READ_LINES))
        .collect::<Vec<_>>()
        .join("\n")
}

fn search_tree(
    root: &Path,
    query: &str,
    max_results: usize,
    results: &mut Vec<String>,
) -> Result<(), String> {
    if results.len() >= max_results {
        return Ok(());
    }
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        if results.len() >= max_results {
            break;
        }
        let entry = entry.map_err(|e| e.to_string())?;
        let file_type = entry.file_type().map_err(|e| e.to_string())?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            search_tree(&path, query, max_results, results)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let metadata = entry.metadata().map_err(|e| e.to_string())?;
        if metadata.len() > MAX_SEARCH_FILE_BYTES {
            continue;
        }
        let Ok(data) = fs::read_to_string(&path) else {
            continue;
        };
        for (idx, line) in data.lines().enumerate() {
            if line.contains(query) {
                results.push(format!("{}:{}:{}", path.display(), idx + 1, line));
                if results.len() >= max_results {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn call_tool(runtime: &mut Runtime, name: &str, args: &Value) -> Result<Value, String> {
    let policy = &runtime.policy;
    match name {
        "read_file" => {
            ensure_capability(policy, Capability::ReadFile).map_err(|e| format!("{e:?}"))?;
            let path = policy
                .resolve_existing_workspace_path(required_str(args, "path")?)
                .map_err(|e| format!("{e:?}"))?;
            let data = fs::read_to_string(path).map_err(|e| e.to_string())?;
            let offset = args.get("offset_line").and_then(Value::as_u64).unwrap_or(0) as usize;
            let max_lines = args
                .get("max_lines")
                .and_then(Value::as_u64)
                .unwrap_or(MAX_READ_LINES as u64) as usize;
            Ok(text_result(line_slice(&data, offset, max_lines)))
        }
        "write_file" => {
            ensure_capability(policy, Capability::WriteFile).map_err(|e| format!("{e:?}"))?;
            let content = required_str(args, "content")?;
            if content.len() > policy.max_write_bytes {
                return Err("write exceeds policy max_write_bytes".into());
            }
            let path = policy
                .resolve_write_workspace_path(required_str(args, "path")?)
                .map_err(|e| format!("{e:?}"))?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            match args.get("mode").and_then(Value::as_str).unwrap_or("rewrite") {
                "rewrite" => fs::write(path, content).map_err(|e| e.to_string())?,
                "append" => {
                    let mut file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .map_err(|e| e.to_string())?;
                    file.write_all(content.as_bytes()).map_err(|e| e.to_string())?;
                }
                _ => return Err("mode must be rewrite or append".into()),
            }
            Ok(text_result("OK"))
        }
        "edit_file" => {
            ensure_capability(policy, Capability::EditFile).map_err(|e| format!("{e:?}"))?;
            let path = policy
                .resolve_existing_workspace_path(required_str(args, "path")?)
                .map_err(|e| format!("{e:?}"))?;
            let old = required_str(args, "old_string")?;
            let new = required_str(args, "new_string")?;
            if new.len() > policy.max_write_bytes {
                return Err("replacement exceeds policy max_write_bytes".into());
            }
            let data = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            let count = data.matches(old).count();
            if count != 1 {
                return Err(format!("old_string must match exactly once; matches={count}"));
            }
            let changed = data.replacen(old, new, 1);
            if changed.len() > policy.max_write_bytes {
                return Err("edited file exceeds policy max_write_bytes".into());
            }
            fs::write(path, changed).map_err(|e| e.to_string())?;
            Ok(text_result("OK"))
        }
        "list_directory" => {
            ensure_capability(policy, Capability::ListDirectory).map_err(|e| format!("{e:?}"))?;
            let path = policy
                .resolve_existing_workspace_path(
                    args.get("path").and_then(Value::as_str).unwrap_or(""),
                )
                .map_err(|e| format!("{e:?}"))?;
            let mut lines = Vec::new();
            for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let ty = entry.file_type().map_err(|e| e.to_string())?;
                let kind = if ty.is_symlink() {
                    "symlink"
                } else if ty.is_dir() {
                    "dir"
                } else if ty.is_file() {
                    "file"
                } else {
                    "other"
                };
                lines.push(format!("{kind}\t{}", entry.file_name().to_string_lossy()));
            }
            lines.sort();
            Ok(text_result(lines.join("\n")))
        }
        "search_files" => {
            ensure_capability(policy, Capability::SearchFiles).map_err(|e| format!("{e:?}"))?;
            let path = policy
                .resolve_existing_workspace_path(
                    args.get("path").and_then(Value::as_str).unwrap_or(""),
                )
                .map_err(|e| format!("{e:?}"))?;
            let query = required_str(args, "query")?;
            if query.is_empty() {
                return Err("query must not be empty".into());
            }
            let max_results = args
                .get("max_results")
                .and_then(Value::as_u64)
                .unwrap_or(50)
                .min(MAX_SEARCH_RESULTS as u64) as usize;
            let mut results = Vec::new();
            search_tree(&path, query, max_results, &mut results)?;
            Ok(text_result(results.join("\n")))
        }
        "create_directory" => {
            ensure_capability(policy, Capability::CreateDirectory).map_err(|e| format!("{e:?}"))?;
            let path = policy
                .resolve_write_workspace_path(required_str(args, "path")?)
                .map_err(|e| format!("{e:?}"))?;
            fs::create_dir_all(path).map_err(|e| e.to_string())?;
            Ok(text_result("OK"))
        }
        "move_path" => {
            ensure_capability(policy, Capability::MoveFile).map_err(|e| format!("{e:?}"))?;
            let source = policy
                .resolve_existing_workspace_path(required_str(args, "source")?)
                .map_err(|e| format!("{e:?}"))?;
            let destination = policy
                .resolve_write_workspace_path(required_str(args, "destination")?)
                .map_err(|e| format!("{e:?}"))?;
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::rename(source, destination).map_err(|e| e.to_string())?;
            Ok(text_result("OK"))
        }
        "file_info" => {
            ensure_capability(policy, Capability::FileInfo).map_err(|e| format!("{e:?}"))?;
            let path = policy
                .resolve_existing_workspace_path(required_str(args, "path")?)
                .map_err(|e| format!("{e:?}"))?;
            let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
            Ok(text_result(format!(
                "path={}\nis_file={}\nis_dir={}\nlen={}\nreadonly={}",
                path.display(),
                meta.is_file(),
                meta.is_dir(),
                meta.len(),
                meta.permissions().readonly()
            )))
        }
        "run_command" => {
            ensure_capability(policy, Capability::RunCommand).map_err(|e| format!("{e:?}"))?;
            let program = required_str(args, "program")?;
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
            let program = required_str(args, "program")?;
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
            let stdout_guard = proc.stdout.lock().map_err(|_| "stdout lock poisoned")?;
            let stderr_guard = proc.stderr.lock().map_err(|_| "stderr lock poisoned")?;
            let stdout = stdout_guard
                .get(proc.stdout_offset..)
                .ok_or("stdout offset invalid")?
                .to_string();
            let stderr = stderr_guard
                .get(proc.stderr_offset..)
                .ok_or("stderr offset invalid")?
                .to_string();
            proc.stdout_offset = stdout_guard.len();
            proc.stderr_offset = stderr_guard.len();
            Ok(text_result(format!(
                "status={}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                status.map_or_else(|| "running".into(), |s| format!("exited:{:?}", s.code())),
                stdout,
                stderr
            )))
        }
        "send_process_input" => {
            ensure_capability(policy, Capability::InteractProcess).map_err(|e| format!("{e:?}"))?;
            let id = args
                .get("process_id")
                .and_then(Value::as_u64)
                .ok_or("process_id required")?;
            let input = required_str(args, "input")?;
            let proc = runtime.processes.get_mut(&id).ok_or("unknown process_id")?;
            let stdin = proc.stdin.as_mut().ok_or("process stdin unavailable")?;
            stdin.write_all(input.as_bytes()).map_err(|e| e.to_string())?;
            stdin.flush().map_err(|e| e.to_string())?;
            Ok(text_result("OK"))
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
                "os={}\narch={}\nworkspace={}",
                env::consts::OS,
                env::consts::ARCH,
                policy.workspace_root.display()
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
                "serverInfo":{"name":"synergy-node-commander","version":"0.2.0"}
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
