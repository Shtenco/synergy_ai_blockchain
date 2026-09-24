#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, os, shutil, subprocess, sys
from pathlib import Path
from urllib.request import Request, urlopen

URL="https://huggingface.co/bartowski/Qwen_Qwen3.5-0.8B-GGUF/resolve/main/Qwen_Qwen3.5-0.8B-Q4_K_M.gguf?download=true"
NAME="Qwen_Qwen3.5-0.8B-Q4_K_M.gguf"
SHA256="fb044e93939a70469c905781334f5de1e6c8b608ced6cbc8c9249bd4127d9526"

def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(8*1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def download(dst:Path)->None:
    tmp=dst.with_suffix(dst.suffix+".part")
    req=Request(URL,headers={"User-Agent":"SYNERGY-MVP/1"})
    with urlopen(req,timeout=60) as r, tmp.open("wb") as f:
        shutil.copyfileobj(r,f,length=8*1024*1024)
    os.replace(tmp,dst)

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--dir",default="models/qwen35_08b")
    p.add_argument("--llama-cli")
    p.add_argument("--prompt",default="Reply with exactly: SYNERGY_QWEN_OK")
    args=p.parse_args()
    d=Path(args.dir);d.mkdir(parents=True,exist_ok=True)
    dst=d/NAME
    if not dst.exists():
        print(f"downloading {URL}",flush=True);download(dst)
    got=sha256(dst)
    print("sha256",got,flush=True)
    if got!=SHA256:
        raise SystemExit(f"SHA mismatch: expected {SHA256}, got {got}")
    if args.llama_cli:
        cmd=[args.llama_cli,"-m",str(dst),"-p",args.prompt,"-n","32","--temp","0","--seed","1","--no-display-prompt","--simple-io"]
        proc=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=180)
        print(proc.stdout)
        if proc.returncode!=0 or not proc.stdout.strip():
            print(proc.stderr,file=sys.stderr)
            raise SystemExit("llama.cpp inference failed")
    return 0

if __name__=="__main__":raise SystemExit(main())
