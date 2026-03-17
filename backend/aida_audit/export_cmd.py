import os
import sys
import json
import time
import hashlib
import argparse
import glob
import subprocess
import shutil
import sqlite3
import threading
import tempfile
import platform
import re
import select
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

# =============================================================================
# Import Setup
# =============================================================================

from .ghidra_importer import import_ghidra_export
from .elf_service import ElfService
from .audit_database import AuditDatabase
from .constants import AUDIT_DB_FILENAME
from .workspace import init_workspace

# =============================================================================
# Shared Utilities & Logging
# =============================================================================

class ConsoleLogger:
    def __init__(self, log_file=None):
        self._lock = threading.Lock()
        self.binary_name = None
        self.log_file = os.path.abspath(log_file) if log_file else None
        self._ansi_re = re.compile(r"\x1b\[[0-9;]*m")
        self._use_color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self._ctx_icon = {
            "ERROR": "❌",
            "WARN": "⚠️ ",
            "MERGE": "🧩",
            "MASTER": "🧠",
            "ORCHESTRATOR": "🧭",
            "BUNDLE": "📦",
            "GHIDRA": "🐉",
            "HOST": "🖥️ ",
        }
        if self.log_file:
            parent = os.path.dirname(self.log_file)
            if parent:
                os.makedirs(parent, exist_ok=True)

    def set_binary(self, name):
        with self._lock:
            self.binary_name = name

    def log(self, msg, context="HOST"):
        ts = time.strftime("%H:%M:%S", time.localtime())
        if msg.startswith("[IDA ") and "]" in msg:
            try:
                parts = msg.split("] ", 1)
                if len(parts) > 1:
                    msg = parts[1]
            except Exception:
                pass
        level = self._detect_level(msg)
        msg_text = self._style_msg(msg, level)
        time_text = self._style(ts, "90")
        base = f"[{time_text}]"
        if self.binary_name:
            base += f" {self._style(self.binary_name, '35')}"
        self._emit_line(f"{base} | {msg_text}")

    def plain(self, msg):
        self._emit_line(msg)

    def _detect_level(self, msg):
        msg_upper = msg.upper()
        if "[ERROR]" in msg_upper or "FAILED" in msg_upper or "ERROR" in msg_upper:
            return "ERROR"
        if "[WARN]" in msg_upper or "WARNING" in msg_upper:
            return "WARN"
        if "[INFO]" in msg_upper:
            return "INFO"
        return "NORMAL"

    def _style_msg(self, msg, level):
        if level == "ERROR":
            return f"❌ {self._style(msg, '31')}"
        if level == "WARN":
            return f"⚠️  {self._style(msg, '33')}"
        if level == "INFO":
            return f"ℹ️  {self._style(msg, '37')}"
        if "Done (" in msg or "Success" in msg:
            return f"✅ {self._style(msg, '32')}"
        if "Starting" in msg or "Launching" in msg:
            return f"🚀 {self._style(msg, '36')}"
        return msg

    def _style(self, text, color_code):
        if not self._use_color:
            return text
        return f"\033[{color_code}m{text}\033[0m"

    def _emit_line(self, line):
        with self._lock:
            print(line, flush=True)
            if self.log_file:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    sanitized = self._ansi_re.sub("", line)
                    f.write(f"{sanitized}\n")


class ExportProgressPanel:
    def __init__(self, logger):
        self.logger = logger
        self._lock = threading.Lock()
        self._started = False
        self.start_time = None
        self.binary_name = "-"
        self.output_db = "-"
        self.backend = "-"
        self.workers = 0
        self.stage = "Pending"
        self.detail = ""
        self.worker_total = 0
        self.worker_done = 0
        self.worker_failed = 0
        self.worker_running = 0
        self.status = "Running"
        self.last_event = ""
        self.last_event_at = 0.0
        self._last_stage_key = None
        self._last_notify = ""
        self._last_notify_at = 0.0

    def start(self, binary_name, output_db, backend, workers):
        with self._lock:
            self._started = True
            self.start_time = time.time()
            self.binary_name = binary_name
            self.output_db = output_db
            self.backend = backend
            self.workers = workers
            self.stage = "Initializing"
            self.detail = "Preparing export task"
            self.worker_total = 0
            self.worker_done = 0
            self.worker_failed = 0
            self.worker_running = 0
            self.status = "Running"
            self.last_event = "Task created"
            self.last_event_at = time.time()
            self._last_stage_key = None
            self._last_notify = ""
            self._last_notify_at = 0.0
            self.logger.log(
                f"🚀 Export started | target={self.binary_name} | backend={self.backend} | workers={self.workers}",
                context="ORCHESTRATOR",
            )
            self.logger.log(f"📄 Output database: {self.output_db}", context="ORCHESTRATOR")

    def update_stage(self, stage, detail=""):
        with self._lock:
            if not self._started:
                return
            self.stage = stage
            self.detail = detail
            stage_key = f"{stage}|{detail}"
            if stage_key != self._last_stage_key:
                self._last_stage_key = stage_key
                text = f"🔄 Stage: {stage}"
                if detail:
                    text += f" | {detail}"
                self.logger.log(text, context="ORCHESTRATOR")

    def set_worker_total(self, total):
        with self._lock:
            if not self._started:
                return
            self.worker_total = total
            self.worker_done = 0
            self.worker_failed = 0
            self.worker_running = total
            self.last_event = f"Parallel tasks started: {total} workers"
            self.last_event_at = time.time()
            self.logger.log(
                f"🧵 Parallel tasks started: total={total}, running={self.worker_running}",
                context="ORCHESTRATOR",
            )

    def worker_finished(self, ok):
        with self._lock:
            if not self._started:
                return
            self.worker_done += 1
            if not ok:
                self.worker_failed += 1
            if self.worker_running > 0:
                self.worker_running -= 1
            self.last_event = (
                f"Worker finished {self.worker_done}/{self.worker_total}"
                + (f", failed {self.worker_failed}" if self.worker_failed else "")
            )
            self.last_event_at = time.time()
            icon = "✅" if ok else "❌"
            self.logger.log(
                f"{icon} Worker progress: done={self.worker_done}/{self.worker_total}, running={self.worker_running}, failed={self.worker_failed}",
                context="ORCHESTRATOR",
            )

    def notify(self, detail):
        with self._lock:
            if not self._started:
                return
            self.last_event = detail
            self.last_event_at = time.time()
            now = time.time()
            if detail != self._last_notify and now - self._last_notify_at >= 1.5:
                self._last_notify = detail
                self._last_notify_at = now

    def finish(self, success, message):
        with self._lock:
            if not self._started:
                return
            self.status = "Completed" if success else "Failed"
            self.stage = "Finished"
            self.detail = message
            self.last_event = message
            self.last_event_at = time.time()
            elapsed = time.time() - self.start_time if self.start_time else 0.0
            prefix = "✅ Export completed" if success else "❌ Export failed"
            self.logger.log(f"{prefix} | elapsed={elapsed:.1f}s | {message}", context="ORCHESTRATOR")
            self._started = False

def _sha256_prefix(path, n=8):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()[:n]

def _safe_makedirs(path):
    os.makedirs(path, exist_ok=True)

def _is_within_dir(path, root_dir):
    path = os.path.realpath(os.path.abspath(path))
    root_dir = os.path.realpath(os.path.abspath(root_dir))
    try:
        common = os.path.commonpath([path, root_dir])
    except Exception:
        return False
    return common == root_dir

def _ensure_audit_db(out_dir: str, logger=None) -> str:
    audit_db = os.path.join(out_dir, AUDIT_DB_FILENAME)
    if not os.path.exists(audit_db):
        db = AuditDatabase(audit_db, logger=logger)
        db.connect()
        db.close()
    return audit_db


def _copy_to_out_dir(src_path, out_dir):
    src_path = os.path.abspath(src_path)
    out_dir = os.path.abspath(out_dir)
    
    # Resolve symlinks to ensure we copy the actual file content
    real_src = src_path
    if os.path.islink(src_path):
        try:
            real_src = os.path.realpath(src_path)
        except Exception:
            real_src = src_path

    if not os.path.exists(real_src):
        raise FileNotFoundError(f"Source file not found (or broken link): {src_path}")
        
    if not os.path.isfile(real_src):
        raise OSError(f"Source is not a regular file: {real_src}")

    dst_path = os.path.join(out_dir, os.path.basename(src_path))
    
    if os.path.abspath(dst_path) == os.path.abspath(real_src):
        return dst_path
        
    try:
        shutil.copy2(real_src, dst_path)
    except Exception as e:
        raise OSError(f"Failed to copy {real_src} to {dst_path}: {e}")

    if not os.path.exists(dst_path) or not os.path.getsize(dst_path) > 0:
         # Double check if file exists and has content (unless source was empty)
         if os.path.getsize(real_src) > 0:
             raise OSError(f"Copy failed or resulted in empty file: {dst_path}")
             
    return dst_path

def _make_db_name(src_path):
    name = os.path.basename(src_path)
    return f"{name}.db"


def _build_export_layout(output_root):
    output_root = os.path.abspath(output_root)
    return {
        "root": output_root,
        "binaries_dir": os.path.join(output_root, "binaries"),
        "databases_dir": os.path.join(output_root, "databases"),
        "idbs_dir": os.path.join(output_root, "idbs"),
    }


def _ensure_export_layout(output_root):
    layout = _build_export_layout(output_root)
    _safe_makedirs(layout["root"])
    _safe_makedirs(layout["binaries_dir"])
    _safe_makedirs(layout["databases_dir"])
    _safe_makedirs(layout["idbs_dir"])
    return layout

def _expand_targets(target_value):
    if not target_value:
        return []
    if glob.has_magic(target_value):
        matches = [p for p in glob.glob(target_value, recursive=True) if os.path.isfile(p)]
        uniq = sorted(set(matches))
        return uniq
    return [target_value]


def _detect_idb_path(binary_path):
    for ext in (".i64", ".idb"):
        p = binary_path + ext
        if os.path.exists(p):
            return p
    return None

# =============================================================================
# Export Orchestrator
# =============================================================================

class ExportOrchestrator:
    def __init__(self, workers=4, verbose=False, log_file=None, backend="ida"):
        self.workers = workers
        self.verbose = verbose
        self.backend = backend
        self.logger = ConsoleLogger(log_file=log_file)
        self.progress = ExportProgressPanel(self.logger)
        self.log_file = os.path.abspath(log_file) if log_file else None
        self.layout = None
        self.worker_idle_timeout = max(30, int(os.environ.get("AIDA_EXPORT_WORKER_IDLE_TIMEOUT", "900")))
        self.worker_max_retries = max(0, int(os.environ.get("AIDA_EXPORT_WORKER_MAX_RETRIES", "1")))

    def set_layout(self, layout):
        self.layout = layout

    def _resolve_layout(self, out_dir):
        if self.layout and self.layout.get("root"):
            return self.layout
        return _ensure_export_layout(out_dir)

    def run_command(self, cmd, stream_output=False, context="HOST"):
        if context != "HOST":
            self.logger.log("Starting...", context=context)
        else:
            self.logger.log("Starting command...", context="HOST")
        self.progress.notify(f"{context} started")
            
        start_time = time.time()
        
        if stream_output:
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            stdout_lines = []
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    stripped = line.rstrip()
                    self.logger.log(stripped, context=context)
                    stdout_lines.append(line)
                    if stripped:
                        self.progress.notify(f"{context}: {stripped[:80]}")
            
            returncode = process.poll()
            result_stdout = "".join(stdout_lines)
            result_stderr = "" # Merged into stdout
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            returncode = result.returncode
            result_stdout = result.stdout
            result_stderr = result.stderr
            
        duration = time.time() - start_time
        
        if returncode != 0:
            self.progress.update_stage("Failed", f"{context} exit code {returncode}")
            self.logger.log(f"Failed (exit={returncode}, {duration:.2f}s).", context=context)
            if not stream_output:
                self.logger.plain(result_stdout.rstrip())
            self.logger.plain(result_stderr.rstrip())
            self.progress.notify(f"{context} failed (exit={returncode})")
            return {"ok": False, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}
            
        self.logger.log(f"Done ({duration:.2f}s).", context=context)
        self.progress.notify(f"{context} done ({duration:.2f}s)")
        return {"ok": True, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}

    def _run_command_with_idle_timeout(self, cmd, context, idle_timeout):
        self.logger.log("Starting...", context=context)
        self.progress.notify(f"{context} started")
        start_time = time.time()
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        stdout_lines = []
        timed_out = False
        last_output_at = time.time()
        try:
            while True:
                ready, _, _ = select.select([process.stdout], [], [], 1.0)
                if ready:
                    line = process.stdout.readline()
                    if line:
                        stripped = line.rstrip()
                        self.logger.log(stripped, context=context)
                        stdout_lines.append(line)
                        if stripped:
                            self.progress.notify(f"{context}: {stripped[:80]}")
                        last_output_at = time.time()
                        continue

                if process.poll() is not None:
                    break

                if idle_timeout and (time.time() - last_output_at) >= idle_timeout:
                    timed_out = True
                    self.logger.log(f"No worker output for {idle_timeout}s, killing process.", context=context)
                    self.progress.notify(f"{context} timeout after {idle_timeout}s")
                    try:
                        process.kill()
                    except Exception:
                        pass
                    break
        finally:
            try:
                remaining = process.stdout.read() if process.stdout else ""
            except Exception:
                remaining = ""
            if remaining:
                stdout_lines.append(remaining)
                for raw in remaining.splitlines():
                    if raw:
                        self.logger.log(raw, context=context)
                        self.progress.notify(f"{context}: {raw[:80]}")
            try:
                if process.stdout:
                    process.stdout.close()
            except Exception:
                pass
            try:
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
                try:
                    process.wait(timeout=5)
                except Exception:
                    pass

        returncode = process.returncode
        result_stdout = "".join(stdout_lines)
        duration = time.time() - start_time

        if timed_out:
            self.logger.log(f"Failed (timeout, {duration:.2f}s).", context=context)
            return {
                "ok": False,
                "duration": duration,
                "returncode": returncode if returncode is not None else -9,
                "stdout": result_stdout,
                "stderr": "",
                "timed_out": True,
            }

        if returncode != 0:
            self.logger.log(f"Failed (exit={returncode}, {duration:.2f}s).", context=context)
            self.progress.notify(f"{context} failed (exit={returncode})")
            return {
                "ok": False,
                "duration": duration,
                "returncode": returncode,
                "stdout": result_stdout,
                "stderr": "",
                "timed_out": False,
            }

        self.logger.log(f"Done ({duration:.2f}s).", context=context)
        self.progress.notify(f"{context} done ({duration:.2f}s)")
        return {
            "ok": True,
            "duration": duration,
            "returncode": returncode,
            "stdout": result_stdout,
            "stderr": "",
            "timed_out": False,
        }

    def _collect_idb_candidates(self, path_spec):
        if not path_spec:
            return []
        abs_path = os.path.abspath(path_spec)
        root, ext = os.path.splitext(abs_path)
        ext = ext.lower()
        candidates = []
        if ext in (".i64", ".idb"):
            candidates.extend([abs_path, root + ".i64", root + ".idb"])
        else:
            candidates.extend([abs_path + ".i64", abs_path + ".idb"])
        uniq = []
        seen = set()
        for p in candidates:
            rp = os.path.realpath(p)
            if rp in seen:
                continue
            seen.add(rp)
            uniq.append(p)
        return uniq

    def _find_existing_idb(self, input_path, save_idb):
        base_name = os.path.splitext(input_path)[0]
        candidates = []
        candidates.extend(self._collect_idb_candidates(input_path))
        candidates.extend(self._collect_idb_candidates(base_name))
        candidates.extend(self._collect_idb_candidates(save_idb))
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
        return None

    def _run_worker_task(self, worker_idx, chunk_file, chunk_size, input_path, analyzed_idb, ida_export_script, temp_dir):
        worker_root = os.path.join(temp_dir, "workers", f"worker_{worker_idx}")
        max_attempts = self.worker_max_retries + 1
        result = {
            "ok": False,
            "worker_db": None,
            "attempts": 0,
            "returncode": None,
        }

        for attempt in range(max_attempts):
            attempt_dir = os.path.join(worker_root, f"attempt_{attempt + 1}")
            if os.path.exists(attempt_dir):
                shutil.rmtree(attempt_dir, ignore_errors=True)
            os.makedirs(attempt_dir, exist_ok=True)

            local_chunk = os.path.join(attempt_dir, "funcs.json")
            shutil.copy2(chunk_file, local_chunk)

            worker_db = os.path.join(attempt_dir, "worker.db")
            worker_input = input_path

            if analyzed_idb:
                ext = os.path.splitext(analyzed_idb)[1]
                worker_idb = os.path.join(attempt_dir, f"worker_input{ext}")
                try:
                    shutil.copy2(analyzed_idb, worker_idb)
                    worker_input = worker_idb
                except Exception as e:
                    self.logger.log(
                        f"Worker {worker_idx} failed to prepare IDB copy: {e}. Using original input.",
                        context="ORCHESTRATOR",
                    )

            cmd = f"\"{sys.executable}\" \"{ida_export_script}\" \"{worker_input}\" --output \"{worker_db}\" --mode worker --funcs-file \"{local_chunk}\""
            self.logger.log(
                f"Worker {worker_idx}: funcs={chunk_size} attempt={attempt + 1}/{max_attempts} dir={attempt_dir}",
                context="ORCHESTRATOR",
            )
            run_res = self._run_command_with_idle_timeout(
                cmd=cmd,
                context=f"WORKER_{worker_idx}",
                idle_timeout=self.worker_idle_timeout,
            )

            result.update(
                {
                    "ok": bool(run_res.get("ok")),
                    "worker_db": worker_db,
                    "attempts": attempt + 1,
                    "returncode": run_res.get("returncode"),
                    "timed_out": bool(run_res.get("timed_out")),
                }
            )

            if result["ok"]:
                return result

            if attempt + 1 < max_attempts:
                self.logger.log(
                    f"Worker {worker_idx} failed on attempt {attempt + 1}, clearing temp directory and restarting.",
                    context="ORCHESTRATOR",
                )
                shutil.rmtree(attempt_dir, ignore_errors=True)

        return result

    def _resolve_ghidra_home(self):
        env_home = os.environ.get("GHIDRA_HOME")
        if env_home:
            return os.path.abspath(env_home)
        return None

    def _get_ghidra_headless(self, ghidra_home):
        if not ghidra_home:
            return None
        
        system = platform.system()
        if system == "Windows":
            cand = os.path.join(ghidra_home, "support", "analyzeHeadless.bat")
            if os.path.exists(cand):
                return cand
        else:
            cand = os.path.join(ghidra_home, "support", "analyzeHeadless")
            if os.path.exists(cand):
                return cand
        return None

    def _run_ghidra_headless(self, input_path, export_dir, threads=None, chunk_size=None):
        ghidra_home = self._resolve_ghidra_home()
        headless = self._get_ghidra_headless(ghidra_home)
        if not headless:
            raise FileNotFoundError("Ghidra headless analyzer not found. Please set GHIDRA_HOME to your Ghidra installation directory.")
        script_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "ghidra_export"))
        if not os.path.isdir(script_dir):
            raise FileNotFoundError("Ghidra script directory not found")
        project_dir = os.path.join(export_dir, "project")
        os.makedirs(project_dir, exist_ok=True)
        project_name = "aida-audit"
        json_dir = os.path.join(export_dir, "json")
        os.makedirs(json_dir, exist_ok=True)
        thread_count = max(1, int(threads) if threads else 1)
        chunk_value = int(chunk_size) if chunk_size is not None else 0
        script_args = f"\"{json_dir}\" --threads {thread_count} --chunk {chunk_value}"
        cmd = (
            f"\"{headless}\" \"{project_dir}\" \"{project_name}\" "
            f"-import \"{input_path}\" -scriptPath \"{script_dir}\" -overwrite "
            f"-postScript AidaExport.java -- {script_args}"
        )
        res = self.run_command(cmd, stream_output=True, context="GHIDRA")
        if not res["ok"]:
            return None
        return json_dir

    def merge_databases(self, main_db, worker_dbs):
        self.logger.log(f"Merging {len(worker_dbs)} worker databases into {main_db}...", context="MERGE")
        conn = sqlite3.connect(main_db)
        cursor = conn.cursor()
        
        # Ensure pseudocode table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pseudocode (
                function_va INTEGER PRIMARY KEY,
                content TEXT
            )
        """)
        conn.commit()
        
        count = 0
        for worker_db in worker_dbs:
            if not os.path.exists(worker_db):
                self.logger.log(f"Warning: Worker DB {worker_db} not found.", context="MERGE")
                continue
                
            try:
                # Attach worker DB
                cursor.execute(f"ATTACH DATABASE '{worker_db}' AS worker")
                
                # Copy pseudocode
                cursor.execute("INSERT OR REPLACE INTO pseudocode SELECT * FROM worker.pseudocode")
                
                conn.commit()
                cursor.execute("DETACH DATABASE worker")
                count += 1
            except Exception as e:
                self.logger.log(f"Error merging {worker_db}: {e}", context="MERGE")
                
        conn.close()
        self.logger.log(f"Merged {count} worker databases.", context="MERGE")

    def print_full_performance_summary(self, parallel_stats, master_perf, worker_perfs):
        total_time = parallel_stats.get("total_time", 0.0)
        master_time = parallel_stats.get("master_time", 0.0)
        worker_time = parallel_stats.get("worker_time", 0.0)
        merge_time = parallel_stats.get("merge_time", 0.0)
        total_funcs = parallel_stats.get("total_funcs", 0)
        workers = parallel_stats.get("workers", 0)

        attempted = 0
        decompiled = 0
        failed = 0
        pseudocode_time = 0.0

        for wp in worker_perfs:
            try:
                t = wp.get("timer", {})
                pseudocode_step = None
                for step in t.get("steps", []):
                    if step.get("name") == "Pseudocode":
                        pseudocode_step = step
                        break
                if pseudocode_step:
                    pseudocode_time += float(pseudocode_step.get("duration", 0.0))

                ps = (wp.get("export", {}) or {}).get("pseudocode", {}) or {}
                attempted += int(ps.get("attempted", 0))
                decompiled += int(ps.get("decompiled", 0))
                failed += int(ps.get("failed", 0))
            except Exception:
                continue

        overall_speed = (total_funcs / total_time) if total_time else 0.0
        worker_speed = (total_funcs / worker_time) if worker_time else 0.0
        pseudo_speed = (attempted / pseudocode_time) if pseudocode_time else 0.0

        self.logger.plain("")
        self.logger.plain("=" * 72)
        self.logger.plain(f"{'FINAL EXPORT PERFORMANCE SUMMARY':^72}")
        self.logger.plain("=" * 72)
        self.logger.plain(f"{'Total Time':<28}: {total_time:>10.2f}s")
        self.logger.plain(f"{'Master (Step 1)':<28}: {master_time:>10.2f}s")
        self.logger.plain(f"{'Workers (Step 3)':<28}: {worker_time:>10.2f}s")
        self.logger.plain(f"{'Merge (Step 4)':<28}: {merge_time:>10.2f}s")
        self.logger.plain("-" * 72)
        self.logger.plain(f"{'Total Functions':<28}: {total_funcs:>10}")
        self.logger.plain(f"{'Worker Threads':<28}: {workers:>10}")
        self.logger.plain(f"{'Overall Speed':<28}: {overall_speed:>10.2f} funcs/sec")
        self.logger.plain(f"{'Worker Speed':<28}: {worker_speed:>10.2f} funcs/sec")
        if attempted:
            self.logger.plain(f"{'Pseudocode Attempted':<28}: {attempted:>10}")
            self.logger.plain(f"{'Pseudocode Decompiled':<28}: {decompiled:>10}")
            self.logger.plain(f"{'Pseudocode Failed':<28}: {failed:>10}")
            self.logger.plain(f"{'Pseudocode Speed':<28}: {pseudo_speed:>10.2f} funcs/sec")

        if master_perf and master_perf.get("timer", {}).get("steps"):
            self.logger.plain("-" * 72)
            self.logger.plain("Master Step Breakdown:")
            for step in master_perf["timer"]["steps"]:
                name = step.get("name", "")
                dur = float(step.get("duration", 0.0))
                self.logger.plain(f"  {name:<26} {dur:>10.2f}s")

        if worker_perfs:
            self.logger.plain("-" * 72)
            self.logger.plain("Worker Pseudocode Breakdown:")
            for idx, wp in enumerate(worker_perfs):
                ps = (wp.get("export", {}) or {}).get("pseudocode", {}) or {}
                attempted_i = int(ps.get("attempted", 0))
                decompiled_i = int(ps.get("decompiled", 0))
                failed_i = int(ps.get("failed", 0))
                thunks_i = int(ps.get("thunks", 0))
                library_i = int(ps.get("library", 0))
                nofunc_i = int(ps.get("nofunc", 0))
                none_i = int(ps.get("none", 0))
                min_ea_i = ps.get("min_ea", None)
                max_ea_i = ps.get("max_ea", None)
                top_errors_i = ps.get("top_errors", []) or []

                pseudocode_dur = 0.0
                for step in (wp.get("timer", {}) or {}).get("steps", []):
                    if step.get("name") == "Pseudocode":
                        pseudocode_dur = float(step.get("duration", 0.0))
                        break
                rate_i = (attempted_i / pseudocode_dur) if pseudocode_dur else 0.0

                range_str = ""
                try:
                    if min_ea_i is not None and max_ea_i is not None:
                        range_str = f"{hex(int(min_ea_i))}-{hex(int(max_ea_i))}"
                except Exception:
                    range_str = ""
                self.logger.plain(
                    f"  Worker {idx:<3} {pseudocode_dur:>7.2f}s  funcs={attempted_i:<5} ok={decompiled_i:<5} fail={failed_i:<5} thunk={thunks_i:<4} lib={library_i:<4} none={none_i:<4} nofunc={nofunc_i:<4} rate={rate_i:>7.2f}/s {range_str}".rstrip()
                )
                if failed_i and top_errors_i:
                    for entry in top_errors_i[:3]:
                        err = str(entry.get("error", ""))
                        cnt = int(entry.get("count", 0))
                        self.logger.plain(f"           {cnt}x {err}")

        self.logger.plain("=" * 72)
        self.logger.plain("")

    def _run_master_analysis(self, master_input, output_db, temp_dir, save_idb=None, role=None):
        """
        Step 1: Run Master (Export Metadata + Dump Functions)
        """
        self.progress.update_stage("Master Analysis", "Exporting metadata and extracting function list")
        self.logger.log("Running Master (Analysis & Metadata)", context="ORCHESTRATOR")
        master_start = time.time()

        funcs_json = os.path.join(temp_dir, "funcs.json")
        analysis_base = os.path.join(temp_dir, "analysis")
        if save_idb:
            analysis_base = os.path.abspath(save_idb)
            low = analysis_base.lower()
            if low.endswith(".i64") or low.endswith(".idb"):
                analysis_base = os.path.splitext(analysis_base)[0]

        # NOTE: We assume ida-export-worker.py is in the same directory as this script
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        ida_export_script = os.path.join(current_script_dir, "ida_export_worker.py")

        master_cmd = f"\"{sys.executable}\" \"{ida_export_script}\" \"{master_input}\" --output \"{output_db}\" --mode master --funcs-file \"{funcs_json}\" --save-idb \"{analysis_base}\" --fast"
        if role:
            master_cmd += f" --role {role}"
            
        result = self.run_command(master_cmd, stream_output=True, context="MASTER")
        
        if not result["ok"]:
            self.logger.log("Master step failed. Aborting.", context="ORCHESTRATOR")
            return None
            
        if not os.path.exists(funcs_json):
            self.logger.log("Error: Function list was not generated.", context="ORCHESTRATOR")
            return None

        return {
            "duration": time.time() - master_start,
            "funcs_json": funcs_json,
            "analysis_base": analysis_base,
        }

    def _split_work(self, funcs_json, temp_dir):
        """
        Step 2: Split Work
        """
        self.progress.update_stage("Splitting Task", "Preparing parallel worker tasks")
        self.logger.log("Splitting work", context="ORCHESTRATOR")
        try:
            with open(funcs_json, 'r') as f:
                all_funcs = json.load(f)
        except Exception as e:
            self.logger.log(f"Error reading funcs.json: {e}", context="ORCHESTRATOR")
            return None
            
        total_funcs = len(all_funcs)
        self.logger.log(f"Total functions: {total_funcs}", context="ORCHESTRATOR")
        
        if total_funcs == 0:
            self.logger.log("No functions found. Nothing to parallelize.", context="ORCHESTRATOR")
            return {"total_funcs": 0, "worker_files": []}

        # Balanced partitioning
        base_size = total_funcs // self.workers
        remainder = total_funcs % self.workers
        
        chunks = []
        start = 0
        for i in range(self.workers):
            size = base_size + (1 if i < remainder else 0)
            if size > 0:
                chunks.append(all_funcs[start : start + size])
                start += size
        
        worker_files = []
        for i, chunk in enumerate(chunks):
            chunk_file = os.path.join(temp_dir, f"funcs_worker_{i}.json")
            worker_db = os.path.join(temp_dir, f"worker_{i}.db")
            with open(chunk_file, 'w') as f:
                json.dump(chunk, f)
            worker_files.append((chunk_file, worker_db, len(chunk)))
            
        return {"total_funcs": total_funcs, "worker_files": worker_files}

    def _run_workers(self, input_path, analysis_base, existing_idb, worker_files, temp_dir):
        """
        Step 3: Run Workers
        """
        self.progress.update_stage("Parallel Export", "Workers processing pseudocode")
        self.progress.set_worker_total(len(worker_files))
        self.logger.log(f"Launching {len(worker_files)} workers", context="ORCHESTRATOR")
        worker_start = time.time()
        
        analyzed_idb = None
        for ext in [".i64", ".idb"]:
            candidate = analysis_base + ext
            if os.path.exists(candidate):
                analyzed_idb = candidate
                break
        if not analyzed_idb:
            analyzed_idb = existing_idb

        if not analyzed_idb:
            self.logger.log("Warning: No analyzed IDB found from master. Workers will try to open binary directly.", context="ORCHESTRATOR")
            
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        ida_export_script = os.path.join(current_script_dir, "ida_export_worker.py")

        worker_dbs = []
        worker_results = [None] * len(worker_files)
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_idx = {}
            for i, (chunk_file, _worker_db, chunk_size) in enumerate(worker_files):
                future = executor.submit(
                    self._run_worker_task,
                    i,
                    chunk_file,
                    chunk_size,
                    input_path,
                    analyzed_idb,
                    ida_export_script,
                    temp_dir,
                )
                future_to_idx[future] = i

            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                res = future.result()
                worker_results[idx] = res
                if res.get("worker_db"):
                    worker_dbs.append(res["worker_db"])
                self.progress.worker_finished(res["ok"])
            
        duration = time.time() - worker_start
            
        if not all(r and r.get("ok") for r in worker_results):
            self.logger.log("Some workers failed.", context="ORCHESTRATOR")
            
        return {
            "duration": duration,
            "results": worker_results,
            "worker_dbs": worker_dbs,
        }

    def process_single_file_ghidra(self, input_path, output_db, role=None):
        input_path = os.path.abspath(input_path)
        if not os.path.exists(input_path):
            self.logger.log(f"Error: Input file '{input_path}' not found.", context="ERROR")
            return False

        if not output_db:
            output_db = os.path.splitext(input_path)[0] + ".db"

        output_db = os.path.abspath(output_db)
        layout = self._resolve_layout(os.path.dirname(os.path.dirname(output_db)))
        self.logger.set_binary(os.path.basename(input_path))

        output_is_dir = (
            os.path.isdir(output_db)
            or output_db.endswith(os.sep)
            or output_db.endswith("/")
            or output_db.endswith("\\")
            or (not os.path.splitext(output_db)[1] and not output_db.lower().endswith(".db"))
        )

        export_root = None
        cleanup_export_root = False
        if output_is_dir:
            if os.path.isfile(output_db):
                self.logger.log(f"Error: Output path is a file, not a directory: {output_db}", context="ERROR")
                self.progress.finish(False, "Output path error")
                return False
            out_dir = output_db
            _safe_makedirs(out_dir)
            copied_bin = _copy_to_out_dir(input_path, layout["binaries_dir"])
            input_path = copied_bin
            output_db = os.path.join(layout["databases_dir"], f"{os.path.basename(input_path)}.db")
            export_root = os.path.join(out_dir, "ghidra_export")
            _safe_makedirs(export_root)
        else:
            export_base = os.path.splitext(os.path.basename(output_db))[0]
            export_root = os.path.join(os.path.dirname(output_db), f"{export_base}.ghidra_export")
            _safe_makedirs(export_root)
            try:
                copied_bin = _copy_to_out_dir(input_path, layout["binaries_dir"])
                input_path = copied_bin
                self.logger.log(f"Copied {os.path.basename(input_path)} -> {copied_bin}", context="ORCHESTRATOR")
            except Exception as e:
                self.logger.log(f"Warning: failed to copy input binary to output directory: {e}", context="ORCHESTRATOR")

        self.progress.start(os.path.basename(input_path), output_db, self.backend, self.workers)
        self.progress.update_stage("Prepare", "Initializing export context")

        if os.path.exists(output_db):
            self.logger.log(f"Target database already exists: {output_db}", context="ORCHESTRATOR")
            self.logger.log("Skipping export.", context="ORCHESTRATOR")
            self.progress.finish(True, "Target database already exists, skipped")
            return True

        self.logger.log(f"Input  : {input_path}", context="ORCHESTRATOR")
        self.logger.log(f"Output : {output_db}", context="ORCHESTRATOR")

        _ensure_audit_db(layout["databases_dir"], self.logger)

        temp_dir = export_root or tempfile.mkdtemp(prefix="ghidra_export_")
        json_dir = None
        try:
            self.progress.update_stage("Ghidra Export", "Running headless export")
            json_dir = self._run_ghidra_headless(
                input_path,
                temp_dir,
                threads=self.workers,
                chunk_size=0
            )
            if not json_dir:
                self.progress.finish(False, "Ghidra export failed")
                return False
            self.progress.update_stage("Import Database", "Writing to SQLite database")
            ok = import_ghidra_export(json_dir, output_db, self.logger, role=role)
            if not ok:
                self.progress.finish(False, "Failed to import export results")
                return False
            self.progress.finish(True, "Export completed")
            return True
        except Exception as e:
            self.logger.log(f"Failed to export with ghidra: {e}", context="ERROR")
            self.progress.finish(False, f"Export exception: {e}")
            return False
        finally:
            if cleanup_export_root and not (json_dir and os.path.exists(json_dir)):
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass

    def process_directory_ghidra(self, scan_dir, out_dir, target_binary):
        scan_dir = os.path.abspath(scan_dir)
        out_dir = os.path.abspath(out_dir)

        layout = self._resolve_layout(out_dir)

        if not target_binary:
            self.logger.log("Error: target_binary is required for directory processing.", context="ERROR")
            return

        target_path = os.path.abspath(target_binary)
        if not os.path.exists(target_path):
            raise FileNotFoundError(target_path)
        if not _is_within_dir(target_path, scan_dir):
            raise ValueError("target_binary must be within scan_dir")

        src_path = os.path.abspath(target_path)
        name = os.path.basename(src_path)

        try:
            deps = ElfService.resolve_recursive_dependencies(scan_dir, src_path)
            dep_paths = []
            for dep in deps:
                dep_path = dep.get("path")
                if dep_path and os.path.exists(dep_path):
                    dep_paths.append(os.path.abspath(dep_path))

            targets = [src_path] + [p for p in dep_paths if p != src_path]
            seen = set()
            out_db = None
            for path in targets:
                if path in seen:
                    continue
                seen.add(path)
                out_bin = _copy_to_out_dir(path, layout["binaries_dir"])
                self.logger.log(f"Copied {os.path.basename(path)} -> {out_bin}", context="BUNDLE")

                db_name = _make_db_name(path)
                db_path = os.path.join(layout["databases_dir"], db_name)
                # Determine role: target is main, dependencies are dependency
                role = "target" if path == src_path else "dependency"
                self.logger.log(f"Exporting {os.path.basename(path)} -> {db_path} (role={role})", context="BUNDLE")

                success = self.process_single_file_ghidra(
                    input_path=out_bin,
                    output_db=db_path,
                    role=role,
                )
                if path == src_path:
                    out_db = db_path if success else None

            return out_db
        except Exception as e:
            self.logger.log(f"Failed to process {name}: {e}", context="ERROR")
            return None

    def process_single_file(self, input_path, output_db, save_idb=None, role=None):
        input_path = os.path.abspath(input_path)
        if not os.path.exists(input_path):
            self.logger.log(f"Error: Input file '{input_path}' not found.", context="ERROR")
            return False

        if not output_db:
            output_db = os.path.splitext(input_path)[0] + ".db"
        
        output_db = os.path.abspath(output_db)
        layout = self._resolve_layout(os.path.dirname(os.path.dirname(output_db)))
        self.logger.set_binary(os.path.basename(input_path))
        self.progress.start(os.path.basename(input_path), output_db, self.backend, self.workers)
        self.progress.update_stage("Prepare", "Initializing export context")
            
        # Ensure original binary is present in the output directory
        try:
            copied_bin = _copy_to_out_dir(input_path, layout["binaries_dir"])
            input_path = copied_bin
            self.logger.log(f"Copied {os.path.basename(input_path)} -> {copied_bin}", context="ORCHESTRATOR")
        except Exception as e:
            self.logger.log(f"Warning: failed to copy input binary to output directory: {e}", context="ORCHESTRATOR")

        if os.path.exists(output_db):
            self.logger.log(f"Target database already exists: {output_db}", context="ORCHESTRATOR")
           
        self.logger.log(f"Input  : {input_path}", context="ORCHESTRATOR")
        self.logger.log(f"Output : {output_db}", context="ORCHESTRATOR")
        self.logger.log(f"Workers: {self.workers}", context="ORCHESTRATOR")

        _ensure_audit_db(layout["databases_dir"], self.logger)

        # Setup temporary directory
        temp_dir = os.path.join(os.path.dirname(output_db), f"ida_parallel_temp_{os.getpid()}_{int(time.time())}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        
        stats = {
            'start_time': time.time(),
            'workers': self.workers,
            'total_funcs': 0
        }

        if save_idb is None:
            save_idb = os.path.join(layout["idbs_dir"], os.path.basename(input_path))
        existing_idb = self._find_existing_idb(input_path, save_idb)
        if existing_idb:
            self.logger.log(f"Reusing existing IDB: {existing_idb}", context="ORCHESTRATOR")

        try:
            self.progress.update_stage("Master Analysis", "Exporting metadata and extracting functions")
            # Step 1: Run Master
            master_res = self._run_master_analysis(existing_idb or input_path, output_db, temp_dir, save_idb, role)
            if not master_res:
                self.progress.finish(False, "Master analysis failed")
                return False
            stats['master_time'] = master_res['duration']
            
            # Update existing_idb if it wasn't set, using the result from Master
            # This ensures subsequent steps (like CPG export) use the analyzed DB
            if not existing_idb:
                ab = master_res.get('analysis_base')
                if ab:
                    for ext in [".i64", ".idb"]:
                        candidate = ab + ext
                        if os.path.exists(candidate):
                            existing_idb = candidate
                            break

            # Step 2: Split Work
            split_res = self._split_work(master_res['funcs_json'], temp_dir)
            if not split_res:
                self.progress.finish(False, "Task split failed")
                return False
            stats['total_funcs'] = split_res['total_funcs']
            worker_files = split_res['worker_files']
            
            # Step 3: Run Workers
            worker_res = self._run_workers(
                input_path, 
                master_res['analysis_base'], 
                existing_idb, 
                worker_files, 
                temp_dir
            )
            stats['worker_time'] = worker_res['duration']
            
            # Step 4: Merge Results
            self.progress.update_stage("Merging Results", "Merging worker databases")
            self.logger.log("Merging results", context="ORCHESTRATOR")
            merge_start = time.time()
            
            worker_dbs_paths = worker_res.get("worker_dbs") or [w_db for _, w_db, _ in worker_files]
            self.merge_databases(output_db, worker_dbs_paths)
            
            stats['merge_time'] = time.time() - merge_start
            stats['total_time'] = time.time() - stats['start_time']
            
            self.logger.log(f"Success! Full export saved to {output_db}", context="ORCHESTRATOR")
            self.progress.finish(True, "Export completed")
            return True
        except Exception as e:
            self.logger.log(f"Failed to export: {e}", context="ERROR")
            self.progress.finish(False, f"Export exception: {e}")
            return False
            
        finally:
            try:
                 shutil.rmtree(temp_dir) 
            except:
                 pass

    def process_directory(self, scan_dir, out_dir, target_binary):
        scan_dir = os.path.abspath(scan_dir)
        out_dir = os.path.abspath(out_dir)
        layout = self._resolve_layout(out_dir)

        if not target_binary:
            self.logger.log("Error: target_binary is required for directory processing.", context="ERROR")
            return

        # Dependency-based scan
        target_path = os.path.abspath(target_binary)
        if not os.path.exists(target_path):
            raise FileNotFoundError(target_path)
        if not _is_within_dir(target_path, scan_dir):
            raise ValueError("target_binary must be within scan_dir")

        name = os.path.basename(target_path)
        try:
            deps = ElfService.resolve_recursive_dependencies(scan_dir, target_path)
            dep_paths = []
            for dep in deps:
                dep_path = dep.get("path")
                if dep_path and os.path.exists(dep_path):
                    dep_paths.append(os.path.abspath(dep_path))

            targets = [target_path] + [p for p in dep_paths if p != target_path]
            seen = set()
            out_db = None
            for path in targets:
                if path in seen:
                    continue
                seen.add(path)
                out_bin = _copy_to_out_dir(path, layout["binaries_dir"])
                self.logger.log(f"Copied {os.path.basename(path)} -> {out_bin}", context="BUNDLE")

                db_name = _make_db_name(path)
                db_path = os.path.join(layout["databases_dir"], db_name)
                # Determine role: target is main, dependencies are dependency
                role = "target" if path == target_path else "dependency"
                self.logger.log(f"Exporting {os.path.basename(path)} -> {db_path} (role={role})", context="BUNDLE")

                success = self.process_single_file(
                    input_path=out_bin,
                    output_db=db_path,
                    save_idb=None,
                    role=role,
                )
                if path == target_path:
                    out_db = db_path if success else None
            return out_db
        except Exception as e:
            self.logger.log(f"Failed to process {name}: {e}", context="ERROR")
            return None

# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Export binary analysis results to SQLite database and initialize workspace with MCP client configs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export a single binary
  aida-audit export ./binary -o ./output

  # Export with Ghidra backend
  aida-audit export ./binary -o ./output --backend ghidra

  # Bulk mode - scan directory for dependencies
  aida-audit export ./target -o ./output --scan-dir ./rootfs

  # Multiple targets with wildcards
  aida-audit export ./libs/*.so -o ./output

Workspace:
  The export command automatically initializes the output directory with:
  - opencode.json       OpenCode project config
  - .mcp.json           MCP client configuration
  - .trae/mcp.json      Trae client MCP config
  - .claude/settings.local.json  Claude desktop settings
  - .opencode/skills/   OpenCode skills (if available)
  - .claude/skills/     Claude Code skills (if available)
"""
    )

    parser.add_argument("target", nargs="+", help="Input binary file(s) or pattern")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("-s", "--scan-dir", metavar="DIR", help="Scan directory for dependencies (enables bulk mode)")
    parser.add_argument("-j", "--workers", type=int, default=4, help="Number of parallel workers (default: 4)")
    parser.add_argument("-l", "--log-file", metavar="PATH", help="Write logs to file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--backend", choices=["ida", "ghidra"], default="ida", help="Export backend: ida or ghidra (default: ida)")

    args = parser.parse_args()

    if args.backend == "ghidra":
        ghidra_home = os.environ.get("GHIDRA_HOME")
        if not ghidra_home:
            print("Error: Please set GHIDRA_HOME environment variable before using ghidra backend.")
            print("Example: export GHIDRA_HOME=/path/to/ghidra")
            sys.exit(1)
    
    target_values = []
    for raw_target in args.target:
        target_values.extend(_expand_targets(raw_target))
    if not target_values:
        print("Error: No valid target paths found.")
        sys.exit(1)

    target_paths = [os.path.abspath(t) for t in target_values]
    missing = [t for t in target_paths if not os.path.exists(t)]
    if missing:
        print(f"Error: Target path '{missing[0]}' does not exist.")
        sys.exit(1)

    orchestrator = ExportOrchestrator(
        workers=args.workers,
        verbose=args.verbose,
        log_file=args.log_file,
        backend=args.backend
    )

    output_dir = os.path.abspath(args.output)
    if output_dir.lower().endswith(".db"):
        print("Error: Output path must be a directory.")
        sys.exit(1)
    layout = _ensure_export_layout(output_dir)
    orchestrator.set_layout(layout)
    _ensure_audit_db(layout["databases_dir"], orchestrator.logger)
    init_workspace(output_dir)
    orchestrator.logger.log(f"🏗️  Workspace initialized: {output_dir}", context="HOST")
    orchestrator.logger.log(f"📦 Binaries  : {layout['binaries_dir']}", context="HOST")
    orchestrator.logger.log(f"🗄️  Databases : {layout['databases_dir']}", context="HOST")
    orchestrator.logger.log(f"💾 IDBs      : {layout['idbs_dir']}", context="HOST")

    # Determine mode based on arguments
    if args.scan_dir:
        # Bulk Mode
        scan_dir = os.path.abspath(args.scan_dir)
        if not os.path.isdir(scan_dir):
            print(f"Error: Scan directory '{scan_dir}' does not exist or is not a directory.")
            sys.exit(1)

        for target_path in target_paths:
            if not _is_within_dir(target_path, scan_dir):
                print(f"Error: Target binary '{target_path}' must be within scan directory '{scan_dir}' for bulk mode.")
                sys.exit(1)

        orchestrator.logger.log(f"📚 Mode: Bulk (Targets={len(target_paths)}, Scan={scan_dir})", context="HOST")
        try:
            for target_path in target_paths:
                if args.backend == "ghidra":
                    out_db = orchestrator.process_directory_ghidra(
                        scan_dir=scan_dir,
                        out_dir=output_dir,
                        target_binary=target_path,
                    )
                else:
                    out_db = orchestrator.process_directory(
                        scan_dir=scan_dir,
                        out_dir=output_dir,
                        target_binary=target_path,
                    )
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
            
    else:
        # Single Mode
        orchestrator.logger.log(f"🎯 Mode: Single (Targets={len(target_paths)})", context="HOST")
        all_ok = True
        for target_path in target_paths:
            if os.path.isdir(target_path):
                print(f"Error: Target '{target_path}' is a directory. For directory scanning, use --scan-dir.")
                sys.exit(1)

            output_db = os.path.join(layout["databases_dir"], _make_db_name(target_path))

            if args.backend == "ghidra":
                success = orchestrator.process_single_file_ghidra(
                    input_path=target_path,
                    output_db=output_db,
                )
            else:
                success = orchestrator.process_single_file(
                    input_path=target_path,
                    output_db=output_db,
                    save_idb=None,
                )
            all_ok = all_ok and bool(success)
        sys.exit(0 if all_ok else 1)

if __name__ == "__main__":
    main()
