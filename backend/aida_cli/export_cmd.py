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
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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
        if self.log_file:
            parent = os.path.dirname(self.log_file)
            if parent:
                os.makedirs(parent, exist_ok=True)

    def set_binary(self, name):
        with self._lock:
            self.binary_name = name

    def log(self, msg, context="HOST"):
        ts = time.strftime("%H:%M:%S", time.localtime())
        
        # Clean up worker output (strip [IDA HH:MM:SS])
        # Example: [IDA 12:00:00] [INFO] msg -> [INFO] msg
        if msg.startswith("[IDA ") and "]" in msg:
             try:
                 parts = msg.split("] ", 1)
                 if len(parts) > 1:
                     msg = parts[1]
             except:
                 pass
        
        # Format: [DateTime] [Context] [Binary] Msg
        # Align Context to 12 chars
        
        context_str = f"[{context}]"
        base = f"[{ts}] {context_str:<14}"
        
        if self.binary_name:
            base += f" [{self.binary_name}]"
            
        final_msg = f"{base} {msg}"
        self._write_line(final_msg)

    def plain(self, msg):
        self._write_line(msg)

    def _write_line(self, line):
        if not self.log_file:
            return
        with self._lock:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"{line}\n")


class ExportProgressPanel:
    def __init__(self):
        self.console = Console()
        self._lock = threading.Lock()
        self._started = False
        self._live = None
        self.start_time = None
        self.binary_name = "-"
        self.output_db = "-"
        self.backend = "-"
        self.workers = 0
        self.stage = "等待开始"
        self.detail = ""
        self.worker_total = 0
        self.worker_done = 0
        self.worker_failed = 0
        self.worker_running = 0
        self.status = "运行中"
        self.last_event = ""
        self.last_event_at = 0.0

    def start(self, binary_name, output_db, backend, workers):
        with self._lock:
            self._started = True
            self.start_time = time.time()
            self.binary_name = binary_name
            self.output_db = output_db
            self.backend = backend
            self.workers = workers
            self.stage = "初始化"
            self.detail = "准备导出任务"
            self.worker_total = 0
            self.worker_done = 0
            self.worker_failed = 0
            self.worker_running = 0
            self.status = "运行中"
            self.last_event = "任务已创建"
            self.last_event_at = time.time()
            self._live = Live(self._render(), console=self.console, refresh_per_second=16, transient=False)
            self._live.start()

    def update_stage(self, stage, detail=""):
        with self._lock:
            if not self._started:
                return
            self.stage = stage
            self.detail = detail
            self._refresh()

    def set_worker_total(self, total):
        with self._lock:
            if not self._started:
                return
            self.worker_total = total
            self.worker_done = 0
            self.worker_failed = 0
            self.worker_running = total
            self.last_event = f"并行任务启动: {total} 个 worker"
            self.last_event_at = time.time()
            self._refresh()

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
                f"worker 完成 {self.worker_done}/{self.worker_total}"
                + (f"，失败 {self.worker_failed}" if self.worker_failed else "")
            )
            self.last_event_at = time.time()
            self._refresh()

    def notify(self, detail):
        with self._lock:
            if not self._started:
                return
            self.last_event = detail
            self.last_event_at = time.time()
            self._refresh()

    def finish(self, success, message):
        with self._lock:
            if not self._started:
                return
            self.status = "完成" if success else "失败"
            self.stage = "结束"
            self.detail = message
            self.last_event = message
            self.last_event_at = time.time()
            self._refresh()
            if self._live:
                self._live.stop()
                self._live = None
            self._started = False

    def _refresh(self):
        if self._live:
            self._live.update(self._render())

    def _render(self):
        elapsed = 0.0
        if self.start_time:
            elapsed = time.time() - self.start_time
        table = Table.grid(padding=(0, 1))
        table.add_column(justify="right", style="cyan")
        table.add_column()
        table.add_row("状态", self.status)
        table.add_row("阶段", self.stage)
        table.add_row("目标", self.binary_name)
        table.add_row("后端", self.backend)
        table.add_row("输出", self.output_db)
        parallel_text = str(self.workers)
        if self.worker_total > 0:
            parallel_text = (
                f"{self.workers} (运行中 {self.worker_running}, 完成 {self.worker_done}/{self.worker_total}, "
                f"失败 {self.worker_failed})"
            )
        table.add_row("并行", parallel_text)
        table.add_row("耗时", f"{elapsed:.1f}s")
        if self.detail:
            table.add_row("说明", self.detail)
        if self.last_event:
            event_age = max(0.0, time.time() - self.last_event_at) if self.last_event_at else 0.0
            table.add_row("最近事件", f"{self.last_event} ({event_age:.1f}s 前)")
        border_style = "green" if self.status == "完成" else "red" if self.status == "失败" else "blue"
        title = Text("AIDA Export", style="bold")
        return Panel(table, title=title, border_style=border_style)

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
        self.progress = ExportProgressPanel()
        self.log_file = os.path.abspath(log_file) if log_file else None
        self.layout = None

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
        self.progress.notify(f"{context} 启动")
            
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
            self.progress.update_stage("执行失败", f"{context} 退出码 {returncode}")
            self.logger.log(f"Failed (exit={returncode}, {duration:.2f}s).", context=context)
            if not stream_output:
                self.logger.plain(result_stdout.rstrip())
            self.logger.plain(result_stderr.rstrip())
            self.progress.notify(f"{context} 失败 (exit={returncode})")
            return {"ok": False, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}
            
        self.logger.log(f"Done ({duration:.2f}s).", context=context)
        self.progress.notify(f"{context} 完成 ({duration:.2f}s)")
        return {"ok": True, "duration": duration, "returncode": returncode, "stdout": result_stdout, "stderr": result_stderr}

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
        project_name = "aida-cli"
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
        self.progress.update_stage("主分析", "导出元数据并提取函数列表")
        self.logger.log("Running Master (Analysis & Metadata)", context="ORCHESTRATOR")
        master_start = time.time()

        funcs_json = os.path.join(temp_dir, "funcs.json")
        analysis_base = os.path.join(temp_dir, "analysis")
        if save_idb:
            analysis_base = os.path.abspath(save_idb)
            low = analysis_base.lower()
            if low.endswith(".i64") or low.endswith(".idb"):
                analysis_base = os.path.splitext(analysis_base)[0]

        master_perf_json = os.path.join(temp_dir, "perf_master.json")

        # NOTE: We assume ida-export-worker.py is in the same directory as this script
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        ida_export_script = os.path.join(current_script_dir, "ida_export_worker.py")

        master_cmd = f"\"{sys.executable}\" \"{ida_export_script}\" \"{master_input}\" --output \"{output_db}\" --parallel-master --dump-funcs \"{funcs_json}\" --save-idb \"{analysis_base}\" --perf-json \"{master_perf_json}\" --no-perf-report --fast --plain-log"
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
            "master_perf_json": master_perf_json
        }

    def _split_work(self, funcs_json, temp_dir):
        """
        Step 2: Split Work
        """
        self.progress.update_stage("拆分任务", "准备并行 worker 任务")
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
        self.progress.update_stage("并行导出", "worker 正在处理伪代码")
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
        
        worker_cmds = []
        worker_perf_paths = []
        for i, (chunk_file, worker_db, chunk_size) in enumerate(worker_files):
            worker_input = input_path
            
            if analyzed_idb:
                # Copy IDB for this worker to avoid contention
                ext = os.path.splitext(analyzed_idb)[1]
                worker_idb = os.path.join(temp_dir, f"worker_{i}{ext}")
                try:
                    if not os.path.exists(worker_idb):
                        shutil.copy2(analyzed_idb, worker_idb)
                    worker_input = worker_idb
                except Exception as e:
                    self.logger.log(f"Failed to copy IDB for worker {i}: {e}. Using original input.", context="ORCHESTRATOR")

            cmd = f"\"{sys.executable}\" \"{ida_export_script}\" \"{worker_input}\" --output \"{worker_db}\" --parallel-worker \"{chunk_file}\""
            perf_json = os.path.join(temp_dir, f"perf_worker_{i}.json")
            cmd += f" --perf-json \"{perf_json}\" --no-perf-report --plain-log"
            worker_cmds.append(cmd)
            worker_perf_paths.append(perf_json)
            self.logger.log(f"Worker {i}: funcs={chunk_size} db={worker_db}", context="ORCHESTRATOR")

        # Run workers
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_idx = {}
            for i, cmd in enumerate(worker_cmds):
                future = executor.submit(self.run_command, cmd, True, f"WORKER_{i}")
                future_to_idx[future] = i
            results = [None] * len(worker_cmds)
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                res = future.result()
                results[idx] = res
                self.progress.worker_finished(res["ok"])
            
        duration = time.time() - worker_start
            
        if not all(r["ok"] for r in results):
            self.logger.log("Some workers failed.", context="ORCHESTRATOR")
            
        return {
            "duration": duration,
            "results": results,
            "worker_perf_paths": worker_perf_paths
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
                self.progress.finish(False, "输出路径错误")
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
        self.progress.update_stage("准备", "初始化导出上下文")

        if os.path.exists(output_db):
            self.logger.log(f"Target database already exists: {output_db}", context="ORCHESTRATOR")
            self.logger.log("Skipping export.", context="ORCHESTRATOR")
            self.progress.finish(True, "目标数据库已存在，已跳过")
            return True

        self.logger.log(f"Input  : {input_path}", context="ORCHESTRATOR")
        self.logger.log(f"Output : {output_db}", context="ORCHESTRATOR")

        _ensure_audit_db(layout["databases_dir"], self.logger)

        temp_dir = export_root or tempfile.mkdtemp(prefix="ghidra_export_")
        json_dir = None
        try:
            self.progress.update_stage("Ghidra 导出", "执行 headless 导出")
            json_dir = self._run_ghidra_headless(
                input_path,
                temp_dir,
                threads=self.workers,
                chunk_size=0
            )
            if not json_dir:
                self.progress.finish(False, "Ghidra 导出失败")
                return False
            self.progress.update_stage("导入数据库", "写入 SQLite 数据库")
            ok = import_ghidra_export(json_dir, output_db, self.logger, role=role)
            if not ok:
                self.progress.finish(False, "导入导出结果失败")
                return False
            self.progress.finish(True, "导出完成")
            return True
        except Exception as e:
            self.logger.log(f"Failed to export with ghidra: {e}", context="ERROR")
            self.progress.finish(False, f"导出异常: {e}")
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
        self.progress.update_stage("准备", "初始化导出上下文")
            
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

        base_name = os.path.splitext(input_path)[0]
        existing_idb = None
        for candidate in [
            input_path + ".i64",
            input_path + ".idb",
            base_name + ".i64",
            base_name + ".idb",
        ]:
            if os.path.exists(candidate):
                existing_idb = candidate
                break
        
        if save_idb is None:
            save_idb = os.path.join(layout["idbs_dir"], os.path.basename(input_path))

        try:
            self.progress.update_stage("主分析", "导出元数据并提取函数")
            # Step 1: Run Master
            master_res = self._run_master_analysis(existing_idb or input_path, output_db, temp_dir, save_idb, role)
            if not master_res:
                self.progress.finish(False, "主分析失败")
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
                self.progress.finish(False, "任务拆分失败")
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
            self.progress.update_stage("合并结果", "合并 worker 数据库")
            self.logger.log("Merging results", context="ORCHESTRATOR")
            merge_start = time.time()
            
            worker_dbs_paths = [w_db for _, w_db, _ in worker_files]
            self.merge_databases(output_db, worker_dbs_paths)
            
            stats['merge_time'] = time.time() - merge_start
            stats['total_time'] = time.time() - stats['start_time']
            
            self.logger.log(f"Success! Full export saved to {output_db}", context="ORCHESTRATOR")
            self.progress.finish(True, "导出完成")
            return True
        except Exception as e:
            self.logger.log(f"Failed to export: {e}", context="ERROR")
            self.progress.finish(False, f"导出异常: {e}")
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
  aida-cli export ./binary -o ./output

  # Export with Ghidra backend
  aida-cli export ./binary -o ./output --backend ghidra

  # Bulk mode - scan directory for dependencies
  aida-cli export ./target -o ./output --scan-dir ./rootfs

  # Multiple targets with wildcards
  aida-cli export ./libs/*.so -o ./output

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
            print("Error: 使用 ghidra 后端前，请先设置 GHIDRA_HOME 环境变量。")
            print("例如: export GHIDRA_HOME=/path/to/ghidra")
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
    print(f"Workspace initialized: {output_dir}")
    print(f"Binaries  : {layout['binaries_dir']}")
    print(f"Databases : {layout['databases_dir']}")
    print(f"IDBs      : {layout['idbs_dir']}")

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

        print(f"Mode: Bulk (Targets: {len(target_paths)}, Scan: {scan_dir})")
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
        print(f"Mode: Single (Targets: {len(target_paths)})")
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
