#!/usr/bin/env python3

"""
**********************************************************************
  Copyright(c) 2026, Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************
"""

"""
asm-cov.py - x86 assembly coverage pipeline.

This script provides a config-driven workflow to measure
instruction/branch coverage for selected assembly symbols in a target binary.

External tools used by the coverage pipeline:
- setarch: launches the emulator with ASLR disabled for stable addresses.
- sde64: executes test commands and collects MIX profiling data.
- xed64: disassembles the target image so MIX execution can be correlated
  to symbol/instruction lines.

Python/runtime dependencies:
- Python 3 standard library modules.
- Optional PyYAML when using YAML configs (JSON works without PyYAML).

Execution flow in coverage mode:
1. Parse CLI + config and build an execution matrix.
2. Materialize a symbol file (provided/generate/command mode).
3. Run each matrix command under SDE MIX collection.
4. Rebase per-run MIX files to target-image-relative addresses.
5. Merge MIX files and compute per-address execution coverage.
6. Post-process disassembly + coverage to generate warnings.
7. Build static HTML reports (index + per-symbol detail pages).

Two modes are supported:
- Coverage mode: full end-to-end pipeline above.
- Standalone symbols mode: disassemble one image and write all symbols.
"""

import argparse
import fnmatch
import html
import itertools
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

try:
    import yaml
except ImportError:
    yaml = None


# =============================================================================
# SECTION 1: Module constants and tag values
#
# This section defines constants used across the pipeline:
# - script location used for PATH augmentation
# - parse-state tags for warning report sections
# - address attribute tags used to colorize HTML output
# =============================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

MODE_UNEXEC = 0
MODE_NO_SYMS = 1
MODE_JCC_NT = 2
MODE_JCC_AT = 3

ATTR_UNEXEC = 'unexec_code'
ATTR_JCC_NT = 'jcc_nt'
ATTR_JCC_AT = 'jcc_at'


# =============================================================================
# SECTION 2: Core data structures
#
# - ExecutionCommand: one expanded matrix command
# - CovState: coverage analysis state carried across post-processing stages
# - SymbolInfo: per-symbol coverage counters used to build HTML summaries
# =============================================================================
@dataclass
class ExecutionCommand:
    """One expanded test command from the config matrix."""
    context: dict
    result_dir: str
    executable: str
    args: list
    app_basename: str


@dataclass
class CovState:
    """State carried across post-processing stages for line/jump analysis."""
    first_addr: list = field(default_factory=list)
    last_addr: list = field(default_factory=list)
    jcc_addr: list = field(default_factory=list)
    jcc_real_addr: list = field(default_factory=list)
    jcc_never_taken: list = field(default_factory=list)
    jcc_always_taken: list = field(default_factory=list)
    any_printed: bool = False


@dataclass
class SymbolInfo:
    """Coverage counters for one symbol, used to build HTML summaries."""
    found: bool = False
    slug: str = ""
    total_lines: int = 0
    unexec_lines: int = 0
    jcc_total: int = 0
    jcc_nt: int = 0
    jcc_at: int = 0

    def get_line_coverage(self):
        if self.total_lines == 0:
            return 0.0
        return float(((self.total_lines - self.unexec_lines) / self.total_lines) * 100)

    def get_branch_coverage(self):
        if self.jcc_total == 0:
            return 100.0
        return float(((self.jcc_total - self.jcc_nt) / self.jcc_total) * 100)


def extract_unique_symbols_from_disasm(disasm_text, output_file):
    """Extract SYM labels from disassembly, dedup (first-seen wins), write to file.

    Returns the number of unique symbols written. Used by both standalone
    ``--generate-symbol-file`` mode and coverage ``symbols.mode: generate``.
    """
    seen = set()
    symbols = []
    for line in disasm_text.splitlines():
        if not line.startswith("SYM "):
            continue
        sym = line.split(" ", 1)[1].strip()
        if sym.endswith(":"):
            sym = sym[:-1]
        if not sym or sym in seen:
            continue
        seen.add(sym)
        symbols.append(sym)
    with open(output_file, "w", encoding="utf-8") as f:
        for sym in symbols:
            f.write(sym + "\n")
    return len(symbols)


def data_path(rc, *parts):
    """Build a path under <results_dir>/<data_dir>/. Joins additional parts."""
    return os.path.join(
        rc["results_dir"].rstrip("/"),
        rc["outputs"]["data_dir"].rstrip("/"),
        *parts,
    )


def _apply_symbol_ignore(out_syms, patterns, quiet=False, verbose=False):
    """Filter out symbols matching any fnmatch pattern in ``patterns``.

    Rewrites ``out_syms`` in place. Matching is case-sensitive and supports
    standard glob wildcards (``*``, ``?``, ``[seq]``). When ``verbose`` is
    true, each ignored symbol is logged individually.
    """
    if not patterns:
        return
    with open(out_syms, "r", encoding="utf-8") as f:
        symbols = [line.rstrip("\n") for line in f if line.strip()]
    kept = []
    dropped = []
    for s in symbols:
        if any(fnmatch.fnmatchcase(s, p) for p in patterns):
            dropped.append(s)
        else:
            kept.append(s)
    with open(out_syms, "w", encoding="utf-8") as f:
        for sym in kept:
            f.write(sym + "\n")
    if dropped and not quiet:
        log_line("Ignored {} symbol(s) matching symbols.ignore patterns".format(len(dropped)))
        if verbose:
            for sym in dropped:
                log_line("  ignored: {}".format(sym))


def materialize_symbol_file(rc, env, out_syms=None):
    """Materialize symbol file following mode precedence.

    If out_syms is None, defaults to <results_dir>/<data_dir>/<result_syms>.
    Symbols matching any pattern in ``symbols.ignore`` (config) are filtered
    out after materialization, regardless of mode.
    """
    if out_syms is None:
        out_syms = data_path(rc, rc["outputs"]["result_syms"])

    ignore = rc["symbols"].get("ignore", [])
    quiet = rc.get("quiet", False)
    verbose = rc.get("verbose", False)

    override = rc["symbol_file_override"]
    if override:
        shutil.copy2(resolve_path(os.getcwd(), override), out_syms)
    else:
        mode = rc["symbols"]["mode"]
        if mode == "provided":
            shutil.copy2(rc["symbols"]["path"], out_syms)
        elif mode == "generate":
            target_image = rc["target_image_path"]
            disasm = disassemble_target_image(rc, target_image, env)
            extract_unique_symbols_from_disasm(disasm, out_syms)
        elif mode == "command":
            target_image = rc["target_image_path"]
            context = {"target_image": target_image}
            cmd = render_template_list(rc["symbols"]["command_template"], context)
            stdout, _ = run_cmd(cmd, env=env)
            with open(out_syms, "w", encoding="utf-8") as f:
                for line in stdout.splitlines():
                    sym = line.strip()
                    if sym:
                        f.write(sym + "\n")
        else:
            raise RuntimeError("Unsupported symbols.mode '{}'".format(mode))

    _apply_symbol_ignore(out_syms, ignore, quiet, verbose)

    with open(out_syms, "r", encoding="utf-8") as f:
        if not any(line.strip() for line in f):
            raise RuntimeError("Symbol file is empty after materialization: {}".format(out_syms))

    return out_syms


# =============================================================================
# SECTION 3: Logging, subprocess execution, and preflight checks
#
# The helper functions in this section keep command invocation consistent:
# - timestamped stage/progress logging
# - strict subprocess wrappers with clear RuntimeError messages
# - simple required-tool checks in PATH before long runs begin
# =============================================================================
def get_date_time():
    """Return log timestamp in the same format as legacy scripts."""
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def log_line(message, quiet=False, force=False):
    """Print one timestamped status line.

    Args:
        message: Human-readable status message.
        quiet: Suppress routine logs when True.
        force: Print even when quiet=True (for key milestones/errors).
    """
    if quiet and not force:
        return
    print("[{}] {}".format(get_date_time(), message))


def log_stage(stage_num, stage_total, title, quiet=False):
    """Print a consistent stage header line."""
    log_line("Stage {}/{}: {}".format(stage_num, stage_total, title), quiet=quiet)


def log_verbose_summary(rc, commands, config_path, env=None):
    """Print a one-time configuration summary when --verbose is enabled.

    Tool path resolution uses ``env['PATH']`` when ``env`` is provided so the
    summary reflects the same PATH the pipeline will actually use (including
    entries from ``paths.prepend_path`` and the script directory).
    """
    if not rc.get("verbose") or rc.get("quiet"):
        return
    sym = rc["symbols"]
    ignore = sym.get("ignore", [])
    log_line("Configuration summary:")
    log_line("  config:        {}".format(config_path))
    log_line("  results_dir:   {}".format(rc["results_dir"]))
    log_line("  parallel_jobs: {}".format(rc["behavior"]["parallel_jobs"]))
    log_line("  symbols.mode:  {}".format(sym.get("mode", "generate")))
    if ignore:
        log_line("  symbols.ignore ({}): {}".format(len(ignore), ", ".join(ignore)))
    log_line("  matrix items:  {} (after --select)".format(len(commands)))
    if rc["selectors"]:
        log_line("  selectors:     {}".format(
            ", ".join("{}={}".format(k, v) for k, v in rc["selectors"].items())))
    lookup_path = env.get("PATH") if env else None
    for tool in ("setarch", "sde64", "xed64", rc["commands"]["executable"]):
        resolved = shutil.which(tool, path=lookup_path)
        log_line("  tool {:>10}: {}".format(tool, resolved or "(not found in PATH)"))


def log_stage_timing(stage_num, stage_total, title, elapsed_s, quiet=False, verbose=False):
    """Print a stage-completion line with elapsed seconds when verbose."""
    if not verbose:
        return
    log_line("Stage {}/{} done: {} ({:.2f}s)".format(stage_num, stage_total, title, elapsed_s),
             quiet=quiet)


def run_cmd(args, cwd=None, env=None):
    """Run a command and raise RuntimeError with merged output on failure."""
    try:
        proc = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError("Command not found: {}".format(args[0])) from exc
    if proc.returncode != 0:
        out = (proc.stdout or "") + (proc.stderr or "")
        raise RuntimeError("Command failed: {}\n{}".format(" ".join(args), out))
    return proc.stdout, proc.stderr


def run_cmd_capture_rc(args, cwd=None, env=None):
    """Run a command and return CompletedProcess without enforcing return code."""
    try:
        return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError("Command not found: {}".format(args[0])) from exc


def check_required_tools_in_path(required_tools, context):
    """Perform a simple PATH preflight check for required tool names."""
    missing = [tool for tool in required_tools if shutil.which(tool) is None]
    if missing:
        missing_csv = ", ".join("'{}'".format(t) for t in missing)
        raise RuntimeError(
            "Missing required tool(s) in PATH for {}: {}. "
            "Please install them or add them to PATH."
            .format(context, missing_csv)
        )


# =============================================================================
# SECTION 4: CLI parsing and configuration/template resolution
#
# This section converts user inputs (CLI + YAML/JSON config) into a normalized
# runtime configuration dictionary:
# - validates schema/type constraints
# - resolves paths and defaults
# - renders string templates with strict key checking
# - applies CLI precedence over config where required
# =============================================================================
def parse_args():
    """Parse generic CLI arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='', help='YAML/JSON config path')
    parser.add_argument('--results-dir', default='', help='output directory')
    parser.add_argument('--symbol-file', default='', help='override symbol file path')
    parser.add_argument('--generate-symbol-file', default='',
                        help='standalone mode: generate symbols file at this path and exit')
    parser.add_argument('--image-path', default='',
                        help='image path for standalone --generate-symbol-file mode')
    parser.add_argument('-j', '--parallel-jobs', type=int, default=None,
                        help='number of parallel emulator jobs (overrides config)')
    parser.add_argument('--select', action='append', default=[],
                        help='matrix filter in key=value form (repeatable)')
    parser.add_argument('--dry-run', action='store_true', help='print expanded commands only')
    parser.add_argument('-q', '--quiet', action='store_true', help='reduce non-essential output')
    parser.add_argument('--verbose', action='store_true',
                        help='print config summary, ignored symbols, '
                             'per-job emulator commands, and per-stage timing')
    args = parser.parse_args()
    if args.generate_symbol_file:
        if not args.image_path:
            parser.error("--image-path is required when --generate-symbol-file is used")
        if (args.config or args.results_dir or args.symbol_file or args.select
                or args.dry_run or args.verbose or args.quiet
                or args.parallel_jobs is not None):
            parser.error("--generate-symbol-file is standalone; do not combine it with coverage-run options")
        return args
    if not args.config:
        parser.error("--config is required for coverage runs")
    return args


def load_config(config_path):
    """Load YAML/JSON configuration."""
    with open(config_path, "r", encoding="utf-8") as f:
        raw = f.read()

    if config_path.endswith(".json"):
        cfg = json.loads(raw)
    else:
        if yaml is None:
            raise RuntimeError("PyYAML is required for YAML config files")
        cfg = yaml.safe_load(raw)
    if not isinstance(cfg, dict):
        raise RuntimeError("Config root must be a mapping/dictionary")
    return cfg


def resolve_path(base_dir, value):
    """Resolve relative paths against a base directory.

    Args:
        base_dir: Directory to resolve relative paths from.
        value: Absolute or relative path.

    Returns:
        Absolute normalized path.
    """
    if os.path.isabs(value):
        return value
    return os.path.normpath(os.path.join(base_dir, value))


def slugify(text):
    """Create a filesystem-safe token from an arbitrary string."""
    return re.sub(r'[^A-Za-z0-9._-]+', '_', text).strip('_') or "item"


def parse_selectors(select_list):
    """Parse repeatable --select key=value arguments into a dictionary.

    If the same key appears multiple times, the last value wins.
    """
    selectors = {}
    for item in select_list:
        if "=" not in item:
            raise RuntimeError("Invalid --select '{}', expected key=value".format(item))
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise RuntimeError("Invalid --select '{}', missing key".format(item))
        selectors[key] = value
    return selectors


def render_template(value, context):
    """Render one Python format string with strict key checking."""
    if not isinstance(value, str):
        return value
    try:
        return value.format(**context)
    except KeyError as exc:
        raise RuntimeError("Missing template key '{}' in '{}'".format(exc.args[0], value)) from exc


def render_template_list(items, context):
    """Render every item in a template list with the same context."""
    return [render_template(i, context) for i in items]


def _check_known_keys(section, allowed, path):
    """Reject unknown keys in a config section to catch typos and misplacements.

    Keys starting with an underscore (for example ``_doc``) are treated as
    inline documentation and always permitted.
    """
    if not isinstance(section, dict):
        return
    unknown = sorted(k for k in section.keys()
                     if not str(k).startswith("_") and k not in allowed)
    if unknown:
        raise RuntimeError(
            "Unknown key(s) in {}: {}. Allowed: {}".format(
                path, ", ".join(unknown), ", ".join(sorted(allowed))))


def validate_config(cfg):
    """Validate schema and types for user-provided configuration.

    This function performs structure/type checks only. Runtime checks such as
    binary existence and command correctness are handled later at execution.
    """
    allowed_top = {"target", "commands", "tools", "behavior",
                   "symbols", "outputs", "paths", "results_dir"}
    _check_known_keys(cfg, allowed_top, "top level")

    required = ["target", "commands"]
    for key in required:
        if key not in cfg:
            raise RuntimeError("Config missing required section '{}'".format(key))

    tools = cfg.get("tools", {})
    if not isinstance(tools, dict):
        raise RuntimeError("tools must be a dictionary when provided")
    _check_known_keys(tools, {"emulator", "disassembler"}, "tools")
    for tool_key in ("emulator", "disassembler"):
        if tool_key in tools and not isinstance(tools[tool_key], dict):
            raise RuntimeError("tools.{} must be a dictionary".format(tool_key))
    emulator = tools.get("emulator", {})
    disassembler = tools.get("disassembler", {})
    _check_known_keys(emulator,
                      {"command_template", "mix_option_candidates",
                       "mix_enable_flag", "mix_output_flag", "top_blocks"},
                      "tools.emulator")
    _check_known_keys(disassembler, {"command_template"}, "tools.disassembler")
    if "command_template" in emulator and not isinstance(emulator["command_template"], list):
        raise RuntimeError("tools.emulator.command_template must be a list")
    if "command_template" in disassembler and not isinstance(disassembler["command_template"], list):
        raise RuntimeError("tools.disassembler.command_template must be a list")
    if "mix_option_candidates" in emulator and not isinstance(emulator["mix_option_candidates"], list):
        raise RuntimeError("tools.emulator.mix_option_candidates must be a list")

    behavior = cfg.get("behavior", {})
    if not isinstance(behavior, dict):
        raise RuntimeError("behavior must be a dictionary when provided")
    _check_known_keys(behavior,
                      {"include_script_dir_in_path", "parallel_jobs"},
                      "behavior")
    if "parallel_jobs" in behavior:
        pj = int(behavior["parallel_jobs"])
        if pj < 1:
            raise RuntimeError("behavior.parallel_jobs must be >= 1")

    _check_known_keys(cfg["target"], {"image_path", "image_match"}, "target")
    if "image_path" not in cfg["target"] or "image_match" not in cfg["target"]:
        raise RuntimeError("target.image_path and target.image_match are required")
    _check_known_keys(cfg["target"].get("image_match", {}),
                      {"type", "value"}, "target.image_match")
    if "type" not in cfg["target"]["image_match"] or "value" not in cfg["target"]["image_match"]:
        raise RuntimeError("target.image_match must include type and value")

    symbols = cfg.get("symbols", {})
    if not isinstance(symbols, dict):
        raise RuntimeError("symbols must be a dictionary when provided")
    _check_known_keys(symbols, {"mode", "path", "command_template", "ignore"}, "symbols")
    sym_mode = symbols.get("mode", "generate")
    if sym_mode not in ("provided", "generate", "command"):
        raise RuntimeError("symbols.mode must be one of: provided, generate, command")
    if sym_mode == "provided" and "path" not in symbols:
        raise RuntimeError("symbols.path is required when symbols.mode=provided")
    if sym_mode == "command" and "command_template" not in symbols:
        raise RuntimeError("symbols.command_template is required when symbols.mode=command")
    if "command_template" in symbols and not isinstance(symbols["command_template"], list):
        raise RuntimeError("symbols.command_template must be a list")
    if "ignore" in symbols:
        if not isinstance(symbols["ignore"], list):
            raise RuntimeError("symbols.ignore must be a list of strings")
        for pat in symbols["ignore"]:
            if not isinstance(pat, str):
                raise RuntimeError("symbols.ignore entries must be strings")

    commands = cfg["commands"]
    _check_known_keys(commands,
                      {"executable", "args_template", "matrix_axes",
                       "result_subdir_template", "value_maps"},
                      "commands")
    for key in ("executable", "args_template", "matrix_axes", "result_subdir_template"):
        if key not in commands:
            raise RuntimeError("commands.{} is required".format(key))
    if not isinstance(commands["args_template"], list):
        raise RuntimeError("commands.args_template must be a list")
    if not isinstance(commands["matrix_axes"], dict):
        raise RuntimeError("commands.matrix_axes must be a dictionary")

    outputs = cfg.get("outputs", {})
    if not isinstance(outputs, dict):
        raise RuntimeError("outputs must be a dictionary when provided")
    _check_known_keys(outputs,
                      {"data_dir", "result_mix", "result_out", "result_xed",
                       "result_syms", "result_cover", "report_dir"},
                      "outputs")

    paths = cfg.get("paths", {})
    if not isinstance(paths, dict):
        raise RuntimeError("paths must be a dictionary when provided")
    _check_known_keys(paths, {"prepend_path"}, "paths")

    if "results_dir" in cfg and not isinstance(cfg["results_dir"], str):
        raise RuntimeError("results_dir must be a string when provided")


def resolve_config(cfg, config_path, args):
    """Normalize config + CLI inputs into one resolved runtime config.

    This applies defaults, resolves relative paths, and enforces precedence:
    CLI overrides config where applicable (for example --parallel-jobs and
    --results-dir).
    """
    config_dir = os.path.dirname(os.path.abspath(config_path))
    tools = cfg.get("tools", {})
    emu_cfg = tools.get("emulator", {})
    dis_cfg = tools.get("disassembler", {})
    outputs = cfg.get("outputs", {})
    behavior = cfg.get("behavior", {})
    paths = cfg.get("paths", {})

    cfg_results_dir = cfg.get("results_dir", "")
    resolved_results_dir = args.results_dir
    # results_dir can come from CLI or config; CLI wins.
    if not resolved_results_dir and cfg_results_dir:
        resolved_results_dir = resolve_path(config_dir, cfg_results_dir)

    rc = {
        "config_dir": config_dir,
        "tools": {
            "emulator": {
                "command_template": emu_cfg.get(
                    "command_template",
                    ["setarch", "--addr-no-randomize", "sde64", "-{arch}"],
                ),
                "mix_option_candidates": emu_cfg.get("mix_option_candidates", [
                    ["-mix_disable_per_function_stats", "1"],
                    ["-mix_omit_per_function_stats", "1"],
                ]),
                "mix_enable_flag": emu_cfg.get("mix_enable_flag", "-mix"),
                "mix_output_flag": emu_cfg.get("mix_output_flag", "-omix"),
                "top_blocks": int(emu_cfg.get("top_blocks", 10000000)),
            },
            "disassembler": {
                "command_template": dis_cfg.get(
                    "command_template",
                    ["xed64", "-no-resync", "-s", ".text", "-I", "-i", "{target_image}"],
                ),
            },
        },
        "target": cfg["target"],
        "symbols": cfg.get("symbols", {}).copy(),
        "commands": cfg["commands"],
        "outputs": {
            "data_dir": outputs.get("data_dir", "data"),
            "result_mix": outputs.get("result_mix", "result.mix"),
            "result_out": outputs.get("result_out", "result.out"),
            "result_xed": outputs.get("result_xed", "result.xed"),
            "result_syms": outputs.get("result_syms", "result.syms"),
            "result_cover": outputs.get("result_cover", "result.cover"),
            "report_dir": outputs.get("report_dir", "cov-report"),
        },
        "behavior": {
            "include_script_dir_in_path": bool(behavior.get("include_script_dir_in_path", True)),
            "parallel_jobs": int(behavior.get("parallel_jobs", 1)),
        },
        "paths": {
            "prepend_path": [resolve_path(config_dir, p) for p in paths.get("prepend_path", [])],
        },
        "results_dir": resolved_results_dir,
        "symbol_file_override": args.symbol_file,
        "generate_symbol_file": args.generate_symbol_file,
        "selectors": parse_selectors(args.select),
        "dry_run": args.dry_run,
        "quiet": args.quiet,
        "verbose": args.verbose,
    }
    # CLI parallel setting overrides config behavior.parallel_jobs.
    if args.parallel_jobs is not None:
        if args.parallel_jobs < 1:
            raise RuntimeError("--parallel-jobs must be >= 1")
        rc["behavior"]["parallel_jobs"] = args.parallel_jobs

    # Coverage mode must always have a materialized results directory.
    if not rc["results_dir"]:
        raise RuntimeError("results directory is required: pass --results-dir or set results_dir in config")
    if rc["results_dir"] and not rc["results_dir"].endswith("/"):
        rc["results_dir"] += "/"

    target_image = resolve_path(config_dir, rc["target"]["image_path"])
    rc["target_image_path"] = target_image

    # Default symbols mode is generate when section/mode is omitted.
    if "mode" not in rc["symbols"]:
        rc["symbols"]["mode"] = "generate"
    symbols_mode = rc["symbols"]["mode"]
    if symbols_mode == "provided":
        rc["symbols"]["path"] = resolve_path(config_dir, rc["symbols"]["path"])

    return rc


# =============================================================================
# SECTION 5: Runtime environment setup and matrix command expansion
#
# These functions build process environment variables and expand configured
# matrix axes into concrete ExecutionCommand objects consumed by stage 1.
# =============================================================================
def build_environment(rc):
    """Build process environment with optional PATH augmentation.

    PATH entries are prepended so project/toolchain paths take precedence.
    """
    env = os.environ.copy()
    path_parts = []
    path_parts.extend(rc["paths"]["prepend_path"])
    if rc["behavior"]["include_script_dir_in_path"]:
        path_parts.append(SCRIPT_DIR)
    if path_parts:
        env["PATH"] = os.pathsep.join(path_parts + [env.get("PATH", "")])
    return env


def build_execution_commands(rc):
    """Expand matrix axes and render concrete test commands."""
    axes = rc["commands"]["matrix_axes"]
    selectors = rc["selectors"]
    axis_names = list(axes.keys())
    axis_values = []
    for axis in axis_names:
        vals = axes[axis]
        if not isinstance(vals, list) or len(vals) == 0:
            raise RuntimeError("commands.matrix_axes.{} must be a non-empty list".format(axis))
        axis_values.append(vals)

    for sel_key in selectors.keys():
        if sel_key not in axes:
            raise RuntimeError("--select key '{}' not in matrix_axes".format(sel_key))

    value_maps = rc["commands"].get("value_maps", {})
    runs = []
    for combo in itertools.product(*axis_values):
        ctx = dict(zip(axis_names, combo))
        skip = False
        for sel_key, sel_val in selectors.items():
            if str(ctx[sel_key]) != sel_val:
                skip = True
                break
        if skip:
            continue

        for key, value in list(ctx.items()):
            ctx["{}_slug".format(key)] = slugify(str(value))
        for map_axis, map_values in value_maps.items():
            if map_axis in ctx:
                ctx["{}_mapped".format(map_axis)] = map_values.get(str(ctx[map_axis]), slugify(str(ctx[map_axis])))

        executable = render_template(rc["commands"]["executable"], ctx)
        rendered_args = render_template_list(rc["commands"]["args_template"], ctx)
        # Flatten each rendered arg via shell-style splitting so matrix axis
        # values like "--no-avx2 --no-avx512" expand into multiple argv
        # entries (subprocess.run is invoked without a shell). Quoted tokens
        # are honored, e.g. '--name "foo bar"' -> ['--name', 'foo bar'].
        args = []
        for entry in rendered_args:
            args.extend(shlex.split(entry))
        result_dir = render_template(rc["commands"]["result_subdir_template"], ctx)
        app_basename = os.path.basename(executable)
        runs.append(ExecutionCommand(ctx, result_dir, executable, args, app_basename))

    if len(runs) == 0:
        raise RuntimeError("No commands selected after applying matrix/selectors")
    return runs


# =============================================================================
# SECTION 6: Emulator execution, MIX rebasing, and disassembly access
#
# This section covers low-level execution plumbing:
# - identify target image lines in MIX output
# - extract and apply base-address rebasing for BLOCK/XDIS addresses
# - run emulator command candidates (with BAD OPTION fallback)
# - run disassembler commands for target images
# - preserve backward-compatible symbol wrapper function names
# =============================================================================
def line_matches_target(line, matcher):
    """Return True if a line/path matches target.image_match policy."""
    mtype = matcher["type"]
    val = matcher["value"]
    if mtype == "contains":
        return val in line
    if mtype == "regex":
        return re.search(val, line) is not None
    if mtype == "basename":
        return os.path.basename(val) in line
    raise RuntimeError("Unsupported target.image_match.type '{}'".format(mtype))


def get_base_addr(mix_file, matcher):
    """Extract image path and base address for the configured target image.

    SDE MIX files contain an explicit image table delimited by
    '# EMIT_IMAGE_ADDRESSES' / '# END_IMAGE_ADDRESSES'. Each non-comment
    line inside is 'NAME  LOW_ADDR  HIGH_ADDR' (hex, no 0x prefix).
    """
    in_table = False
    with open(mix_file, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "EMIT_IMAGE_ADDRESSES" in line:
                in_table = True
                continue
            if "END_IMAGE_ADDRESSES" in line:
                break
            if not in_table:
                continue
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            if line_matches_target(parts[0], matcher):
                return parts[0], parts[1]
    return None, None


def rebase_mix(mix_file, out_file, target_image_path, base_addr_hex):
    """Rebase BLOCK/XDIS addresses in mix file by subtracting target base."""
    base_addr = int(base_addr_hex, 16)
    in_block = False
    target_basename = os.path.basename(target_image_path)
    block_re = re.compile(r"^(BLOCK:\s*[0-9]+\s+PC:\s*)([0-9a-f]+)(.*)$")
    xdis_re = re.compile(r"^XDIS ([0-9a-f]+): (.*)$")

    with open(mix_file, "r", encoding="utf-8", errors="replace") as fin, \
            open(out_file, "w", encoding="utf-8") as fout:
        for raw in fin:
            line = raw.rstrip("\n")
            if line == "":
                if in_block:
                    fout.write("\n")
                    in_block = False
                continue

            block_match = block_re.match(line)
            if block_match:
                rest = block_match.group(3)
                if target_image_path in rest or target_basename in rest:
                    in_block = True
                    addr = int(block_match.group(2), 16)
                    new_addr = addr - base_addr
                    fout.write("{}{:x}{}\n".format(block_match.group(1), new_addr, rest))
                else:
                    in_block = False
                continue

            if not in_block:
                continue

            xdis_match = xdis_re.match(line)
            if xdis_match:
                addr = int(xdis_match.group(1), 16)
                new_addr = addr - base_addr
                fout.write("XDIS {:x}: {}\n".format(new_addr, xdis_match.group(2)))


def run_emulator_for_command(rc, exec_cmd, env):
    """Run emulator for one expanded command and emit rebased .mix output."""
    out_dir = data_path(rc, exec_cmd.result_dir)
    os.makedirs(out_dir, exist_ok=True)
    tmp_mix = "{}/{}.tmp.mix".format(out_dir, exec_cmd.app_basename)
    rebased_mix = "{}/{}.mix".format(out_dir, exec_cmd.app_basename)
    cmd_candidates = build_emulator_command_candidates(rc, exec_cmd, tmp_mix)

    last_proc = None
    for cmd in cmd_candidates:
        proc = run_cmd_capture_rc(cmd, env=env)
        last_proc = proc
        if proc.returncode == 0:
            break

        output = (proc.stdout or "") + (proc.stderr or "")
        if "BAD OPTION" in output:
            continue
        raise RuntimeError("Failed: {}\n{}".format(" ".join(cmd), output))

    if last_proc is None or last_proc.returncode != 0:
        output = ""
        if last_proc:
            output = (last_proc.stdout or "") + (last_proc.stderr or "")
        raise RuntimeError("Failed running emulator\n{}".format(output))

    target_image_path, lib_base = get_base_addr(tmp_mix, rc["target"]["image_match"])
    if not lib_base:
        raise RuntimeError("Could not detect target base address in {}".format(tmp_mix))
    rebase_mix(tmp_mix, rebased_mix, target_image_path, lib_base)


def build_emulator_command_candidates(rc, exec_cmd, tmp_mix):
    """Build concrete emulator command candidates (primary + fallback knobs)."""
    app_args = [exec_cmd.executable] + exec_cmd.args
    emulator = rc["tools"]["emulator"]
    emulator_base = render_template_list(emulator["command_template"], exec_cmd.context)
    candidates = []
    for option_pair in emulator["mix_option_candidates"]:
        cmd = list(emulator_base)
        cmd.extend([
            emulator["mix_enable_flag"],
            emulator["mix_output_flag"], tmp_mix,
            "-top_blocks", str(emulator["top_blocks"]),
            option_pair[0], str(option_pair[1]),
            "--"
        ])
        cmd.extend(app_args)
        candidates.append(cmd)
    return candidates


def disassemble_target_image(rc, target_image_path, env):
    """Run configured disassembler against a target image and return text."""
    context = {"target_image": target_image_path}
    cmd = render_template_list(rc["tools"]["disassembler"]["command_template"], context)
    stdout, _ = run_cmd(cmd, env=env)
    return stdout


def disassemble_image_default(target_image_path, env):
    """Disassemble an image with default xed command (standalone symbols mode)."""
    cmd = ["xed64", "-no-resync", "-s", ".text", "-I", "-i", target_image_path]
    stdout, _ = run_cmd(cmd, env=env)
    return stdout


# =============================================================================
# SECTION 7: Coverage analysis and warning-report text generation
#
# This section transforms merged MIX data + disassembly into analysis artifacts:
# - per-address execution counts
# - symbol discovery and conditional-branch tracking
# - human-readable warning output describing uncovered code/jump behavior
# =============================================================================
def process_mix_counts(mix_file, count_file):
    """Convert block executions into cumulative address hit counts."""
    counts = defaultdict(int)
    block_re = re.compile(
        r"^BLOCK:\s+\d+\s+PC:\s+0*([0-9a-f]+)\s+ICOUNT:\s+\d+"
        r"\s+EXECUTIONS:\s+(\d+)\s+#BYTES:\s+(\d+)"
    )

    with open(mix_file, "r", encoding="utf-8", errors="replace") as mix_fh:
        for line in mix_fh:
            m = block_re.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            exec_count = int(m.group(2))
            num_bytes = int(m.group(3))
            counts[addr] += exec_count
            counts[addr + num_bytes] -= exec_count

    running = 0
    with open(count_file, "w", encoding="utf-8") as out:
        for key in sorted(counts.keys()):
            delta = counts[key]
            if delta == 0:
                continue
            running += delta
            out.write("{:08X}\t{:8d}\n".format(key, running))


def get_symbols(syms_file):
    """Load symbol list file into a lookup dictionary (symbol -> found count)."""
    syms = {}
    with open(syms_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            symbol = line.strip().replace(" ", "").replace("\t", "")
            if symbol:
                syms[symbol] = 0
    return syms


def check_symbols(xed_file, syms, cov_state):
    """Scan disassembly and populate symbol ranges + JCC tracking state.

    Side effects:
    - increments syms[symbol] when seen
    - fills cov_state.first_addr / last_addr ranges
    - tracks JCC sites and their corresponding next instruction address
    """
    sym_re = re.compile(r"^SYM ([a-zA-Z0-9_:~ `']+):$")
    xdis_re = re.compile(r"^XDIS ([0-9a-f]+): (\w+)(.*)")

    with open(xed_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        m = sym_re.match(lines[i])
        if not m or m.group(1) not in syms:
            i += 1
            continue

        syms[m.group(1)] += 1
        i += 1
        if i >= len(lines):
            break

        start_m = re.search(r"XDIS ([0-9a-f]+):", lines[i])
        if not start_m:
            raise RuntimeError("Can't find start line: {}".format(lines[i].rstrip()))
        first = int(start_m.group(1), 16)
        cov_state.first_addr.append(first)
        last_real_addr = first
        jcc_seen = None

        # Walk instructions until next symbol boundary.
        while i < len(lines):
            xl = lines[i]
            xdis_m = xdis_re.match(xl)
            if xdis_m:
                eip = int(xdis_m.group(1), 16)
                eiph = xdis_m.group(1)
                inst_type = xdis_m.group(2)
                rest = xdis_m.group(3)
                if inst_type not in ("INTERRUPT", "NOP", "WIDENOP"):
                    last_real_addr = eip
                if jcc_seen:
                    cov_state.jcc_addr.append(eip)
                    cov_state.jcc_real_addr.append(jcc_seen)
                if inst_type == "COND_BR":
                    jcc_seen = "{}: {}{}".format(eiph, inst_type, rest.rstrip("\n"))
                else:
                    jcc_seen = None
                i += 1
                continue

            sym2 = sym_re.match(xl)
            if sym2:
                if sym2.group(1) in syms:
                    syms[sym2.group(1)] += 1
                    i += 1
                    continue
                break
            i += 1

        cov_state.last_addr.append(last_real_addr)


def get_zero_range(cover_entries, cover_index, jcc_index, cov_state):
    """Find next zero-execution address interval in cover entries.

    Also updates JCC taken/not-taken classifications while advancing indexes.
    """
    while cover_index[0] < len(cover_entries):
        line, cnt = cover_entries[cover_index[0]]
        cover_index[0] += 1

        while jcc_index[0] < len(cov_state.jcc_addr) and line > cov_state.jcc_addr[jcc_index[0]]:
            cov_state.jcc_never_taken.append(cov_state.jcc_real_addr[jcc_index[0]])
            jcc_index[0] += 1

        if jcc_index[0] < len(cov_state.jcc_addr) and line == cov_state.jcc_addr[jcc_index[0]]:
            if cnt == 0:
                cov_state.jcc_always_taken.append(cov_state.jcc_real_addr[jcc_index[0]])
            jcc_index[0] += 1

        if cnt != 0:
            continue

        first_zero = line
        if cover_index[0] >= len(cover_entries):
            return 0, 0
        last_zero, next_cnt = cover_entries[cover_index[0]]
        cover_index[0] += 1
        if next_cnt == 0:
            raise RuntimeError("Invalid cover line sequence")
        while jcc_index[0] < len(cov_state.jcc_addr) and last_zero >= cov_state.jcc_addr[jcc_index[0]]:
            jcc_index[0] += 1
        return first_zero, last_zero
    return 0, 0


def post_process_xed_cover(xed_file, cover_file, output_file, syms_file, syms, cov_state):
    """Produce human-readable warning report from disassembly + execution data.

    The output file includes:
    - unexecuted instruction blocks
    - missing symbols
    - conditional branches never taken
    - conditional branches always taken
    """
    with open(cover_file, "r", encoding="utf-8", errors="replace") as f:
        cover_entries = []
        for line in f:
            m = re.match(r"^([0-9A-F]+)\s+([0-9]+)$", line.strip())
            if not m:
                raise RuntimeError("Invalid cover line format")
            cover_entries.append((int(m.group(1), 16), int(m.group(2))))

    if not cover_entries:
        with open(output_file, "w", encoding="utf-8") as out:
            out.write("[WARN] No coverage data found ({} has no entries).\n".format(cover_file))
        return

    if not cov_state.first_addr:
        with open(output_file, "w", encoding="utf-8") as out:
            out.write("[WARN] No symbols found in disassembly ranges.\n")
        return

    cover_index = [0]
    jcc_index = [0]
    cov_state.jcc_addr.append(0x7FFFFFFFFFFFFFFF)
    first_zero, last_zero = get_zero_range(cover_entries, cover_index, jcc_index, cov_state)

    output_lines = []
    idx = 0
    printed = False
    sym = ""

    sym_re = re.compile(r"^SYM")
    xdis_re = re.compile(r"XDIS ([0-9a-f]+): (\w+)(.*)")
    # Re-scan disassembly and emit only lines that fall in uncovered ranges.
    with open(xed_file, "r", encoding="utf-8", errors="replace") as xed_fh:
        for xl in xed_fh:
            if sym_re.match(xl):
                sym = xl
            m = xdis_re.search(xl)
            if not m:
                continue
            line_addr = int(m.group(1), 16)
            inst_type = m.group(2)
            text = "{}\t{}: {}{}\n".format(sym, m.group(1), inst_type, m.group(3))
            sym = ""

            while line_addr >= last_zero:
                if printed:
                    output_lines.append("\n")
                    printed = False
                first_zero, last_zero = get_zero_range(cover_entries, cover_index, jcc_index, cov_state)
                if not first_zero:
                    line_addr = None
                    break
            if line_addr is None:
                break

            while line_addr > cov_state.last_addr[idx]:
                idx += 1
                if idx >= len(cov_state.last_addr):
                    line_addr = None
                    break
            if line_addr is None:
                break

            if line_addr < first_zero:
                continue
            if line_addr < cov_state.first_addr[idx]:
                continue
            if inst_type in ("INTERRUPT", "NOP", "WIDENOP"):
                continue

            if not cov_state.any_printed:
                output_lines.append("[WARN] Unexecuted blocks of code:\n")
            output_lines.append(text)
            printed = True
            cov_state.any_printed = True

    warn_symbol = any(v == 0 for v in syms.values())
    if not cov_state.any_printed:
        output_lines.append("[OKAY] No unexecuted code found.\n\n")

    if warn_symbol:
        output_lines.append("[WARN] Symbols not found in disassembly:\n")
        for key in sorted(syms.keys()):
            if syms[key] == 0:
                output_lines.append("\t{}\n".format(key))
        output_lines.append("\n")
    else:
        output_lines.append("[OKAY] All symbols in \"{}\" were found.\n\n".format(syms_file))

    if cov_state.jcc_never_taken:
        output_lines.append("[WARN] Jcc never taken:\n")
        for item in cov_state.jcc_never_taken:
            output_lines.append("\t{}\n".format(item))
        output_lines.append("\n")
    else:
        output_lines.append("[OKAY] All Jcc instructions were taken at-least once.\n\n")

    if cov_state.jcc_always_taken:
        output_lines.append("[WARN] Jcc always taken:\n")
        for item in cov_state.jcc_always_taken:
            output_lines.append("\t{}\n".format(item))
        output_lines.append("\n")
    else:
        output_lines.append("[OKAY] No Jcc instructions were taken always.\n\n")

    if (not cov_state.any_printed and not warn_symbol and
            not cov_state.jcc_never_taken and not cov_state.jcc_always_taken):
        output_lines.append("Code cover check passed.\n")
    else:
        output_lines.append("There were warnings while checking code cover.\n")

    with open(output_file, "w", encoding="utf-8") as out_fh:
        out_fh.writelines(output_lines)


# =============================================================================
# SECTION 8: HTML report parsing/rendering helpers
#
# These helpers parse post-process output and emit static HTML:
# - classify coverage percentages into color buckets
# - generate one detail page per symbol
# - generate index summary with aggregate coverage metrics
# =============================================================================
def get_target_image_path(mix_file, matcher):
    """Extract target image path from merged mix BLOCK lines."""
    with open(mix_file, "r", encoding="utf-8", errors="replace") as mix_fh:
        for xl in mix_fh:
            m = re.search(r"IMG: ([^ ].+)  (OFFSET)", xl)
            if not m:
                continue
            path = m.group(1)
            if line_matches_target(path, matcher):
                return path
    return ""


def get_cov_class(val):
    """Map coverage percentage to CSS class name."""
    if val >= 80:
        return 'high'
    if val >= 40:
        return 'medium'
    return 'low'


def parse_results(results_file):
    """Parse post-process text report into per-address attributes + missing symbols."""
    address_attrs = {}
    missing_symbols = []
    mode = MODE_UNEXEC

    # Hex address followed by ':' at the start of the stripped line.
    addr_re = re.compile(r"^[0-9a-fA-F]+:$")

    with open(results_file, "r", encoding="utf-8", errors="replace") as out_file:
        for line in out_file:
            if "Unexecuted blocks of code" in line:
                mode = MODE_UNEXEC
                continue
            if "Symbols not found in disassembly" in line:
                mode = MODE_NO_SYMS
                continue
            if "Jcc never taken" in line:
                mode = MODE_JCC_NT
                continue
            if "Jcc always taken" in line:
                mode = MODE_JCC_AT
                continue
            if not line.strip():
                continue

            # Validate per mode so non-data lines that may appear inside a
            # section ("SYM foo:" labels inside the unexec listing) or after
            # it ("[OKAY] ...", "There were warnings ...") are ignored
            # rather than captured as data.
            line_list = line.split(" ")
            token = line_list[0].strip()
            if mode in (MODE_UNEXEC, MODE_JCC_NT, MODE_JCC_AT):
                if not addr_re.match(token):
                    continue
                # Keep the trailing ':' on the address key so it matches the
                # parts[1] token format used in generate_html_files.
                if mode == MODE_UNEXEC:
                    address_attrs.setdefault(token, []).append(ATTR_UNEXEC)
                elif mode == MODE_JCC_NT:
                    address_attrs.setdefault(token, []).append(ATTR_JCC_NT)
                else:
                    address_attrs.setdefault(token, []).append(ATTR_JCC_AT)
            elif mode == MODE_NO_SYMS:
                # Missing-symbol rows are tab-indented; non-indented lines are
                # status/section markers and must not be captured.
                if not line[0].isspace():
                    continue
                if token and token not in missing_symbols:
                    missing_symbols.append(token)
    return address_attrs, missing_symbols


def hl_line(line, color, add_break=False):
    """Wrap one line with a colored HTML span class."""
    span_open = '<span class="{}">'.format(color)
    span_close = '</span>'
    line = line.rstrip()
    if add_break:
        return "{}{}{}<br>".format(span_open, line, span_close)
    return "{}{}{}".format(span_open, line, span_close)


def generate_html_files(xed_file, symbols_file, addr_attrs, output_dir):
    """Generate one HTML detail file per symbol and return SymbolInfo map."""
    with open(xed_file, "r", encoding="utf-8", errors="replace") as xed_fh:
        xed_lines = xed_fh.readlines()
    with open(symbols_file, "r", encoding="utf-8", errors="replace") as sym_fh:
        wanted_syms = {s for s in sym_fh.read().split('\n') if s}

    # First pass: group xed lines into one record per wanted symbol.
    # Each record is (symbol_name, original_sym_line, list_of_xdis_body_lines).
    groups = []
    current = None  # (name, header_line, body_list) or None
    for line in xed_lines:
        if line.startswith("SYM "):
            name = line.split(' ')[1].replace(":", "").strip()
            current = (name, line, []) if name in wanted_syms else None
            continue
        if line == '\n' and current is not None:
            groups.append(current)
            current = None
            continue
        if current is not None and 'XDIS' in line:
            current[2].append(line)
    if current is not None:
        groups.append(current)

    # Second pass: write one HTML file per symbol inside its own `with` block.
    os.makedirs(output_dir, exist_ok=True)
    symbols = {}
    used_slugs = {}
    for name, header_line, body_lines in groups:
        # Symbol names may contain characters that are illegal in filenames
        # (e.g. '/', ':', '<', '>'); slugify and disambiguate collisions.
        base_slug = slugify(name)
        slug = base_slug
        suffix = 2
        while slug in used_slugs and used_slugs[slug] != name:
            slug = "{}_{}".format(base_slug, suffix)
            suffix += 1
        used_slugs[slug] = name
        info = SymbolInfo(found=True, slug=slug)
        symbols[name] = info
        out_path = os.path.join(output_dir, "{}.html".format(slug))
        with open(out_path, 'w', encoding="utf-8") as html_file:
            html_file.write(HTML_START)
            html_file.write("<h1>Symbol Coverage</h1>\n")
            html_file.write('<h2>{}</h2>\n'.format(html.escape(name)))
            html_file.write(
                "<p class='legend'>"
                "<span class='tag unexec'>Unexecuted</span>"
                "<span class='tag jat'>Jump always taken</span>"
                "<span class='tag jnt'>Jump never taken</span>"
                "</p>\n"
            )
            html_file.write(DETAIL_BLOCK_START)
            for body_line in body_lines:
                parts = body_line.split()
                if len(parts) < 6:
                    continue
                address = parts[1]
                jcc = False
                info.total_lines += 1
                if parts[2] == 'COND_BR':
                    info.jcc_total += 1
                    jcc = True

                dis_line = html.escape(' '.join(parts[5:]))
                if address in addr_attrs:
                    if ATTR_JCC_NT in addr_attrs[address]:
                        info.jcc_nt += 1
                        dis_line = hl_line(dis_line, 'jnt')
                        html_file.write(hl_line("Jump never taken:", 'note', add_break=True))
                    elif ATTR_JCC_AT in addr_attrs[address]:
                        info.jcc_at += 1
                        dis_line = hl_line(dis_line, 'jat')
                        html_file.write(hl_line("Jump always taken:", 'note', add_break=True))
                    elif ATTR_UNEXEC in addr_attrs[address]:
                        info.unexec_lines += 1
                        if jcc:
                            info.jcc_nt += 1
                        dis_line = hl_line(dis_line, 'unexec')
                html_file.write('0x' + address + '  ' + dis_line + '\n')
            html_file.write(DETAIL_BLOCK_END)
            html_file.write(HTML_END)
    return symbols


def generate_cov_report(out_file, xed_file, sym_file, output_dir, report_dir_name, target_image_path=None):
    """Generate coverage HTML report directory (index + per-symbol pages)."""
    if not output_dir.endswith("/"):
        output_dir += '/'
    cov_dir = output_dir + report_dir_name.rstrip("/") + "/"
    os.makedirs(cov_dir, exist_ok=True)

    addr_attrs, missing_symbols = parse_results(out_file)
    symbols_subdir = "symbols"
    symbols = generate_html_files(xed_file, sym_file, addr_attrs, os.path.join(cov_dir, symbols_subdir))

    with open(cov_dir + 'report.html', 'w', encoding="utf-8") as index_file:
        index_file.write(HTML_START)
        report_date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        image_name = "UNKNOWN"
        image_title_attr = ""
        if target_image_path:
            image_name = os.path.basename(target_image_path.rstrip("/")) or target_image_path
            image_title_attr = " title='{}'".format(html.escape(target_image_path, quote=True))
        index_file.write("<h1>Coverage Report</h1>\n")
        index_file.write("<p class='subtitle'>Generated: {}</p>\n".format(report_date))
        index_file.write(
            "<p class='subtitle'>Target image: <span class='inline-code'{}>{}</span></p>\n".format(
                image_title_attr, html.escape(image_name)
            )
        )

        total_lines = exec_lines = jcc_total = jcc_taken = symbols_found = 0
        symbol_rows = []

        for key in symbols.keys():
            sym = symbols[key]
            if not sym.found:
                continue
            _total_lines = sym.total_lines
            _unexec_lines = sym.unexec_lines
            _exec_lines = _total_lines - _unexec_lines
            _jcc_total = sym.jcc_total
            _jcc_nt = sym.jcc_nt
            _jcc_taken = _jcc_total - _jcc_nt
            _line_cov = sym.get_line_coverage()
            _branch_cov = sym.get_branch_coverage()

            total_lines += _total_lines
            exec_lines += _exec_lines
            jcc_total += _jcc_total
            jcc_taken += _jcc_taken
            symbols_found += 1

            symbol_rows.append(
                "<tr>"
                "<td><a href='{sd}/{slug}.html'>{name}</a></td>"
                "<td class='num {1}'>{2}/{3}</td><td class='num {1}'>{4:.2f}%</td>"
                "<td class='num {5}'>{6}/{7}</td><td class='num {5}'>{8:.2f}%</td>"
                "</tr>\n".format(
                    key, get_cov_class(_line_cov), _exec_lines, _total_lines, _line_cov,
                    get_cov_class(_branch_cov), _jcc_taken, _jcc_total, _branch_cov,
                    sd=symbols_subdir,
                    slug=html.escape(sym.slug, quote=True),
                    name=html.escape(key),
                )
            )

        symbols_total = symbols_found + len(missing_symbols)
        symbols_perc = (symbols_found / symbols_total) * 100 if symbols_total else 0.0
        lines_perc = (exec_lines / total_lines) * 100 if total_lines else 0.0
        jcc_perc = (jcc_taken / jcc_total) * 100 if jcc_total else 100.0

        summary_cards = (
            "<h2>Summary</h2>"
            "<div class='summary-grid'>"
            "<div class='metric-card'><div class='metric-label'>Symbol coverage</div>"
            "<div class='metric-value {0}'>{1}/{2} ({3:.2f}%)</div></div>"
            "<div class='metric-card'><div class='metric-label'>Line coverage</div>"
            "<div class='metric-value {4}'>{5}/{6} ({7:.2f}%)</div></div>"
            "<div class='metric-card'><div class='metric-label'>Branch coverage</div>"
            "<div class='metric-value {8}'>{9}/{10} ({11:.2f}%)</div></div>"
            "</div>\n".format(
                get_cov_class(symbols_perc), symbols_found, symbols_total, symbols_perc,
                get_cov_class(lines_perc), exec_lines, total_lines, lines_perc,
                get_cov_class(jcc_perc), jcc_taken, jcc_total, jcc_perc
            )
        )
        index_file.write(summary_cards)

        index_file.write("<h2>Symbol Data</h2>\n")
        index_file.write("<div class='table-wrap'><table>")
        index_file.write(
            "<thead><tr><th>Symbol</th><th>Executed lines</th><th>Line %</th>"
            "<th>Taken branches</th><th>Branch %</th></tr></thead><tbody>"
        )
        if symbol_rows:
            for row in symbol_rows:
                index_file.write(row)
        else:
            index_file.write("<tr><td colspan='5'>No symbols were generated in this report.</td></tr>\n")
        index_file.write("</tbody></table></div>\n")

        index_file.write("<h2>Symbols Not Found In Disassembly</h2><ul>")
        if missing_symbols:
            for symbol in missing_symbols:
                index_file.write("<li>{}</li>".format(symbol))
        else:
            index_file.write("<li>NONE</li>")
        index_file.write("</ul>\n")
        index_file.write(HTML_END)

    return {
        "symbols_found": symbols_found,
        "symbols_total": symbols_total,
        "symbols_perc": symbols_perc,
        "exec_lines": exec_lines,
        "total_lines": total_lines,
        "lines_perc": lines_perc,
        "jcc_taken": jcc_taken,
        "jcc_total": jcc_total,
        "jcc_perc": jcc_perc,
    }


# =============================================================================
# SECTION 9: Pipeline orchestration and entrypoint
#
# run_postprocess() executes stage-3 processing and returns detected target
# image metadata for reporting. main() coordinates both modes and all stages:
# - standalone symbols mode (quick utility path)
# - full coverage pipeline (stages 1..4)
# =============================================================================
def run_postprocess(rc, env):
    """Run post-processing chain from merged mix to final report inputs."""
    syms_file = data_path(rc, rc["outputs"]["result_syms"])
    combined_mix_file = data_path(rc, rc["outputs"]["result_mix"])
    cover_file = data_path(rc, rc["outputs"]["result_cover"])
    output_file = data_path(rc, rc["outputs"]["result_out"])
    xed_out_file = data_path(rc, rc["outputs"]["result_xed"])

    target_image = get_target_image_path(combined_mix_file, rc["target"]["image_match"])
    if not target_image:
        raise RuntimeError("Could not detect target image path from {}".format(combined_mix_file))

    disasm_text = disassemble_target_image(rc, target_image, env)
    with open(xed_out_file, "w", encoding="utf-8") as xed_fh:
        xed_fh.write(disasm_text)

    syms = get_symbols(syms_file)
    cov_state = CovState()
    check_symbols(xed_out_file, syms, cov_state)
    process_mix_counts(combined_mix_file, cover_file)
    post_process_xed_cover(xed_out_file, cover_file, output_file, syms_file, syms, cov_state)
    return target_image


# -----------------------------------------------------------------------------
# main() flow
#
# Two modes are dispatched by the CLI arguments:
#
# 1. Standalone symbols mode (--generate-symbol-file):
#    - Disassemble the given image with xed and write every unique SYM label
#      to the requested output file, then exit. No config or emulator runs.
#
# 2. Coverage mode (--config required):
#    a. Load + validate config, then merge with CLI to produce the resolved
#       runtime config `rc` and process environment `env`.
#    b. Preflight: required tools must be in PATH; results dir is created.
#    c. Expand the matrix axes into concrete ExecutionCommand objects.
#    d. If --dry-run: print expanded emulator command candidates and exit.
#    e. Materialize the symbol file (provided / generated / command mode).
#    f. Stage 1: run emulator jobs (optionally in parallel) to produce one
#       rebased .mix file per command.
#    g. Stage 2: concatenate all per-command .mix files into result.mix.
#    h. Stage 3: disassemble target image, scan symbols/branches, compute
#       per-address execution counts, and emit the text warning report.
#    i. Stage 4: render the HTML report (index + one page per symbol).
# -----------------------------------------------------------------------------
def main():
    """Entrypoint for standalone symbols mode and full coverage mode."""
    args = parse_args()
    if args.generate_symbol_file:
        # Standalone utility mode: disassemble image, dump full symbol list, exit.
        image_path = resolve_path(os.getcwd(), args.image_path)
        out_syms = resolve_path(os.getcwd(), args.generate_symbol_file)
        out_dir = os.path.dirname(out_syms)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        env = os.environ.copy()
        check_required_tools_in_path(["xed64"], "standalone symbol generation")
        disasm = disassemble_image_default(image_path, env)
        count = extract_unique_symbols_from_disasm(disasm, out_syms)
        print("Generated symbols file: {} ({} symbols)".format(out_syms, count))
        return

    # Coverage mode: load config, execute all stages, and write outputs/report.
    cfg = load_config(args.config)
    validate_config(cfg)
    rc = resolve_config(cfg, args.config, args)
    env = build_environment(rc)
    check_required_tools_in_path(["setarch", "sde64", "xed64"], "coverage run")

    os.makedirs(rc["results_dir"], exist_ok=True)
    os.makedirs(data_path(rc), exist_ok=True)

    commands = build_execution_commands(rc)
    log_verbose_summary(rc, commands, args.config, env=env)
    # Dry run prints exact emulator command candidates per matrix item.
    if rc["dry_run"]:
        if rc["quiet"]:
            return
        for item in commands:
            out_dir = data_path(rc, item.result_dir)
            tmp_mix = "{}/{}.tmp.mix".format(out_dir, item.app_basename)
            for cmd in build_emulator_command_candidates(rc, item, tmp_mix):
                print("{} -> {}".format(shlex.join(cmd), item.result_dir))
        return

    materialize_symbol_file(rc, env)

    log_stage(1, 4, "Generating MIX files ({} job(s), parallel={})".format(
        len(commands), rc["behavior"]["parallel_jobs"]), quiet=rc["quiet"])
    if rc["verbose"] and not rc["quiet"]:
        for item in commands:
            out_dir = data_path(rc, item.result_dir)
            tmp_mix = "{}/{}.tmp.mix".format(out_dir, item.app_basename)
            for cmd in build_emulator_command_candidates(rc, item, tmp_mix):
                log_line("  cmd[{}]: {}".format(item.result_dir, shlex.join(cmd)))
    # Stage 1: run emulator jobs in parallel (or sequentially when parallel_jobs=1).
    parallel_jobs = rc["behavior"]["parallel_jobs"]
    errors = []
    completed = 0
    total = len(commands)
    stage_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=parallel_jobs) as executor:
        futures = {
            executor.submit(run_emulator_for_command, rc, item, env): item
            for item in commands
        }
        for future in as_completed(futures):
            item = futures[future]
            try:
                future.result()
                completed += 1
                log_line("  [{}/{}] {}".format(completed, total, item.result_dir), quiet=rc["quiet"])
            except Exception as exc:
                errors.append("result_dir={}: {}".format(item.result_dir, exc))
    if errors:
        raise RuntimeError("One or more emulator jobs failed:\n{}".format("\n".join(errors)))
    log_stage_timing(1, 4, "Generating MIX files",
                     time.perf_counter() - stage_start, quiet=rc["quiet"], verbose=rc["verbose"])

    log_stage(2, 4, "Combining MIX files", quiet=rc["quiet"])
    stage_start = time.perf_counter()
    # Stage 2: merge all rebased per-command mix outputs.
    combined_mix_path = data_path(rc, rc["outputs"]["result_mix"])
    with open(combined_mix_path, "w", encoding="utf-8") as combined_mix_file:
        for item in commands:
            mix_path = data_path(rc, item.result_dir, "{}.mix".format(item.app_basename))
            with open(mix_path, 'r', encoding="utf-8", errors="replace") as mix_file:
                combined_mix_file.write(mix_file.read())
    log_stage_timing(2, 4, "Combining MIX files",
                     time.perf_counter() - stage_start, quiet=rc["quiet"], verbose=rc["verbose"])

    log_stage(3, 4, "Post-processing coverage results", quiet=rc["quiet"])
    stage_start = time.perf_counter()
    # Stage 3: create text diagnostics and xed artifacts.
    target_image = run_postprocess(rc, env)
    log_stage_timing(3, 4, "Post-processing coverage results",
                     time.perf_counter() - stage_start, quiet=rc["quiet"], verbose=rc["verbose"])

    log_stage(4, 4, "Creating coverage report", quiet=rc["quiet"])
    stage_start = time.perf_counter()
    # Stage 4: generate HTML report from produced artifacts.
    totals = generate_cov_report(
        data_path(rc, rc["outputs"]["result_out"]),
        data_path(rc, rc["outputs"]["result_xed"]),
        data_path(rc, rc["outputs"]["result_syms"]),
        rc["results_dir"],
        rc["outputs"]["report_dir"],
        target_image,
    )
    log_stage_timing(4, 4, "Creating coverage report",
                     time.perf_counter() - stage_start, quiet=rc["quiet"], verbose=rc["verbose"])
    log_line("Coverage run complete. Report: {}/{}".format(
        rc["results_dir"].rstrip("/"), rc["outputs"]["report_dir"]), quiet=rc["quiet"])
    if not rc["quiet"] and totals:
        log_line("Coverage summary:")
        log_line("  Symbol coverage: {}/{} ({:.2f}%)".format(
            totals["symbols_found"], totals["symbols_total"], totals["symbols_perc"]))
        log_line("  Line coverage:   {}/{} ({:.2f}%)".format(
            totals["exec_lines"], totals["total_lines"], totals["lines_perc"]))
        log_line("  Branch coverage: {}/{} ({:.2f}%)".format(
            totals["jcc_taken"], totals["jcc_total"], totals["jcc_perc"]))


# =============================================================================
# SECTION 10: HTML template constants
# =============================================================================
HTML_START = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Coverage Report</title>
<style>
:root {
  --bg: #f5f7fa;
  --text: #1f2937;
  --muted: #475569;
  --panel: #ffffff;
  --panel-2: #f8fafc;
  --border: #d0d7de;
  --table-border: #8a98ac;
  --th-bg: #eef2f7;
  --row-alt: #f9fbfe;
  --row-hover: #eef6ff;
  --link: #0b5ed7;
  --cov-unexec-bg: #fde2e1;
  --cov-unexec-fg: #1f2937;
  --cov-jat-bg: #ffe5cc;
  --cov-jat-fg: #1f2937;
  --cov-jnt-bg: #fff4bf;
  --cov-jnt-fg: #1f2937;
  --cov-high-bg: #d7f0df;
  --cov-high-fg: #1f2937;
  --cov-medium-bg: #fff2c2;
  --cov-medium-fg: #1f2937;
  --cov-low-bg: #f9d3d9;
  --cov-low-fg: #1f2937;
  --cov-note-bg: #d8ecff;
  --cov-note-fg: #1f2937;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101418;
    --text: #e5e7eb;
    --muted: #b6c1d0;
    --panel: #151b22;
    --panel-2: #0f141a;
    --border: #2f3742;
    --table-border: #7d8ba0;
    --th-bg: #1b232d;
    --row-alt: #171f28;
    --row-hover: #1d2a3a;
    --link: #7fb4ff;
    --cov-unexec-bg: #5b2731;
    --cov-unexec-fg: #f9d6dd;
    --cov-jat-bg: #5a341a;
    --cov-jat-fg: #ffe2c4;
    --cov-jnt-bg: #58480c;
    --cov-jnt-fg: #fff2b8;
    --cov-high-bg: #1f4a2f;
    --cov-high-fg: #d4f5de;
    --cov-medium-bg: #5c4a12;
    --cov-medium-fg: #fff0b6;
    --cov-low-bg: #562433;
    --cov-low-fg: #ffd8e1;
    --cov-note-bg: #173d63;
    --cov-note-fg: #d7ebff;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
.container {
  max-width: 1280px;
  margin: 0 auto;
  padding: 24px 28px 32px;
}
h1 { margin: 0 0 4px; }
h2 { margin: 26px 0 10px; }
.subtitle {
  margin: 0 0 14px;
  color: var(--muted);
  font-size: 0.95rem;
}
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 12px;
  margin: 8px 0 16px;
}
.metric-card {
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
  padding: 12px 14px;
}
.metric-label {
  font-size: 0.82rem;
  color: var(--muted);
  margin-bottom: 4px;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}
.metric-value {
  font-size: 1.05rem;
  font-weight: 600;
  display: inline-block;
  padding: 2px 6px;
  border-radius: 6px;
}
.table-wrap { overflow-x: auto; }
table {
  width: 100%;
  border-collapse: collapse;
  border: 2px solid var(--table-border);
  margin: 8px 0 20px;
  background: var(--panel);
}
th, td {
  border: 1px solid var(--table-border);
  padding: 8px 10px;
}
th {
  background: var(--th-bg);
  text-align: left;
  position: sticky;
  top: 0;
  z-index: 1;
}
tbody tr:nth-child(even) { background: var(--row-alt); }
tbody tr:hover { background: var(--row-hover); }
td.num {
  text-align: right;
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
}
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }
.inline-code {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--panel-2);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 0.92em;
}
ul { margin-top: 0; }
.tag {
  display: inline-block;
  margin-right: 8px;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid var(--border);
  font-size: 0.85rem;
}
.legend { margin: 4px 0 12px; }
.asm-block {
  margin: 0;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel-2);
  overflow-x: auto;
  line-height: 1.4;
  font-size: 0.9rem;
}
.unexec { background-color: var(--cov-unexec-bg); color: var(--cov-unexec-fg); }
.jat    { background-color: var(--cov-jat-bg); color: var(--cov-jat-fg); }
.jnt    { background-color: var(--cov-jnt-bg); color: var(--cov-jnt-fg); }
.high   { background-color: var(--cov-high-bg); color: var(--cov-high-fg); }
.medium { background-color: var(--cov-medium-bg); color: var(--cov-medium-fg); }
.low    { background-color: var(--cov-low-bg); color: var(--cov-low-fg); }
.note   { background-color: var(--cov-note-bg); color: var(--cov-note-fg); }
</style>
</head>
<body>
<main class="container">
"""

HTML_END = "</main></body></html>"
DETAIL_BLOCK_START = "<pre class='asm-block'><code>"
DETAIL_BLOCK_END = "</code></pre>"


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print("[{}] ERROR: {}".format(get_date_time(), exc), file=sys.stderr)
        raise SystemExit(1)
