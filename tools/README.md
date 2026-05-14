# Intel(R) Multi-Buffer Crypto for IPsec Library - Tools

## Contents

- Overview
- Tools
- Usage

## Overview

This directory contains utility scripts and tools to assist with development, formatting, and maintenance tasks for the project.

## Tools

- **asm-format.py**  
  A Python script for formatting assembly (`.asm`) and include (`.inc`) files to ensure consistent style and readability across the codebase.

- **asm-cov.py**  
  Assembly code-coverage pipeline driven by Intel SDE + XED. Detects, in compiled
  assembly: unexecuted code blocks, conditional jumps that are always taken, and
  conditional jumps that are never taken. Produces an HTML report
  (`<results-dir>/cov-report/report.html`) with a per-symbol breakdown.

  Configuration is YAML or JSON. Example configs shipped here:
  - `example.yaml` / `.json` — project-neutral schema reference
  - `imb-kat.yaml` / `.json` — imb-kat test case matrix

## Usage

Each tool is typically run from the command line. For example, to format all assembly files:

```sh
python asm-format.py [options] <file1 file2...>
```

Coverage run (requires `setarch`, `sde64`, `xed64` in `PATH`):

```sh
./asm-cov.py --config ./asm-cov-configs/example.yaml \
             --results-dir ./coverage-results
```

Standalone symbol-file generation (only needs `xed64`):

```sh
./asm-cov.py --image-path ../build/lib/libIPSec_MB.so \
             --generate-symbol-file ./my-symbols.syms
```

Filter the command matrix with one or more `--select axis=value` (AND semantics):

```sh
./asm-cov.py --config ./asm-cov-configs/imb-kat.yaml \
             --results-dir ./coverage-results \
             --select arch=icx --select test_type=CTR
```

Output layout under `<results-dir>/`:

```
cov-report/
    report.html             # open this
    symbols/<sym>.html      # per-symbol detail pages
data/
    result.mix / .out / .xed / .syms / .cover
    <command-subdir>/<basename>.mix
```

Paths inside a config file (`results_dir`, `target.image_path`, `symbols.path`,
`paths.prepend_path[]`) may be absolute or relative; relative paths are
resolved against the directory of the config file.

Refer to each tool's `--help` option for detailed usage instructions and available options.

## Adding New Tools

Place new scripts or utilities in this directory and update this README with a brief description and usage instructions.

