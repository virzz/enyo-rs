# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Enyo** - The Cyber Swiss Army Knife for Terminal. A Rust CLI toolkit for security/encoding utilities (base encoding, hashing, JWT, gopher SSRF, git hack, etc.).

## Common Commands

```bash
cargo check                  # Quick check (fastest feedback)
cargo build                  # Debug build
cargo build --release        # Release build
cargo test                   # Run all tests
cargo test <module>::tests   # Run tests for a specific module (e.g. cargo test hash::tests)
cargo test -- --ignored      # Run ignored tests
cargo clippy                 # Lint
cargo fmt                    # Format
cargo doc --open             # Generate and open docs
make local-install           # Install locally
```

## Architecture

### Entry Flow

`main.rs` → `App::try_parse()` → `app.run()` → tracing init → `Command::invoke()` → each command's `Action::execute()`

### Core Trait

All commands implement `Action` trait (`src/core/action.rs`):
```rust
#[async_trait]
pub trait Action: Send + Sync {
    async fn execute(&self) -> anyhow::Result<()>;
}
```

### Auto-Generated Command Registry

`build.rs` scans `src/cmds/*/mod.rs` for `pub struct Cmd` and parses metadata comments (`//! @alias:`, `//! @about:`) to auto-generate `src/cmds/mod.rs`. **Do not manually edit `src/cmds/mod.rs`** — it is overwritten on every build.

### Adding a New Subcommand

1. Create `src/cmds/<name>/mod.rs` with `pub struct Cmd` (clap `Parser` derive)
2. Add `//! @alias:` and `//! @about:` doc comments at the top of the file
3. Implement `Action for Cmd`
4. The build script auto-registers it — no manual registration needed
5. Directory names with special chars (e.g. `gh-mozhu`) are skipped by the build script
6. Write corresponding unit tests; test artifacts must be cleaned up.
7. Check `cargo check;cargo clippy`, then fix it

### I/O System (`src/core/io.rs`)

Unified input handling with auto-detection: stdin (default), file (if path exists), or direct argument. Use `Input` struct for flexible input sources. Output goes to stdout by default or file via `-o`.

### Project Structure

- `src/lib.rs` — `App` struct with clap Parser, logging init, command dispatch
- `src/core/` — `Action` trait, I/O utilities, external command delegation
- `src/cmds/` — Each subdirectory is an independent command module (18 commands)
- `build.rs` — Auto-generates command enum and dispatch from module metadata

## Tech Stack

- **语言**: Rust 2021 Edition
- **命令行解析**: clap 4.x (派生宏风格)
- **异步运行时**: tokio
- **错误处理**: anyhow
- **日志**: tracing + tracing-subscriber
- **序列化**: serde + serde_json

## Code Conventions

### 命名规范

- 函数和变量: `snake_case`，类型和 trait: `PascalCase`，常量: `SCREAMING_SNAKE_CASE`
- 未使用变量使用 `_` 前缀
- 使用显式导入而非通配符导入

### 格式化

- 最大行长度 100 字符，使用 `cargo fmt` + `cargo clippy`
- 使用枚举(enum)代替布尔标志
- 使用 `Option` 和 `Result` 处理可能缺失或错误的情况

### CLI 参数规范

- 为所有参数提供 `///` 文档注释作为帮助文本
- 适当使用 `env` 属性支持环境变量，提供合理默认值
- 子命令层次不超过 3 级

### 输出规范

- 错误输出到 stderr，正常输出到 stdout
- 进度条使用 `indicatif`，表格输出使用 `comfy-table`
- 日志使用 `tracing`（不用 `println!` 调试）

### 错误处理

- 使用 `anyhow::Result` 返回类型，`anyhow::Context` 丰富错误上下文
- 使用 `?` 操作符传播错误
- 退出码: 0 = 成功, 1 = 用户错误, 2 = 系统错误

### 测试

- 内联测试使用 `#[cfg(test)]` 模块，异步测试用 `#[tokio::test]`
- 集成测试放在 `tests/` 目录，使用 `tempfile` 处理临时文件
- 测试产物必须清理

### 性能

- 使用 `rayon` 进行数据并行处理
- 大文件使用流式处理，使用迭代器而非手动循环

## Build Dependencies Note

- `OPENSSL_DIR=/opt/homebrew/` is set in Makefile for macOS builds
- `rusqlite` uses `sqlcipher` feature (requires system libsqlcipher)
- Cross-compilation targets defined in Makefile for Darwin/Linux/Windows × x86_64/aarch64
