# AGENTS.md - AI 开发助手指南

> 本文档为 AI 代理（如 Cursor、GitHub Copilot 等）提供项目开发规范和上下文信息。

## 项目概述

**Enyo** - The Cyber Swiss Army Knife for terminal

一个基于 Rust 的终端工具集，提供多种实用的命令行工具，包括编码转换、哈希计算、JWT 处理、网络工具等。

## 技术栈

- **语言**: Rust 2021 Edition
- **命令行解析**: clap 4.x (派生宏风格)
- **异步运行时**: tokio
- **错误处理**: anyhow + thiserror
- **日志**: tracing + tracing-subscriber
- **序列化**: serde + serde_json

## 项目结构

```
enyo-rs/
├── Cargo.toml          # 依赖配置
├── build.rs            # 构建脚本
├── Makefile            # 常用命令
├── src/
│   ├── main.rs         # 主入口
│   ├── lib.rs          # 库入口
│   ├── bin/            # 独立二进制工具
│   │   ├── basex.rs
│   │   ├── hash.rs
│   │   ├── jwttool.rs
│   │   └── ...
│   ├── cmds/           # 子命令实现
│   │   ├── mod.rs      # 子命令注册
│   │   ├── basex/      # Base 编码工具
│   │   ├── hash/       # 哈希工具
│   │   ├── jwttool/    # JWT 工具
│   │   ├── gopher/     # Gopher 协议工具
│   │   └── ...
│   └── core/           # 核心模块
│       ├── mod.rs
│       ├── io.rs       # I/O 工具函数
│       ├── completion.rs
│       └── external.rs
└── tests/              # 集成测试
```

## 代码风格规范

### 命名规范

- **函数和变量**: `snake_case`
- **类型和特性(trait)**: `PascalCase`
- **常量**: `SCREAMING_SNAKE_CASE`
- **未使用变量**: 使用 `_` 前缀

### 格式化

- 最大行长度 100 字符
- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 进行代码质量检查
- 使用显式导入而非通配符导入

### 类型系统

- 充分利用 Rust 类型系统
- 使用枚举(enum)代替布尔标志
- 使用 `Option` 和 `Result` 处理可能缺失或错误的情况
- 为公共 API 提供适当的类型约束

## 命令行开发规范

### 子命令结构

每个子命令应独立模块实现，典型结构：

```rust
// src/cmds/xxx/mod.rs
use clap::{Args, Subcommand};
use anyhow::Result;

/// 子命令描述
#[derive(Debug, Args)]
pub struct XxxArgs {
    /// 参数描述
    #[arg(short, long)]
    pub input: String,
}

impl XxxArgs {
    pub fn run(&self) -> Result<()> {
        // 业务逻辑
        Ok(())
    }
}
```

### 参数定义要求

- 为所有参数提供详细帮助文本（使用 `///` 文档注释）
- 支持环境变量（使用 `env` 属性）
- 提供合理的默认值
- 子命令层次不超过 3 级

### 输出格式

- 错误输出到 stderr，正常输出到 stdout
- 支持 `--quiet` 静默模式（按需）
- 支持 `--verbose` 详细输出（按需）
- 使用 `indicatif` 显示进度条（按需）
- 表格输出使用 `comfy-table`

## 错误处理

### 规范

- 使用 `anyhow::Result` 作为返回类型
- 使用 `anyhow::Context` 丰富错误上下文
- 错误信息应具体且有用
- 使用 `?` 操作符进行错误传播

### 示例

```rust
use anyhow::{Context, Result};

fn process_file(path: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("无法读取文件: {}", path))?;
    // ...
    Ok(())
}
```

### 退出码规范

- `0`: 成功
- `1`: 用户错误（参数错误、输入无效等）
- `2`: 系统错误（文件不存在、权限不足等）

## I/O 处理

### 输入来源

项目支持多种输入来源，统一使用 `core::io` 模块处理：

1. 命令行参数直接传入
2. 标准输入（使用 `-` 作为文件名）
3. 文件读取

### 输出目标

- 标准输出（默认）
- 文件输出（使用 `-o` 参数）

## 测试策略

### 单元测试

- 使用 `#[test]` 标记测试函数
- 测试文件与源代码放在同一目录
- 使用 `#[cfg(test)]` 模块组织测试

### 集成测试

- 放在 `tests/` 目录
- 使用 `assert_cmd` 测试命令行行为
- 使用 `tempfile` 处理测试临时文件

### 运行测试

```bash
cargo test              # 运行所有测试
cargo test -- --ignored # 运行被忽略的测试
```

## 性能优化

- 使用 `rayon` 进行数据并行处理
- 大文件使用流式处理
- 避免不必要的内存分配
- 使用迭代器而非手动循环

## 安全实践

- 避免 `unsafe` 代码除非必要
- 使用 `cargo audit` 检查依赖漏洞
- 正确处理用户输入
- 敏感信息不记录日志

## 依赖管理

- 使用 `cargo add` 添加依赖
- 最小化依赖项
- 区分开发依赖和生产依赖
- 使用 `cargo tree` 检查依赖关系

## 构建和发布

### 开发构建

```bash
cargo build             # Debug 构建
cargo build --release   # Release 构建
```

### 生成补全脚本

项目支持生成 shell 补全脚本：

- bash: `clap_complete`
- zsh: `clap_complete`
- fish: `clap_complete`
- PowerShell: `clap_complete`

## 常用命令

```bash
cargo check             # 快速检查
cargo clippy            # 代码质量检查
cargo fmt               # 格式化代码
cargo test              # 运行测试
cargo doc --open        # 生成并打开文档
```

## 添加新子命令流程

1. 在 `src/cmds/` 下创建新目录（如 `newcmd/`）
2. 创建 `mod.rs` 定义命令参数和逻辑
3. 在 `src/cmds/mod.rs` 中注册新命令
4. 如需独立二进制，在 `src/bin/` 创建入口文件
5. 编写单元测试和文档

## 文档要求

- 使用 `///` 编写文档注释
- 包含代码示例（使用 `# Examples` 部分）
- 文档测试应能编译运行
- 保持 README.md 更新

