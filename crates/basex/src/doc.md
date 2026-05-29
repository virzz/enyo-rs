# Base X

## 基础编码加解码

- base16
- base32
- base36
- base58
- base62
- base64
- base91
- base100 (emoji)

## 功能

- 编码/解码各种Base编码格式
- 支持从文件、命令行参数或标准输入读取数据
- 自动检测并递归解码

## 命令格式

### 新格式 (推荐)
```
# 基本用法
enyo basex <子命令> [输入]

# 可用子命令:
b16e, base16e: Base16 编码
b16d, base16d: Base16 解码
b32e, base32e: Base32 编码
b32d, base32d: Base32 解码
b36e, base36e: Base36 编码
b36d, base36d: Base36 解码
b58e, base58e: Base58 编码
b58d, base58d: Base58 解码
b62e, base62e: Base62 编码
b62d, base62d: Base62 解码
b64e, base64e: Base64 编码
b64d, base64d: Base64 解码
b91e, base91e: Base91 编码
b91d, base91d: Base91 解码
b100e, base100e: Base100 (emoji) 编码
b100d, base100d: Base100 (emoji) 解码

# 从文件读取
enyo basex b64e -f <文件路径>

# 标准输入
echo "测试" | enyo basex b64e
```

### 兼容模式
```
# 自动检测解码
enyo basex -a <输入>

# 默认使用Base64编码
enyo basex <输入>
```

## 使用示例

```bash
# Base64 编码
enyo basex b64e "Hello World"
# 输出: SGVsbG8gV29ybGQ=

# Base64 解码
enyo basex b64d "SGVsbG8gV29ybGQ="
# 输出: Hello World

# Base32 编码
enyo basex b32e "Hello"
# 输出: JBSWY3DP

# 从文件编码
enyo basex b64e -f /path/to/file.txt

# 自动检测并解码
enyo basex -a "SGVsbG8gV29ybGQ="
# 输出: 检测到 Base64 编码，解码后:
# Hello World
``` 