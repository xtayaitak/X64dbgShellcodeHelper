# X64dbg ShellCode Helper

[English](#english) | [中文](#中文)

---

## 中文

### 简介

一个专为 x64dbg 调试器设计的插件，用于简化 shellcode 分析流程。通过将 shellcode 注册为虚拟模块，解决了 shellcode 地址随机化导致的注释丢失问题。

### 核心问题

在逆向分析过程中，shellcode 通常存在以下问题：
- **地址不固定**：shellcode 每次运行时的内存地址都不同
- **注释丢失**：x64dbg 中手动添加的注释和标签会因地址变化而失效
- **重复劳动**：每次分析都需要重新理解和标注代码

### 解决方案

通过 shellcode 特征码识别技术：
1. **特征码匹配**：使用预定义的字节特征快速定位 shellcode
2. **虚拟模块注册**：将识别到的 shellcode 注册为 x64dbg 虚拟模块
3. **注释持久化**：虚拟模块中的注释会被保存，下次加载自动恢复

### 主要功能

#### 1. Load ShellCode as Virtual Module（加载 ShellCode 为虚拟模块）
- 根据配置文件中的特征码扫描内存
- 自动识别并定位 shellcode
- 使用 `virtualmod` 命令注册为虚拟模块
- 支持批量加载多个 shellcode

#### 2. Enum ShellCode（枚举 ShellCode）
- 显示配置文件中的所有特征码
- 列出在内存中匹配到的 shellcode
- 显示每个 shellcode 的名称和地址

#### 3. Unload All Virtual Modules（卸载所有虚拟模块）
- 自动检测所有虚拟模块（`virtual:\\` 前缀）
- 批量卸载已注册的虚拟模块
- 显示卸载统计信息

### 配置文件

**位置**：`x64dbg目录\ShellcodeComment\进程名.exe.shellcode_features`

**格式**：
```
ShellCode大小(16进制8位)|名称|特征偏移(16进制8位)|特征码字节(连续16进制)
```

**示例**：
```
00014000|b1000shellcode|0000F5AD|83EC205356578BD933FF8D4C2410897C2418897C240C
00010000|MessageBoxShellcode|00000010|558BEC83EC40
```

### 使用流程

1. **配置特征码**
   - 在调试过程中找到 shellcode
   - 选择一段稳定的字节序列作为特征码（建议 10-20 字节）
   - 记录 shellcode 大小、特征偏移和特征字节
   - 写入配置文件

2. **加载虚拟模块**
   - 启动 x64dbg 并附加目标进程
   - 点击 `Plugins -> ShellCodeHelper -> Load ShellCode as Virtual Module`
   - 插件自动识别并注册虚拟模块

3. **分析 Shellcode**
   - 在模块列表中可以看到注册的虚拟模块
   - 像调试普通模块一样分析 shellcode
   - 添加的注释和断点会自动保存

4. **下次分析**
   - 重新加载虚拟模块即可恢复所有注释
   - 无需重新标注代码

### 工作原理

1. **内存扫描**：扫描 `MEM_PRIVATE` + `PAGE_EXECUTE_READWRITE` 属性的内存块
2. **大小过滤**：只检查配置文件中定义大小的内存块（性能优化）
3. **特征匹配**：读取指定偏移处的字节，与特征码比对
4. **模块注册**：执行 `virtualmod <名称>,<地址>` 将 shellcode 注册为虚拟模块

### 编译

```bash
cd build
cmake ..
cmake --build . --config Release
```

输出：`build\Release\ShellCodeHelper.dp32`（32位）或 `ShellCodeHelper.dp64`（64位）

### 安装

复制 `ShellCodeHelper.dp32` 到 `x64dbg\x32\plugins\`  
或复制 `ShellCodeHelper.dp64` 到 `x64dbg\x64\plugins\`

---

## English

### Introduction

A plugin designed for x64dbg debugger to simplify shellcode analysis workflow. By registering shellcode as virtual modules, it solves the problem of losing comments due to shellcode address randomization.

### Core Problem

During reverse engineering, shellcode typically has the following issues:
- **Unfixed Address**: Shellcode loads at different memory addresses each time
- **Lost Comments**: Manual comments and labels in x64dbg become invalid when addresses change
- **Repetitive Work**: Requires re-understanding and re-annotating code for each analysis

### Solution

Through shellcode signature recognition technology:
1. **Signature Matching**: Quickly locate shellcode using predefined byte patterns
2. **Virtual Module Registration**: Register identified shellcode as x64dbg virtual modules
3. **Persistent Comments**: Comments in virtual modules are saved and automatically restored on next load

### Main Features

#### 1. Load ShellCode as Virtual Module
- Scan memory based on signatures in configuration file
- Automatically identify and locate shellcode
- Register as virtual module using `virtualmod` command
- Support batch loading of multiple shellcodes

#### 2. Enum ShellCode
- Display all signatures in configuration file
- List shellcode matched in memory
- Show name and address of each shellcode

#### 3. Unload All Virtual Modules
- Automatically detect all virtual modules (`virtual:\\` prefix)
- Batch unload registered virtual modules
- Display unload statistics

### Configuration File

**Location**: `x64dbg_directory\ShellcodeComment\process_name.exe.shellcode_features`

**Format**:
```
ShellCodeSize(Hex8)|Name|FeatureOffset(Hex8)|FeatureBytes(ContinuousHex)
```

**Example**:
```
00014000|b1000shellcode|0000F5AD|83EC205356578BD933FF8D4C2410897C2418897C240C
00010000|MessageBoxShellcode|00000010|558BEC83EC40
```

### Usage Workflow

1. **Configure Signatures**
   - Find shellcode during debugging
   - Select a stable byte sequence as signature (10-20 bytes recommended)
   - Record shellcode size, feature offset, and feature bytes
   - Write to configuration file

2. **Load Virtual Modules**
   - Start x64dbg and attach to target process
   - Click `Plugins -> ShellCodeHelper -> Load ShellCode as Virtual Module`
   - Plugin automatically identifies and registers virtual modules

3. **Analyze Shellcode**
   - See registered virtual modules in module list
   - Analyze shellcode like debugging normal modules
   - Added comments and breakpoints are automatically saved

4. **Next Analysis**
   - Reload virtual modules to restore all comments
   - No need to re-annotate code

### How It Works

1. **Memory Scanning**: Scan memory blocks with `MEM_PRIVATE` + `PAGE_EXECUTE_READWRITE` attributes
2. **Size Filtering**: Only check memory blocks with sizes defined in configuration (performance optimization)
3. **Signature Matching**: Read bytes at specified offset and compare with signatures
4. **Module Registration**: Execute `virtualmod <name>,<address>` to register shellcode as virtual module

### Build

```bash
cd build
cmake ..
cmake --build . --config Release
```

Output: `build\Release\ShellCodeHelper.dp32` (32-bit) or `ShellCodeHelper.dp64` (64-bit)

### Installation

Copy `ShellCodeHelper.dp32` to `x64dbg\x32\plugins\`  
or copy `ShellCodeHelper.dp64` to `x64dbg\x64\plugins\`

---

## License

MIT License

