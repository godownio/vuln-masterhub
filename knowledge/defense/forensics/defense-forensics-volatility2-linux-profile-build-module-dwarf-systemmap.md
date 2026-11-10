---
id: defense-forensics-volatility2-linux-profile-build-module-dwarf-systemmap
title: Volatility2 Linux Profile 制作：按目标内核编译 module.dwarf、配对 System.map 打包 zip 放入 overlays，并规避 dwarfdump 弃用与版本兼容坑
type: scenario
domain: defense
path: defense/forensics
technique: volatility2-linux-profile-build
aliases:
- Volatility2 Linux profile 制作
- module.dwarf
- System.map 打包 profile
- Linuxcentos8 profile
- dwarfdump 编译安装
- CentOS 8 Volatility2 profile
tags:
- linux
- forensics
- memory
- volatility2
- profile
- dwarfdump
- libdwarf
- centos
- rhel
- incident-response
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V363
  verified_at: '2026-11-09T03:17:16+08:00'
  notes: 已对照原文与 7 张截图核对：dwarfdump 源码编译、module.dwarf 生成、System.map 配对打包、overlays 部署、dwarfdump 0.8 触发 dwarf.py ValueError 均有原文证据。未验证点：换 dwarfdump 0.1 后仅文字称不再报 Python 错误，无截图；原文 --info 截图 profile 名为 Linuxuxlinux_centos8_5_kernel_4_18x64 与后续命令 --profile=Linuxcentos8x64 不一致，属原文自身不一致，卡片按 medium 置信度保留。
---

## 一句话结论

当目标 Linux 内核没有现成的 Volatility2 profile 时，在与目标同版本内核（`uname -r` 一致）的环境里安装 kernel-devel/kernel-headers 与 gcc/make，编译 Volatility2 `tools/linux` 的调试模块并用 `dwarfdump -di` 生成 `module.dwarf`，再与 `/boot/System.map-<内核版本>` 一起打包成 zip 放进 `volatility/volatility/plugins/overlays/linux/`，`vol.py --info` 能列出该 profile 后即可用它分析同内核的内存镜像；CentOS/RHEL 8 已弃用 dwarfdump，需要源码编译 libdwarf，且 dwarfdump 版本与 Volatility2 的 DWARF 解析器不匹配时 profile 会在加载阶段报错。

## 原理

- **为什么需要 profile**：Volatility2 的插件全部依赖内核结构体的字段偏移与符号地址。Windows 的内存布局版本有限，官方预置了 VistaSP0x64～Win10x64 等 profile；Linux 发行版内核随版本、补丁、编译配置变化，必须针对目标机器的内核现场生成 profile，否则无法正确解释内存结构。
- **profile 的两个组成部分**：
  - `module.dwarf`：把 Volatility2 自带的 `tools/linux/module.c` 以 `CONFIG_DEBUG_INFO=y` 针对目标内核头编译成 `module.ko`，再用 `dwarfdump -di module.ko > module.dwarf` 导出 DWARF 调试信息。DWARF 里保存了内核结构体的类型、字段名、偏移与大小，Volatility2 启动时用 `dwarf.DWARFParser` 解析它构建 vtypes。
  - `System.map`：内核符号表，提供符号名到地址的映射；插件解析内核全局对象（进程链表、网络结构等）时按符号找地址，结构布局则来自 module.dwarf。
- **为什么版本必须精确**：module 是针对 `/lib/modules/$(uname -r)/build` 的头文件与配置编译的，结构体偏移取自目标内核。用其他内核头编译的 profile 与镜像实际布局不一致时，多数情况不会直接报错，而是读出错误字段，得出错误的进程/网络结论，比直接失败更危险。
- **为什么 zip 文件名决定 profile 名**：Volatility2 扫描 `overlays/linux/` 下的 zip，把文件名转成 profile 类名（如 `linux_centos8_5_kernel_4_18.zip` 对应 `Linuxcentos8_5_kernel_4_18x64`）。`--profile=` 必须使用 `vol.py --info` Profiles 列表里显示的名字。
- **RHEL/CentOS 8 的 dwarfdump 弃用坑**：RHEL 8 起 `libdwarf`/`dwarfdump` 被标记弃用，官方替代是 binutils 的 `readelf --debug-dump` 或 elfutils 的 `eu-readelf --debug-dump`，但 Volatility2 的 Makefile 与解析器只认 `dwarfdump` 命令及其输出文本格式，替代工具不能直接使用。可行做法是从 libdwarf 源码编译安装，`configure && make && make install` 后命令落在 `/usr/local/bin/dwarfdump`。
- **dwarfdump 版本兼容坑**：用较新的 libdwarf（0.8，2023 年发布）生成 module.dwarf 后，加载 profile 时在 `volatility/dwarf.py` 的 `process_statement` 处报 `ValueError: invalid literal for int() with base 16: '136 (-120)'`——解析器对 `DW_AT_byte_size` 等属性值直接做 `int(value, 16)`，而新版 dwarfdump 的属性行里带了额外文本（如括号内的负值说明），不是纯十六进制。换用与平台年代匹配的旧版 dwarfdump（0.1，2021 年发布）重新生成 module.dwarf，可以消掉这个 Python 解析异常；镜像能否被分析还取决于下一层的地址空间问题（见关联卡片）。

## 触发条件

- 已取得目标 Linux 主机的内存镜像，但没有与镜像内核匹配的现成 Volatility2 profile。
- 能获得目标内核同版本的 kernel-devel/kernel-headers（CentOS/RHEL 可用 dnf 安装与 `uname -r` 对应的 kernel-devel），并具备 gcc/gcc-c++/make 与可用的 dwarfdump。
- 目标 `/boot` 下存在与 `uname -r` 一致的 `System.map-<版本>`；升级过内核的机器会有多份，必须按版本选择。
- 编译环境最好与目标内核/发行版一致（同版本内核头、相近工具链），避免结构体布局差异。
- Volatility2 依赖 Python2 运行（`python2 vol.py`）。

## 利用步骤

1. **记录目标内核**：`uname -a` 确认内核版本（如 `4.18.0-348.7.1.el8_5.x86_64`），在 `/boot` 找同名 `System.map-4.18.0-348.7.1.el8_5.x86_64`。
2. **安装编译依赖**：`dnf -y install kernel-devel kernel-headers gcc gcc-c++ make`；kernel-devel 提供 `/lib/modules/$(uname -r)/build` 构建目录。
3. **准备 dwarfdump（RHEL/CentOS 8 必需）**：解压 libdwarf 源码，`mkdir build && cd build && ../configure && make -j16 && make install`，确认 `which dwarfdump` 指向 `/usr/local/bin/dwarfdump` 且能运行。
4. **编译 module.dwarf**：进入 volatility2 的 `tools/linux/` 执行 `make`。Makefile 会调用 `/lib/modules/$(uname -r)/build` 以 `CONFIG_DEBUG_INFO=y` 编译 `module.ko`，随后执行 `dwarfdump -di module.ko > module.dwarf`；目录下出现 `module.dwarf` 即成功（modpost 的 `missing MODULE_LICENSE()` 警告不影响结果）。
5. **与 System.map 打包**：`zip linux_<描述>.zip /boot/System.map-<版本> tools/volatility/tools/linux/module.dwarf`，两个文件必须同包，且对应同一内核版本。
6. **部署到 overlays**：把 zip 复制到 `volatility/volatility/plugins/overlays/linux/`。
7. **验证加载**：`python2 vol.py --info`，在 Profiles 列表找到由 zip 文件名派生的新 profile；用 `--profile=<该名字>` 打开同内核镜像，先跑 `linux_psscan` 验证基础解析。

## PoC

```bash
# 1) 编译依赖
dnf -y install kernel-devel kernel-headers gcc gcc-c++ make

# 2) CentOS/RHEL 8：源码编译 dwarfdump
tar -xf libdwarf-0.8.0.tar.xz && cd libdwarf-0.8.0 && mkdir build && cd build
../configure && make -j16 && make install
which dwarfdump                 # /usr/local/bin/dwarfdump

# 3) 编译 module.dwarf（Volatility2 2.6.1）
cd volatility/tools/linux
make
ls module.dwarf                 # 生成成功

# 4) 与同版本 System.map 打包并部署
zip linux_centos8_5_kernel_4_18.zip \
  /boot/System.map-4.18.0-348.7.1.el8_5.x86_64 \
  /opt/tools/volatility/tools/linux/module.dwarf
cp linux_centos8_5_kernel_4_18.zip /opt/tools/volatility/volatility/plugins/overlays/linux/

# 5) 验证 profile 已加载
python2 vol.py --info | grep -i linux_centos8
```

dwarfdump 版本过新时的典型报错：

```text
ValueError: invalid literal for int() with base 16: '136 (-120)'
  File "volatility/dwarf.py", line 200, in process_statement
    self.types[name] = [ int(data['DW_AT_byte_size'], self.base), {} ]
```

该报错说明 module.dwarf 的属性值不是解析器期望的纯十六进制，优先换旧版 dwarfdump 重新生成，而不是改 Volatility2 源码。

## 变体与关联

- **镜像格式问题**：profile 成功加载后，若 raw 镜像仍报 `No suitable address space mapping found`，见 [[defense-forensics-volatility2-linux-raw-vs-lime-address-space]]，改用 LiME 格式采集。
- **多个 System.map**：内核升级后 `/boot` 下有多份 `System.map-*`，必须选 `uname -r` 对应的那一份；选错会导致符号地址错位。
- **新版/旧版 dwarfdump**：Volatility2 官方文档提到 dwarfdump 版本过低会产出有问题的 profile；实践里版本过新同样会触发 DWARF 解析异常。选择与 Volatility2 发布年代接近、能正常被其 dwarf.py 解析的版本最稳妥。
- **Volatility3**：改用 ISF 符号表方案（由 module.dwarf + System.map 转换成 JSON 符号文件），同样是“目标内核头编译 + 符号表”思路，但工具链与 profile 机制不同；本卡仅覆盖 Volatility2。
- **Windows 对比**：Windows 直接用官方预置 profile；Linux 才需要按机器构建，这是 Linux 内存取证的前置步骤。

## 检测与防御

- **取证可信性**：profile 必须由与镜像同内核版本的 headers 生成；记录 `uname -r`、System.map 路径与哈希、dwarfdump/libdwarf 版本、profile 名，保证分析可复现、证据链完整。
- **误读风险**：profile 版本不匹配时常常不报错而是给出错误偏移，必须先用 `linux_psscan` 等基础插件验证，再使用依赖深层结构的插件；结论要与其他证据交叉。
- **运维准备**：保留生产内核对应的 kernel-devel 与 `/boot/System.map-*`（或整份 `/boot` 归档），内核升级时同步留档，事后取证才有对应构建材料。
- **检测视角**：在主机上编译内核模块、加载模块（insmod）、读取物理内存等行为会留下模块加载审计/EDR 记录；非授权方对生产机做内存采集与 profile 构建可作为入侵调查线索。
