---
id: ctf-forensics-wsl-ext4-vhdx-offline-inspect
title: WSL ext4.vhdx 离线取证：挂载虚拟磁盘读取 bash_history 与模型部署配置
type: scenario
domain: ctf
path: ctf/forensics
technique: wsl-ext4-vhdx-offline-forensics
tags:
- ctf
- forensics
- wsl
- vhdx
- ext4
- bash-history
- vllm
- offline-analysis
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:53:18+08:00'
  notes: 已对照原文与图片 06-14 核对；ext4.vhdx 路径、bash_history 的 vllm serve/max-model-len 8192、CUDA 12.8 包目录一致
url: /docs/ctf/forensics/ctf-forensics-wsl-ext4-vhdx-offline-inspect/
draft: false
kb_aliases:
- WSL 虚拟磁盘取证
- ext4.vhdx 挂载
- bash_history 取证
- vLLM 部署还原
- WSL 镜像仿真
---

## 一句话结论

Windows 镜像中的 WSL 发行版以 `ext4.vhdx` 虚拟磁盘形式存放（常见于 `Users/<user>/AppData/Local/wsl/<GUID>/`）；离线挂载该 VHDX 后，读取 `/home/<user>/.bash_history`、`~/.config`、Python 包目录与模型配置，即可还原推理引擎版本、启动参数、CUDA 版本与模型部署细节，全程不需要启动原系统。

## 原理

- **WSL2 的根文件系统就是一个 ext4 虚拟磁盘**：`ext4.vhdx` 是动态扩展的 VHDX，内含完整 Linux 根分区；Windows 侧只保存少量元数据。
- **虚拟磁盘可离线挂载**：Linux 可用 `guestmount`/`qemu-nbd`/`losetup` 挂载 VHDX；Windows 可用 7-Zip 读取或取证工具的虚拟磁盘浏览/镜像仿真功能。
- **用户痕迹集中在 home 目录**：`~/.bash_history` 记录启动命令（如 `vllm serve ... --max-model-len 8192 --port 8000`），`~/.config`/venv 的 `*.dist-info` 记录包版本与 CUDA 依赖，模型目录的 `config.json` 记录模型名与参数。
- **为什么有效**：WSL 的虚拟磁盘通常不受 BitLocker 保护（或随宿主磁盘一起解密），且取证工具可直接解析 ext4；命令历史与包元数据是明文，能快速回答“部署了什么、怎么启动、什么版本”。
- **与镜像仿真的区别**：仿真启动原系统能获得更完整的运行时状态，但成本高、可能改动证据；离线挂载只读分析更安全，适合 CTF 和取证初筛。

## 触发条件

- 已获得 Windows 镜像或 `ext4.vhdx` 文件。
- 镜像中的 WSL 发行版仍保留用户 home 目录、bash 历史与虚拟环境。
- 分析环境有 VHDX/ext4 挂载能力（Linux guestmount/qemu-nbd，Windows 取证工具或 7-Zip）。
- 目标用户没有清理历史/缓存，或清理不彻底。

## 利用步骤

1. 在镜像中定位 `ext4.vhdx`：常见路径 `Users/<user>/AppData/Local/wsl/<GUID>/ext4.vhdx`，也可搜索文件名。
2. 以只读方式挂载 VHDX 到分析机（Linux 示例：`guestmount --add ext4.vhdx --ro -m /dev/sda1 /mnt/wsl`；或 `qemu-nbd -r -c /dev/nbd0 ext4.vhdx` 后 `mount -o ro /dev/nbd0p1 /mnt/wsl`）。
3. 进入 `/home/<user>/`，查看 `.bash_history`、`.bash_logout`、`.profile`、`.config`、`.local`、虚拟环境目录。
4. 从历史命令提取启动参数（端口、`--max-model-len`、模型名、`--host` 等）；从 `site-packages/*.dist-info/METADATA` 提取包版本与 CUDA 依赖。
5. 在模型目录读取 `config.json`、`usage_stats.json` 等，确认模型名称、参数量、上下文长度与服务地址。
6. 交叉验证：历史命令、配置文件、包版本三者互相对应后再写入结论；分析完成后卸载并校验镜像哈希未变。

## PoC

原文通过取证工具的虚拟磁盘浏览/镜像仿真完成，未给出手工挂载命令；以下为通用只读挂载示意（需按实际分区调整）：

```bash
# Linux 分析机：只读挂载 WSL 的 ext4.vhdx
sudo guestmount --add ext4.vhdx --ro -m /dev/sda1 /mnt/wsl

# 读取命令历史与启动参数
grep -iE "vllm|serve|--max-model-len|--port|pip install|python3" /mnt/wsl/home/*/.bash_history

# 读取 Python 包版本与 CUDA 依赖
ls /mnt/wsl/home/*/vllm-env/lib/python3.*/site-packages/ | grep -iE "cuda|vllm|torch"
cat /mnt/wsl/home/*/vllm-env/lib/python3.*/site-packages/vllm-*.dist-info/METADATA | head

sudo guestunmount /mnt/wsl
```

原文观察到的痕迹示例：`~/.bash_history` 中含 `vllm serve Qwen3-1.7B --host 0.0.0.0 --port 8000 --max-model-len 8192 ...`、`pip install transformers==4.57.6 "tokenizers<0.23.0"`；包目录中出现 `nvidia_cuda_runtime_cu12-12.8.90.dist-info`、`cupy_cuda12x-14.2.0.dist-info`。

## 变体与关联

- **虚拟化格式变体**：VHDX、VHD、qcow2、raw；WSL1 为 NTFS 目录，WSL2 为 ext4.vhdx；Docker Desktop 也有独立的虚拟磁盘。
- **痕迹变体**：`.bash_history`、`.zsh_history`、`.python_history`、systemd 服务、crontab、Jupyter 配置、HuggingFace 缓存。
- **挂载变体**：7-Zip 直接浏览 VHDX；取证工具（火眼等）虚拟磁盘浏览/镜像仿真；`qemu-nbd` + `mount -o ro`；`guestmount --ro`。
- **关联卡片**：[[ctf-forensics-windows-sam-system-offline-ntlm-mask-crack]]（同属 Windows 镜像离线取证）、[[ai-security-supply-chain-agent-skill-external-second-stage-loader]]（模型/脚本部署链）。
- **边界**：WSL 虚拟磁盘若被加密或损坏，需先修复/解密；用户清理过历史或使用其他 shell 时痕迹减少；手工挂载的分区号需按实际镜像确认。

## 检测与防御

- **取证侧**：始终只读挂载，记录 VHDX 哈希与访问时间；对历史命令、配置、包版本做交叉验证，避免只凭单条命令下结论。
- **防御侧**：对 WSL 虚拟磁盘启用加密（如 BitLocker + WSL 加密）；定期清理命令历史与缓存；不要在 WSL 中明文保存 API Key/口令；模型服务仅监听 localhost 并加认证。
- **检测信号**：镜像中出现含密钥/口令的 `.bash_history`、`config.json`、`usage_stats.json`；WSL 端口对外监听；异常 pip 源或未签名模型下载。
