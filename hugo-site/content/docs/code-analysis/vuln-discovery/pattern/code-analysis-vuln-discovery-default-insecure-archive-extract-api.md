---
id: code-analysis-vuln-discovery-default-insecure-archive-extract-api
title: 跨语言解压 API 默认不安全清单：Zip Slip sink 识别与穿越条目构造
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery/pattern
technique: default-insecure-archive-extract-api-audit
tags:
- code-audit
- path-traversal
- zip-slip
- archive
- java
- python
- golang
- ruby
- arbitrary-write
- pattern
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-07T23:34:17+08:00'
  notes: 已对照 content.md(433 行)与唯一图 img/01（Zip Slip 概念图，无请求响应细节）核对。文中 9 个 sink 与卡内表格逐条对应：Java ZipInputStream.getNextEntry()+FileOutputStream(output+separator+getName)、ZipFile entries()+Paths.get(output,getName)+Files.newOutputStream、Commons Compress TarArchiveInputStream+Paths.get(output).resolve(getName)+Files.copy；Python zf.namelist()+os.path.join+shutil.copyfileobj、tarfile getmembers()+extract；Golang archive/zip 的 filepath.Join(dest,f.Name)+os.Create+io.Copy、archive/tar 的 tr.Next()+filepath.Join(dest,header.Name)；Ruby Zip::File.extract 与 Gem::Package::TarReader 的 entry.full_name+File.expand_path。判断标准（归一化后与解压根做前缀比较）与三格式 payload 构造（zipfile.writestr、TarInfo(name)、tarfile w:gz）与原文示例一致，仅槽位名做了泛化。另用本机 CPython 3.12.0 源码只读复核两点：ZipFile._extract_member 确实 splitdrive 后过滤空/./.. 段（故卡内把 extractall 列为 Python 安全参照成立）、tarfile._extract_member 仍只做 rstrip+replace 不剥离 ..（CVE-2007-4559 语义，卡内『旧版不剥离 ..』+『3.12+ extractall(filter=data)』成立，本机存在 tarfile.data_filter）。未在本机解压任何恶意归档、未执行原文 PoC。
url: /docs/code-analysis/vuln-discovery/pattern/code-analysis-vuln-discovery-default-insecure-archive-extract-api/
draft: false
kb_aliases:
- 默认不安全解压
- Zip Slip sink 清单
- 解压 API 审计
- entry.getName 拼接
- namelist 拼路径
- zipfile.extractall 不安全
- tarfile.extract 路径穿越
- filepath.Join 解压穿越
---

## 一句话结论

多数语言的标准解压 API 在「用条目名拼路径」时都不保证路径留在解压目录内，且不少二次封装（`shutil.copyfileobj`、`io.Copy`、`Files.copy`、`Zip::File#extract`）接收的是「已打开的文件描述符或已算好的路径」而不是「目录 + 条目名」，因此库内部没有机会做边界校验；审计时按「拼接用的哪个 API / 归一化后是否与解压根做过包含性比较」两个问题逐点扫，就能稳定定位 Zip Slip 写点，再用对应格式的恶意条目名验证。

## 原理

- 归档条目名（zip 的 `ZipEntry.getName()` / `ZipInfo.filename`，tar 的 `TarInfo.name` / `Header.Name`，Ruby 的 `entry.full_name`）由压缩包制作者完全控制，是攻击者数据；解压实现若把它当相对路径信任，安全边界就完全依赖这个字符串。
- 「接收文件描述符」的 API 天然不知道路径：`shutil.copyfileobj(src, dst)`、`io.Copy(outFile, inFile)`、`entry.read` + `File.open(path, "wb")` 只看到两个流/一个已算好的 `path`，没有「基准目录」概念。这类封装把校验责任整个甩给调用方，而调用方通常只写了 `os.path.join` / `filepath.Join` / `File.join`。
- 「拼接」不等于「约束」：`os.path.join(dest, name)` 直接字符串拼接后不做归一化，`..` 生效后落到 dest 之外；Go 的 `filepath.Join` 会 `Clean`，`dest/../../x` 会被归一化成 dest 之外的绝对路径 —— 归一化只是让路径变短，并不会把它拉回 dest 里面。判定标准只有一个：把结果规范化（`os.path.realpath` / `filepath.Abs`+`filepath.Clean` / `Path.resolve`）后，是否仍以解压根为前缀。
- 库自身的「安全方法」与「不安全方法」在同一个库里并存，形成默认踩坑面：Python 的 `ZipFile.extract/extractall` 走 `_extract_member`，会 `splitdrive` 并过滤掉名为 `''`/`.`/`..` 的路径段，但同一对象的 `namelist()/open()` 完全不校验；`tarfile.extract()` 在加入 `filter` 参数之前不做这类规范化；Ruby 的 `Gem::Package::TarReader` 干脆只负责读。
- 危害落点：写入 dest 之外的任意可写路径 —— Web 根写脚本、模板目录覆写、`authorized_keys`/cron/计划任务、配置文件、可执行目录；因此该 sink 的上限是任意文件写乃至 RCE。

## 触发条件

- 服务端存在「接收压缩包并解压」的功能（批量导入、主题/插件安装、备份恢复、镜像/数据包上传）。
- 解压实现命中下列任一不安全形态，且没有等价的手写边界校验。
- 进程对穿越目标目录有写权限；若要拿到 RCE，还需目标目录被 Web 容器/计划任务/其他进程消费。

按语言的不安全形态对照（同语言的相邻写法作为「安全参照」）：

| 语言 | 不安全形态（sink） | 为什么默认不安全 | 安全参照 |
|---|---|---|---|
| Java | `ZipInputStream.getNextEntry()` 后 `new FileOutputStream(output + File.separator + entry.getName())` | 条目名未清理，直接进入写入路径 | 规范化后与输出根做前缀比较 |
| Java | `ZipFile.entries()` 遍历，`Paths.get(output, entry.getName())` + `Files.newOutputStream(destPath)` | `Paths.get` 只拼接不校验 | `toRealPath()` 后用 `startsWith(output)` 判定 |
| Java | Apache Commons Compress `TarArchiveInputStream.getNextEntry()` + `Paths.get(output).resolve(entry.getName())` + `Files.copy` | 同上，`resolve` 跟随 `..` | 同上，并拒绝绝对路径 |
| Python | `zipfile.ZipFile(...).namelist()` + `os.path.join(output, filename)` + `shutil.copyfileobj(zf.open(f), open(p,'wb'))` | `os.path.join` 不规范化；`copyfileobj` 只见两个 fd | `ZipFile.extractall()`（内建逐段过滤）或 `os.path.realpath` 后与解压根比较 |
| Python | `tarfile.open(...)` 遍历 `getmembers()` 后 `tf.extract(tarinfo, path)` | 旧版 `_extract_member` 只把 `/` 换成本地分隔符，不剥离 `..`/多余分隔符 | 显式成员名校验，或 3.12+ 的 `extractall(filter='data')` |
| Golang | `archive/zip` 的 `filepath.Join(dest, f.Name)` 后 `os.Create(fpath)` + `io.Copy` | `Join` 会 Clean，但结果仍可落在 dest 之外；无包含性校验 | `filepath.Rel(dest, fpath)` 起头非 `..` 才放行 |
| Golang | `archive/tar` 的 `tr.Next()` 后 `filepath.Join(dest, header.Name)` + `os.Create` | 同上 | 同上，另需拒绝 `TypeSymlink`/`TypeLink` |
| Ruby | `Zip::File.open(f){|z| z.each{|e| p = File.join(output, e.name); z.extract(e, p) } }` | `extract` 注释明确把 `destination_directory` 的安全性交给调用方 | 自行规范化并校验前缀 |
| Ruby | `Gem::Package::TarReader` 的 `entry.full_name` + `File.expand_path(name, output)` | 纯读取器，无任何提取期校验；`expand_path` 会把 `..` 展开到外面 | 同上 |

## 利用步骤

1. 在代码里按上表 grep sink：`getNextEntry`、`entries()`、`Paths.get(`+`getName`、`namelist()`、`copyfileobj`、`tarfile`+`extract(`、`filepath.Join(`+`Name`、`Zip::File`+`extract`、`TarReader`。
2. 对每个命中点回答两问：拼接后有没有 `realpath`/`Clean`/`resolve` 再与解压根比较？比较失败时是拒绝还是仅日志？
3. 确认归档类型（zip / tar / tar.gz）、解压落点、进程对目标目录的写权限。
4. 按对应格式构造带 `../` 条目名的压缩包（见 PoC），上传触发解压。
5. 检查穿越落点是否出现文件；若落点是 Web 目录，改写为脚本文件取得执行，否则用覆盖配置/计划任务的方式落地代码。
6. 记录写点绝对路径、进程权限与后续消费方（谁来执行这个文件）。

## PoC

按格式构造穿越条目（同一载荷只改容器格式，便于在只接受某种后缀的上传点上复用）：

```python
import io, tarfile, zipfile

# zip
with zipfile.ZipFile('payload.zip', 'w') as z:
    z.writestr('../../poc.txt', 'PoC')

# tar
data = io.BytesIO(b'PoC')
ti = tarfile.TarInfo(name='../../poc.txt')
ti.size = len(b'PoC')
with tarfile.open('payload.tar', 'w') as t:
    t.addfile(ti, data)

# tar.gz
with tarfile.open('payload.tar.gz', 'w:gz') as t:
    t.addfile(ti, io.BytesIO(b'PoC'))
```

Java 侧最小不安全解压（用于自建靶标验证 sink）：

```java
try (ZipInputStream zip = new ZipInputStream(new FileInputStream(name))) {
    ZipEntry e;
    while ((e = zip.getNextEntry()) != null) {
        // 危险：直接拼接条目名
        try (FileOutputStream out = new FileOutputStream(output + File.separator + e.getName())) {
            zip.transferTo(out);
        }
    }
}
```

## 变体与关联

- 变体：绝对路径条目（`/var/www/x.php`）、Windows 盘符与反斜杠（`..\..\x`）、符号链接/硬链接条目（先写链接再写目标，绕过只校验条目名的实现）。
- 变体：只校验第一个 `..` 或 `startsWith("../")` 的实现，可用 `./../../`、`....//`、多重分隔符绕过（见关联卡）。
- 变体：把条目名与真实落点不一致的编码手法（NUL 截断、Unicode 归一化）绕过「按后缀白名单」的检查。
- 关联：`[[web-generic-file-upload-zip-slip-webshell-write]]` 是这一类 sink 的落地利用场景（Web 根写 webshell）；`[[web-generic-file-upload-ant-zipslip-leading-dotdot-prefix-bypass]]` 是对已有 `startsWith` 校验的绕过；`[[web-generic-file-upload-zip-entry-nul-windows-truncation]]` 是条目名与落点不一致的变体。
- 边界：解压实现做了真实路径包含性校验、只解压白名单后缀到隔离目录、进程对目标目录无写权限时，sink 被堵住。

## 检测与防御

- 检测：解压后出现解压根之外的写入；归档条目名含 `..`、绝对路径、盘符、反斜杠、符号链接；上传接口随后在异常目录出现新文件。
- 修复：统一封装一个 `safeExtract`：对每个条目 `realpath` 后与解压根做 `startsWith`/`commonpath` 比较，拒绝绝对路径、盘符、`..`、符号链接与硬链接条目；只解压后缀白名单；先解压到隔离临时目录再按清单移动。
- 加固：解压进程以最小权限运行，解压目录与 Web 可执行目录分离；对归档解压做审计日志（条目名原值 + 最终落点路径），便于事后追查。
