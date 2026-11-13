---
id: code-analysis-source-audit-java-decompile-classbak-version-mixing
title: Java 反编译目录审计前先排除备份类文件：Jadx 目录模式混入 classbak 旧版本代码导致白名单误判
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: java-decompile-classbak-version-mixing-audit
tags:
- code-analysis
- audit
- java
- decompile
- jadx
- classbak
- backup
- false-positive
- source-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V526
  verified_at: '2026-11-11T15:08:27+08:00'
  notes: 已对照原文与全部23张图核对：图07 POST 1.jsp返回上传材料格式不正确；图08/18/22 显示含jsp/js/html的白名单旧版逻辑（图18 Jadx单文件打开AttachmentController.class、图22 Jadx加载含备份的action目录）；图15 IDEA与图16 jd-gui打开同一class均为仅图片后缀白名单；图20 Jadx加载不含备份的biton目录恢复正常；图21目录中存在AttachmentController.class.cache、classbak220627、classbak220926；图23脚本扫出两个classbak。原文结论为白名单实为限制（仅图片），上传漏洞不成立，卡片结论一致。已修正卡片机制表述：原文『单文件正常、仅目录模式异常』与截图不符（图18 Jadx单文件也输出了旧版），改为『Jadx在含同名备份类的输入集（目录或目录内单个class）中会选中/混入历史版本』并同步触发条件。未验证点：未本地复现Jadx版本混入现象（作者使用其本地Jadx版本）。
url: /docs/code-analysis/static/source-audit/code-analysis-source-audit-java-decompile-classbak-version-mixing/
draft: false
kb_aliases:
- Jadx 目录反编译串版本
- classbak 干扰代码审计
- 反编译前查备份文件
- 备份 class 导致误判
- 反编译结果交叉验证
---

## 一句话结论

对反编译出的 Java class 目录做源码审计时，若目录中混有 `*.classbak<日期>`、`*.class.cache` 等备份/缓存类文件，Jadx 在加载含同名备份类的输入集（目录，或该目录内的单个 class）时会按类名索引并选中/混入历史版本的代码，反编译结果可能变成旧版本逻辑，导致审计结论建立在线上并不存在的代码上——本例因此误判"上传白名单允许 jsp"，实际当前类只允许图片后缀，上传漏洞并不存在。

## 原理

- Java 部署/解包目录常残留历史备份：开发或运维把旧 class 重命名为 `AttachmentController.classbak220627`、`AttachmentController.classbak220926` 之类，或保留 `*.class.cache` 目录，这些文件仍与当前 `AttachmentController.class` 同处一个目录。
- 复现现象（结合截图）：同一份 `AttachmentController.class`，IDEA（图15）与 jd-gui（图16）打开时白名单仅含 `jpg/jpeg/gif/png/bmp`，与线上 `.jsp` 被拒一致；而 Jadx 从含 `classbak220627/220926` 的目录中打开该单个 class（图18）以及加载含备份的 `action` 目录（图22）时，输出变成含 `jsp/js/html` 的旧版白名单；换到不含备份的 `biton` 目录（图20），Jadx 输出又恢复为仅图片后缀。说明反编译输出会随输入集里是否存在同名历史类而变化，可能出现"增加莫名其妙代码"或把不同版本代码混在一起的现象——审计工具链不能默认信任反编译结果。
- 审计工具链默认信任反编译结果；如果不核对文件时间戳/大小、不用第二款反编译工具交叉验证，就会把备份类的旧逻辑当成线上逻辑：本例备份版本的白名单判断包含 `jsp/js/html`（看似"白名单形同虚设、可直接上传 webshell"），而线上当前类只允许 `jpg/jpeg/gif/png/bmp`，实际请求上传 `.jsp` 返回"上传材料格式不正确"，与当前类行为一致。
- 反向风险同样成立：也可能因混入旧版本而把已修复的漏洞当成存在（误报），或把新版本的修复代码当成旧版本（漏报），浪费大量审计时间甚至提交错误的 Issue。

## 触发条件

- 拿到的是部署目录或解包后的 class 目录（而非干净的单一 jar/源码包），目录内含备份、缓存或被改名的历史 class 文件。
- 使用 Jadx 等按类名索引的反编译器加载含备份类的目录（目录模式，或在同一目录中打开单个 class），输入集中存在同名多版本 class。
- 审计者未先核对反编译结果与原始文件的时间戳/大小，也未用第二种反编译工具交叉验证关键判断逻辑。

## 利用步骤

1. 反编译前先扫描目标目录，按文件名关键词列出可疑文件：`bak`、`beifen`、`backup`、`cache`、`~`、日期后缀（如 `classbak220627`）等。
2. 在副本上操作：把备份/缓存文件移出反编译目录，或将当前版本的 class 单独加入工程，避免同名类被历史版本覆盖。
3. 对关键类用至少两种工具（Jadx、jd-gui、IDEA、CFR 等）分别反编译并对比关键分支（白名单、鉴权、sink 调用）。
4. 对每个疑似漏洞点回到运行态验证（构造请求看响应），确认反编译代码与线上实际行为一致后再下结论。
5. 把扫描备份文件固化为审计第一步的脚本（见 PoC），避免重复踩坑。

## PoC

反编译前扫描备份/缓存类的极简脚本（示意，可自行扩展关键词）：

```python
import os, argparse

p = argparse.ArgumentParser()
p.add_argument("-r", "--root", required=True)
args = p.parse_args()

KEYWORDS = ("bak", "beifen", "backup", "cache")
for dirpath, dirnames, filenames in os.walk(args.root):
    for name in filenames:
        low = name.lower()
        if any(k in low for k in KEYWORDS):
            print(os.path.join(dirpath, name))
```

示例输出：

```
.../action/aaa/AttachmentController.classbak220627
.../action/aaa/AttachmentController.classbak220926
```

发现此类文件后应先隔离，再对当前 `AttachmentController.class` 做反编译审计。

## 变体与关联

- 同类污染源：`WEB-INF/lib` 下同名 jar 的多个版本、解包目录中源码与 class 混放、IDE 的 out/target 构建残留、服务器上的 `.war.bak`/`.jar.old`。
- 不同工具处理多版本同名类的方式不同：Jadx 目录模式可能混合，jar 内重复 class 通常按 classpath 顺序取第一个；因此工具交叉验证很重要。
- 与"多版本/多客户部署对比审计"互补：那种方法是有意收集多个版本来找版本特有漏洞；本卡提醒的是无意混入的历史版本会污染反编译结果，二者都要求先厘清"哪份代码才是线上运行的版本"。

## 检测与防御

- 审计侧：反编译前先清点并隔离备份/缓存类文件；关键类用两款以上工具交叉验证；任何漏洞结论都要经过运行态请求验证。
- 开发/运维侧：部署包与线上目录不要携带 `classbak`、`.cache`、`.bak` 等历史文件，既减少代码与历史逻辑泄露，也避免干扰自动化/人工审计的准确性。
- 自动化审计平台：在反编译流水线入口增加文件名过滤与同名类多版本检测，发现同名多版本时告警而不是静默覆盖。
