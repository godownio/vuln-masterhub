---
id: web-php-rce-webshell-junk-comment-nul-padding
title: 注释与 NUL 序列灌入 + 伪语法错误：用垃圾代码撑大文件让静态解析器与 AI 判读提前放弃
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-junk-comment-nul-padding
tags:
- php
- webshell
- av-bypass
- obfuscation
- junk-code
- comment-padding
- ai-detection
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:58:34+08:00'
  notes: 已对照原文核对：原文第三版代码大量 /* \\00\\00\\00%00%00fvjivgjisghtrehgtghbvtrifh 希儿世界第一可爱！*/ 注释插在 class 名与 { 之间、方法名与参数之间，以及 rejfgireghjebvf;fvevbbn();ff;、echo();die(); 这类伪错误语句，卡片描述准确；3.php 文件大小 31.51 KB、引擎检出 1/26，1.php 4.55 KB 检出 0/28，均与原文截图一致。未验证点：'1/26~1/28' 区间由两张截图合成；PHP 8 下未定义常量抛 Error 的表述为语言行为推断，原文未说明 PHP 版本；未执行任何 PHP 代码。
url: /docs/web/php/rce/web-php-rce-webshell-junk-comment-nul-padding/
draft: false
kb_aliases:
- 无用代码免杀
- 注释填充混淆
- '"%00" 序列填充 webshell'
- 伪语法错误干扰
- 垃圾代码撑大文件
---

## 一句话结论

在同一个 PHP 文件里用 `/* ... */` 注释块重复灌入同一条无意义字符串（例如 `\00\00\00%00%00` 加自造拼音串），再在注释外插入看起来"写错了"的语句（`rejfgireghjebvf;fvevbbn();ff;`、`echo();die();\n\0`），可以把文件从几 KB 撑到 30 KB 以上，让基于行长/窗口/特征密度的静态扫描器失去采样点、让字符串级 YARA/正则难以命中，同时诱导人工与 LLM 判读提前放弃（"这代码乱七八糟，读不下去"），而真实门控与变量函数调用仍完整保留、可正常执行。

## 原理

- **注释膨胀的两种作用**：① 稀释特征密度——真实敏感片段（`$c($pcs)`、`getLockerStatus()`）在大量无关文本中被摊薄，按"命中数/文件大小"或固定窗口取样的检测器更容易漏；② 破坏行结构——`\00`、`%00` 这类不可打印序列与超长单行会让部分解析器/扫描器（尤其带行长上限的）截断或跳过该区域。
- **伪语法错误**：`rejfgireghjebvf;fvevbbn();ff;` 这类裸标识符在 PHP 中并不致命（`rejfgireghjebvf` 会被当作未定义常量，PHP 8 会抛 `Error`，但原文把 `error_reporting(0)` 与分支安排在前，且这些语句若在未执行路径或异常被吞掉时不影响主链）；`echo();die();\n\0` 同样以"看起来像残破代码"的形态占据行首。目的是让读者与自动分析都认为"这段代码是坏的/无关的"，从而不再往里追。
- **可执行性不受影响**：注释块与噪声语句不改变控制流；`class InazumaPuzzle/*...*/{` 这种把注释插在 `class` 名与 `{` 之间的写法在 PHP 里合法（注释等价空白），因此门控与 `$c($pcs)` 照常工作。原文实测该 31.51 KB 版本 POST `wpstring=ABBCCD&b=s&pcs=whoami` 仍回显命令结果，多个引擎检出 1/26~1/28（判"安全"）。
- **为什么比"加密"更省事**：不需要额外的编码/解码函数（这些本身就是可疑特征），只需复制粘贴字符串；代价是文件变大、可读性下降——但对攻击者正是收益。
- 与"AI 检测器的注释盲区"不同：那类靠注释里的自然语言指令操纵模型判断；本卡靠**数量与噪声**让判读过程失效（上下文窗口被垃圾占满、注意力被伪错误吸引）。

## 触发条件

- 目标为 PHP，且文件可落地并被执行（前置上传/写入/包含环节独立）；
- 防护以静态文件扫描、关键词/正则、或 LLM 整文件判读为主，缺少运行时行为监控；
- 膨胀后的文件仍在目标上传限制内（原文样例约 31 KB，一般远低于限制）。

## 利用步骤

1. 先准备可执行的核心马（门控 + 变量函数调用），确认其单独可跑通。
2. 在类名与 `{` 之间、方法之间、行尾插入 `/* 无意义串 */` 注释块；无意义串可用 `\00\00\00%00%00` + 任意自造字符串重复拼接，避开会破坏语法的字符（不要引入未闭合的 `*/`）。
3. 在注释外的空白/行首插入若干"疑似错写"的语句（未定义常量调用、空参 `echo()`、裸 `die();` 等），使读者以为文件已损坏；确保这些语句位于不会先于主链执行的位置或被错误抑制覆盖。
4. 逐次增大注释量并复测：文件仍能正常返回执行结果、静态引擎不再命中、LLM 判读给出"无害/看不懂"。
5. 需要更强效果时，叠加门控（`web-php-rce-webshell-puzzle-state-gate-av-bypass`）与算法载体（`web-php-rce-webshell-algorithmic-array-byte-carrier`）。

## PoC

```php
class InazumaPuzzle/*\00\00\00%00%00<无意义串重复 N 次>*/{
    private $blockA = 0;/*\00\00\00%00%00<无意义串>*/private $blockB = 0;
    /* ... */
    private function hit($blockIdx) {
        global $cnbd;
        rejfgireghjebvf;fvevbbn();ff;      /* 伪错误语句 */
        /* ... 真实逻辑 ... */
    }
}
```

请求侧不变：

```http
POST /shell/3.php HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

wpstring=ABBCCD&b=s&pcs=whoami
```

## 变体与关联

- 变体：用超长单行（把整个文件挤成一行或几行）配合大量注释，专门针对按行读取/按行显示的分析工具。
- 变体：把无意义串换成"看起来像正常业务日志/配置"的文本（伪 JSON、伪 SQL、伪版本号），比纯乱码更容易让 LLM 认为是业务数据。
- 变体：伪错误语句改为"看起来像被删了一半的函数"（缺右括号的注释片段、孤立 `?>`），进一步误导读者。
- 关联：[[web-php-rce-webshell-puzzle-state-gate-av-bypass]]（门控外壳，常与本卡叠加）。
- 关联：[[ai-security-prompt-injection-ai-webshell-detector-comment-bypass]]（同为注释层对抗但机制不同：那条是给模型下指令，本卡是用体量与噪声让判读失效）。
- 边界：注释必须语法闭合，`\00`/`%00` 只是普通字符，放进 `/* */` 内不影响解析；若膨胀文本里出现 `*/` 会截断注释并造成真实语法错误。

## 检测与防御

- 检测：不要依赖"文件大小/特征密度"这类可稀释指标；对 PHP 文件做 AST 级检测（变量函数调用、`$$key` 批量注册、动态变量拼接），并跳过注释后再分析；对超长单行文件单独标记。
- 防御：`disable_functions`、上传目录禁解析、内容校验（扩展名 + magic + 语法解析）；部署 RASP/EDR 关注运行时执行而非文件外观。
