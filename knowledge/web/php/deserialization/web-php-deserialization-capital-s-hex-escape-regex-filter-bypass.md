---
id: web-php-deserialization-capital-s-hex-escape-regex-filter-bypass
title: PHP 反序列化过滤器只匹配小写 s：大写 S 十六进制转义绕过并触发 __toString 读文件
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-capital-s-hex-escape-filter-bypass
aliases:
- 大写 S 反序列化绕过
- S 十六进制转义
- 序列化正则绕过
- __toString 文件读取
- unserialize 过滤器绕过
tags:
- php
- deserialization
- filter-bypass
- magic-method
- tostring
- hex-escape
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:52:09+08:00'
  notes: 已对照原文「魔法导入器」核对：过滤规则 /s:\d+:"[^"]*flag[^"]*"/ 只匹配小写 s，第二条类名规则允许 Welcome|Profile|FileViewer；payload O:7:"Welcome":1:{s:4:"user";O:10:"FileViewer":1:{s:4:"path";S:5:"/\66lag";}} 用大写 S 的 \66 还原 f，长度按解码后 5 字节；Welcome::__destruct 拼接 user 触发 FileViewer::__toString 的 file_get_contents 读取 /flag，与原文一致。未验证点：未复跑；无 CVE/版本；frontmatter 无 sources/source_url。
---

## 一句话结论

服务端用正则 `/s:\d+:"[^"]*flag[^"]*"/` 拦截序列化字符串中的敏感路径，但 PHP 的 `unserialize` 同时接受大写 `S` 作为“带十六进制转义的字符串”类型；构造 `S:5:"/\66lag"` 即可让正则看不到 `flag` 字面量，反序列化后却还原成 `/flag`，再通过 `Welcome::__destruct` 输出 `FileViewer` 对象触发 `__toString` 的 `file_get_contents` 读文件。

## 原理

- **PHP 序列化字符串有两种写法**：小写 `s:<len>:"..."` 是普通字符串；大写 `S:<len>:"..."` 支持 `\xx` 十六进制转义，`\66` 会被解码为字符 `f`。`unserialize` 对两者都接受。
- **过滤器只覆盖小写**：规则 `/s:\d+:"[^"]*flag[^"]*"/` 只匹配 `s:`，不匹配 `S:`；因此 `S:5:"/\66lag"` 不会命中，但其解码结果包含 `/flag`。
- **长度语义**：`S` 的长度写的是解码后的字节数；`/\66lag` 原始 7 个字符、解码后 `/flag` 为 5 字节，所以是 `S:5:`。写错长度会反序列化失败。
- **魔术方法链**：`Welcome::__destruct()` 执行 `echo "..." . $this->user`，把 `user` 属性（`FileViewer` 对象）转为字符串，触发 `FileViewer::__toString()`；后者 `file_get_contents($this->path)` 读取路径并返回内容，最终随 echo 输出。
- **类白名单仍可通过**：第二条规则只禁止 `Welcome|Profile|FileViewer` 之外的类，本题 payload 只使用允许的类，因此不触发。
- **为什么正则过滤天生不可靠**：序列化格式有多种等价写法（大写 `S`、`C`/`O` 自定义序列化、引用 `R`/`r`、长度与前缀变体），逐条正则很难穷尽；正确做法是解析结构或禁止对象反序列化。

## 触发条件

- 应用对用户提交的序列化数据调用 `unserialize`，且用正则做黑名单/敏感字符串过滤。
- 过滤规则只匹配小写 `s:` 或只检查字面量，没有规范化序列化格式。
- 存在可利用的魔术方法链（`__destruct`/`__toString`/`__wakeup` 等）与文件读取/命令执行 sink。
- 目标类在允许列表中，或类名过滤可被绕过。

## 利用步骤

1. 审计源码，找到 `unserialize` 入口与过滤正则；确认 `s:` 规则只匹配小写，类名规则允许 `Welcome`、`Profile`、`FileViewer`。
2. 找 sink：`FileViewer::__toString()` 的 `file_get_contents($path)`；找触发点：`Welcome::__destruct()` 的字符串拼接。
3. 构造对象链：`Welcome.user = FileViewer(path=...)`。
4. 用大写 `S` 与十六进制转义隐藏敏感路径：`/flag` 写成 `/\66lag`，长度按解码后 5 字节写 `S:5:`。
5. 提交 payload：`O:7:"Welcome":1:{s:4:"user";O:10:"FileViewer":1:{s:4:"path";S:5:"/\66lag";}}`。
6. 反序列化后对象被置空/脚本结束触发 `__destruct`，`__toString` 读取文件并输出。

## PoC

```text
O:7:"Welcome":1:{s:4:"user";O:10:"FileViewer":1:{s:4:"path";S:5:"/\66lag";}}
```

过滤规则（存在缺陷）：

```php
$rules = [
    '/s:\d+:"[^"]*flag[^"]*"/' => '拦截：检测到 flag 路径 (s:string)',
    '/O:\d+:"(?!Welcome|Profile|FileViewer)[^"]+"/' => '拦截：不允许的类',
];
```

原文提交上述 payload 后成功读取 `/flag`；未在本机复跑。

## 变体与关联

- **等价写法变体**：大写 `S`、`C:` 自定义序列化、`R:`/`r:` 引用、对象属性名转义、长度前导零/加号等；任何“正则匹配序列化文本”的过滤器都可能被绕过。
- **魔术方法变体**：`__destruct`/`__toString`/`__wakeup`/`__call` 触发文件读取、SSRF、命令执行。
- **过滤绕过变体**：大小写、注释、空白、编码、分段拼接、`S` 转义、`O` 类名大小写。
- **关联**：[[web-php-deserialization-*]] 系列 POP 链卡；本卡重点是“过滤器只匹配小写 s”的解析差异。

## 检测与防御

- 不要对序列化文本做正则黑名单；使用 `unserialize($data, ['allowed_classes' => [...]])` 限制可实例化类，或改用 JSON。
- 对敏感字符串做解码后的语义校验，而不是只看原始文本；对序列化结构做解析与规范化。
- 移除不必要的魔术方法 sink；文件读取路径使用白名单与 `realpath` 校验。
- 检测：请求体出现大写 `S:`、`\xx` 转义、长度与内容不一致的序列化串；反序列化后出现文件读取或异常对象链。
