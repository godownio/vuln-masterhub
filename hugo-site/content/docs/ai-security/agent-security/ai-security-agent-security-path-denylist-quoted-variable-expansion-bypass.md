---
id: ai-security-agent-security-path-denylist-quoted-variable-expansion-bypass
title: Agent 宿主沙箱的路径黑名单被引号路径与变量展开绕过
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: path-denylist-shell-parsing-bypass
tags:
- llm
- agent
- sandbox
- access-control
- shell
- bypass
- file-read
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:28:25+08:00'
  notes: 已对照原文与全部 29 张图核对：机制层只按字面路径匹配，带引号路径与变量展开可绕过（原文两处真实绕过），内联 Python 为早期版本另一入口；修复后 29 条路径/写法穷举全部拒绝的截图（img29）与正文一致；卡片为通用实现绕过模式、无产品版本，未复跑
url: /docs/ai-security/agent-security/ai-security-agent-security-path-denylist-quoted-variable-expansion-bypass/
draft: false
kb_aliases:
- 引号路径绕过沙箱
- 变量展开绕过路径黑名单
- 路径字面匹配绕过
- sandbox deny list bypass
- shell parsing path confusion
---

## 一句话结论

当 Agent 宿主的受保护文件拒绝逻辑按"命令字符串里的字面路径"匹配时，`cat "/srv/data/customers_export.csv"` 这样的带引号路径、或 `T=/srv/data/customers_export.csv; cat $T` 这样的变量展开不会命中黑名单，受保护文件仍可被读取；只有按 shell 解析后的真实路径、在唯一的读取汇聚点统一判定，才能堵住这一类绕过。

## 原理

LLM Agent 的 shell 工具通常接收一条命令字符串。若宿主的安全层只做字符串层面的前缀/子串匹配（例如检查 `cmd` 中是否出现 `/srv/data/`），它检查的是**命令原文**，而实际执行的是 shell **解析后的 argv**。shell 会在执行前去掉引号、展开变量、处理重定向与 fd 操作，因此同一个目标路径可以有多种原文写法：

- `cat /srv/data/x.csv`：字面命中黑名单，被拒绝；
- `cat "/srv/data/x.csv"`：原文中路径被引号分隔，按字面匹配可能不命中，但 shell 解析后仍是同一文件；
- `T=/srv/data/x.csv; cat "$T"`：原文里没有完整路径字面量，变量在运行时展开为受保护路径。

同理，若强制层只在 shell 和 read_file 两个入口实现，而内联 Python（`python3 -c "open('/srv/data/...')"`）走的是另一条路径，攻击者可以自行发现并利用这个缺口。原文指出：强制必须在**每个读取都会经过的唯一判定点**上集中实现，而不是按入口重复实现。

## 触发条件

- Agent 宿主对文件读取实施路径黑名单/前缀拒绝，且判定基于命令字符串或未解析的路径；
- Agent 具备 shell 执行或内联代码执行工具，并能读取受保护目录中的文件名（目录列举、配置、报错等）；
- 受保护路径在操作系统层面对该进程可读（即宿主只依赖应用层拒绝，没有 OS 权限隔离）；
- 强制逻辑分散在多个入口，存在未覆盖的读取通道。

## 利用步骤

1. 通过目录列举、配置文件或错误信息确认目标文件路径，例如 `/srv/data/customers_export.csv`。
2. 先用字面路径测试，确认宿主拒绝：`cat /srv/data/customers_export.csv` 返回 `PERMISSION DENIED`。
3. 改用等价但原文不同的写法，观察是否仍被拒绝：
   - 带引号：`cat "/srv/data/customers_export.csv"`
   - 变量展开：`T=/srv/data/customers_export.csv; cat "$T"`
   - 重定向/fd：`exec 3< /srv/data/customers_export.csv; cat <&3`
   - 内联 Python：`python3 -c "print(open('/srv/data/customers_export.csv').read())"`
4. 以工具返回的实际文件内容确认是否读取成功；不要以模型自述或命令退出码单独判断。
5. 若某一写法被拒绝，换用 base64、gzip、xxd、dd、tar、strings 等消费端变体，测试判定层是否只覆盖了部分命令。

## PoC

最小对照（在"仅按字面路径拒绝"的宿主上）：

```bash
# 被拦截
cat /srv/data/customers_export.csv

# 引号路径：原文不含连续的保护路径字面量
cat "/srv/data/customers_export.csv"

# 变量展开：运行时才还原真实路径
T=/srv/data/customers_export.csv; cat "$T"

# 内联 Python：绕开 shell 工具的独立入口
python3 -c "print(open('/srv/data/customers_export.csv').read())"
```

期望结果：修复前，后三条可读到受保护文件；修复后，宿主对全部写法返回统一拒绝，例如：

```text
PERMISSION DENIED: this principal is not authorised for the requested resource (/srv/data/customers_export.csv)
```

原文在修复后还主动穷举了 29 条路径/写法（cut、grep、base64、xxd、dd、gzip、wc、strings、重定向、fd 3<、mapfile、read、source、`../`、`./`、python open、builtins、io.open、tarfile 等），全部返回拒绝。

## 变体与关联

- 路径规范化变体：`/srv/data/../data/x.csv`、`./`、重复斜杠、符号链接、大小写（大小写不敏感文件系统）都可能让字面匹配失效；符号链接需要在 `resolve()` 后判断真实路径。
- 解释器变体：shell 之外还有 Python `open`、`io.open`、`tarfile`、`subprocess` 等读取通道；只拦截 shell 等于没拦住。
- 与文件名消费工具结合：`base64`、`xxd`、`dd`、`gzip` 等不改变"读取"本质，只是改变输出形式；判定层若只匹配 `cat` 会漏。
- 关联：路径穿越、符号链接逃逸、TOCTOU、命令注入、Agent 工具调用越权。

## 检测与防御

- 集中判定：所有文件读取（shell、文件工具、内联代码执行、归档解包）必须经过同一个 `denies(path)` 判定点；不要在多个入口复制逻辑。
- 按解析结果判定：用 shell 解析器或等价规范化处理引号、变量展开、重定向与 fd，得到真实目标路径后，再做 `normpath` + `realpath`（解析符号链接）检查；仅做字符串前缀匹配必然可绕。
- 白名单优于黑名单：只允许工作区内的路径，比列举受保护路径更稳；对确需保护的目录同时使用 OS 权限、独立用户/容器与只读挂载。
- 测试用例要覆盖绕过语料：带引号、变量、`../`、`./`、fd 重定向、`source`、`mapfile`、解释器直读、归档工具、符号链接；原文在修复后以 29 条路径做回归。
- 日志与检测：记录每次拒绝的真实解析路径、原始命令、工具入口与进程身份；关注"同一路径多次不同写法"的探测序列，以及拒绝后改用解释器/归档工具的切换。
- 局限：应用层强制即使做得再细，也不等于安全边界；原文中仅开启机制层时打穿率仍为 0.70（n=10），文本层与机制层同时开启仍有 0.40，说明必须配合真正的权限隔离。
- 原文的机制层修复属于防御方视角；卡片描述的是该类实现的通用绕过模式，不对应某个有版本号的产品。
