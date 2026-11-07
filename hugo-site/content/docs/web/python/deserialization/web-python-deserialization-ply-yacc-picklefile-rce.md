---
id: web-python-deserialization-ply-yacc-picklefile-rce
title: PLY yacc 未文档化 picklefile 参数直接 pickle.load：文件路径可控即反序列化 RCE（CVE-2025-56005）
type: scenario
domain: web
path: web/python/deserialization
technique: ply-yacc-undocumented-picklefile-unsafe-deserialization
tags:
- python
- ply
- yacc
- pickle
- deserialization
- undocumented-parameter
- rce
cve:
- CVE-2025-56005
severity: critical
confidence: medium
affected_versions: PLY 3.11（原文审计版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T08:47:28+08:00'
  notes: 已对照原文与01.jpg核对：yacc() 签名含未文档化 picklefile，分支内 open+pickle.load+return 与原文一致；read_pickle 首处 tabversion pickle.load 及后续多点 load 与截图一致；CVE-2025-56005 与原文标题一致。未验证点：原文无端到端应用调用与完整 payload，卡片 PoC 已标注非原文；实际可利用性依赖应用是否将可控路径传入 picklefile/read_pickle，PoC 未本机执行；frontmatter 无 sources/source_url。
url: /docs/web/python/deserialization/web-python-deserialization-ply-yacc-picklefile-rce/
draft: false
kb_aliases:
- CVE-2025-56005
- PLY picklefile 参数
- yacc pickle.load RCE
- Python Lex-Yacc 反序列化
- read_pickle 不安全反序列化
- 未文档化参数后门
---

## 一句话结论

PLY（Python Lex-Yacc）3.11 的 `yacc()` 暴露了一个官方文档未披露的 `picklefile` 参数：只要该参数非空，代码就 `open(picklefile, 'rb')` 后直接 `pickle.load()` 并 `return`，在版本校验与 parser 初始化之前完成反序列化；若应用把攻击者可控的路径/文件传给该参数，攻击者即可用恶意 pickle 在导入阶段执行任意代码（CVE-2025-56005）。

## 原理

- **未文档化参数进入安全边界**：`yacc()` 的函数签名包含 `picklefile=None`，但该参数未出现在 PLY 官方文档中；API 使用者难以意识到传入此参数等于把文件内容交给 `pickle.load`。
- **裸 `pickle.load()` 在一切校验之前**：只要 `picklefile` 非空，就进入如下分支：

  ```python
  if picklefile:
      try:
          import pickle
          f = open(picklefile, 'rb')
          parsetab = pickle.load(f)
          f.close()
          return parsetab
      except Exception:
          pass
  ```

  代码先 `open` 并 `pickle.load`，之后才可能做 tabversion 检查；payload 在第一次 `pickle.load` 时已经执行，后续校验即使失败也无法回滚。
- **`read_pickle()` 也是多点 load**：源码审计截图中 `read_pickle(self, filename)` 会依次 `pickle.load(in_f)` 读取 `tabversion`、`self.lr_method`、`signature`、`self.lr_action`、`self.lr_goto`、`productions`，第一处 `pickle.load`（读取 tabversion）就发生在任何版本比较之前，后续每一次 load 也都是独立的反序列化执行点。
- **pickle 不是数据格式而是对象重建**：`pickle.load` 会依据字节流调用任意可导入 callable，典型地通过 `__reduce__()` 返回 `(callable, args)`；因此恶意 pickle 可在反序列化阶段执行 `os.system("whoami")` 等命令，不需要 parser 真正被使用。
- **逻辑短路降低可见性**：`return parsetab` 跳过后续所有初始化与校验；`except Exception: pass` 吞掉异常且无日志，使失败与攻击行为都难以在运行期被发现。
- **前提条件**：漏洞本身是“危险 API / 不安全反序列化 sink”；要形成实际 RCE，调用方必须把攻击者可控的 `picklefile` 值（或攻击者可写入/覆盖的 pickle 文件路径）传给 `yacc()`/`read_pickle()`，并且该文件内容可控。

## 触发条件

- 目标应用使用 PLY 3.11（或包含同款 `picklefile`/`read_pickle` 代码的版本）。
- 应用调用 `yacc()` 时把外部可控值传给 `picklefile` 参数，或调用内部 `read_pickle()` 且文件名可控。
- 攻击者可提供/覆盖该路径指向的 pickle 文件（例如上传、共享目录、可写缓存目录），或路径本身指向攻击者控制的位置。
- Python 进程对该文件有读权限；`pickle` 模块可用（标准库，默认可用）。
- 应用未对 `picklefile` 路径做白名单/来源校验，也未禁用 `pickle`。

## 利用步骤

1. 审计应用中对 `ply.yacc.yacc(...)` 的调用，确认是否存在 `picklefile=` 参数，以及该值是否来自请求参数、配置、上传文件名、缓存路径等外部输入。
2. 若存在可控路径，确认攻击者能否把恶意 pickle 放到该路径（上传、写共享目录、覆盖已有 parse table 等）。
3. 生成恶意 pickle：用 `__reduce__` 指定可执行 callable 与参数（例如 `os.system`）。
4. 让应用以该文件作为 `picklefile` 调用 `yacc()`；`pickle.load` 执行 payload。
5. 观察命令执行结果/回连；由于异常被 `except Exception: pass` 吞掉，命令执行成功时应用可能仍正常返回 parse table 或继续后续逻辑。
6. 若只能控制 `read_pickle()` 的文件名，同理利用其第一次 `pickle.load`（tabversion 读取点）。

## PoC

原文只给出概念性 payload（反序列化阶段执行 `os.system("whoami")`），未给出完整文件与调用代码。按同一 sink 可构造的最小验证如下（非原文，属 pickle 标准利用方式）：

```python
# 攻击者侧：生成恶意 pickle 文件
import pickle, os

class Evil:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

with open('/tmp/evil.pkl', 'wb') as f:
    f.write(pickle.dumps(Evil()))

# 受害应用侧（存在可控 picklefile 时）
import ply.yacc as yacc
yacc.yacc(picklefile='/tmp/evil.pkl')   # 进入 if picklefile 分支，pickle.load 触发命令执行
```

原文未提供端到端应用调用示例，实际可利用性取决于应用是否把外部输入传给 `picklefile`/`read_pickle`，故 confidence 标 medium。

## 变体与关联

- **其他未文档化参数**：库函数签名中未公开但可用的参数（调试、缓存、反序列化路径）常被审计忽略，可作为“隐藏攻击面”排查清单。
- **pickle 缓存文件投毒**：若应用把可写目录中的 parse table/pickle 缓存路径传给 `picklefile`，攻击者可通过文件写入或竞争覆盖实现 RCE，无需直接控制参数值。
- **同族 sink**：`pickle.load/loads`、`cPickle`、`shelve`、`pandas.read_pickle`、`joblib.load`、`torch.load`（默认 pickle）等均属同一不安全反序列化面。
- **关联卡片**：[[web-python-deserialization-pickle-codetype-function-hijack]]（pickle `__reduce__`/CodeType 构造与 WAF 绕过）、[[web-python-deserialization-django-file-cache-pickle-rce]]（缓存文件投毒触发 pickle）、[[web-python-deserialization-pickle-self-secret-signature-bypass]]（签名不能阻止 pickle 执行）。

## 检测与防御

- **调用侧**：全量搜索 `yacc(`, `picklefile=`, `read_pickle(`；禁止把请求参数、文件名、配置项直接传给 `picklefile`；如无必要不要启用该参数。
- **代码加固**：在 `yacc()` 入口对 `picklefile is not None` 直接抛异常（原文建议），或删除该参数；必须反序列化时使用自定义 `Unpickler` 并重写 `find_class` 做类白名单，且只允许安全类型。
- **格式替换**：缓存/表数据改用 JSON、MessagePack 等无代码执行语义的格式；不要对不可信文件使用 `pickle`/`cPickle`。
- **运行环境**：限制应用对可写目录的权限，禁止上传目录与 pickle 缓存目录重合；用 seccomp/容器限制意外命令执行的影响。
- **检测**：审计日志中出现 `yacc` 相关异常被静默吞掉、parse table 文件被外部修改；监控进程在导入/初始化阶段产生 `os.system`/`subprocess` 类子进程；检查 pickle 文件魔数（`\x80\x04`/`\x80\x05` 等）出现在非预期目录。
