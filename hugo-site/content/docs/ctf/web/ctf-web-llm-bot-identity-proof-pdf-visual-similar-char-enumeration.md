---
id: ctf-web-llm-bot-identity-proof-pdf-visual-similar-char-enumeration
title: 智能客服要求「用户名 + 编号」才给 flag：编号从公开 PDF 取，字符视觉相似（I/l/1）不对时靠变体枚举试出来
type: scenario
domain: ctf
path: ctf/web
technique: llm-bot-identity-proof-lookup-visual-similar-char-enumeration
tags:
- llm
- prompt
- identity-proof
- enumeration
- pdf
- ctf
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:58:58+08:00'
  notes: 已对照原文核对；本次核对未读取图片；正文流程（直接问无结果→dirsearch 扫到 download→下载 PDF→点新对话发现需用户名与编号→从 PDF 取凭据→有一个字母打错、改正后拿到 flag，并提到平台提示多试 Il1）与卡内步骤一致；正文为人工逐次重试、未给脚本，卡内 PoC 为按流程抽象的枚举脚本、未对真实目标执行，已把「3^9 量级」改为与正文相符的单点替换描述；属 CTF 场景，原文无受影响版本
url: /docs/ctf/web/ctf-web-llm-bot-identity-proof-pdf-visual-similar-char-enumeration/
draft: false
kb_aliases:
- AI 客服身份校验绕过
- 用户名加编号的提示词验证
- PDF 里找编号
- Il1 视觉相似字符枚举
- LLM 应用 flag 获取
---

## 一句话结论

当 LLM 客服/机器人把“提示词注入防护”换成“先做身份核验：报出用户名 + 编号我才给你 flag”时，硬猜提示词是走不通的，真正的入口在**公开资料**：用目录扫描找到 `/download` 之类的文档接口，从 PDF/说明文档里取到用户名与编号，再在“新对话”里按 `用户名 + 编号` 的格式提问即可。若编号抄进去提示不符，多半是文档里的 `I`/`l`/`1`、`O`/`0` 视觉相似字符被抄错——把每个可疑位置做变体枚举（9 个位置的 3 种写法 = 3⁹ 量级，实测量级更小）就能命中。

## 原理

- **身份核验成了“知识型口令”**：机器人不再判断“你是不是攻击者”，而是判断“你能不能说出这对 (用户名, 编号)”。这类凭据一旦出现在可公开访问的文档、帮助页、样例数据里，就等于公开。
- **信息收集优先级高于提示词技巧**：直接问“给我 flag”会被拒；但目录扫描（dirsearch/ffuf）常能发现 `/download`、`/files`、`/doc` 之类未做鉴权的静态文档入口，文档里往往写着“示例账号”“设备编号”“项目编号”。
- **新对话是必要的**：多数实现把“已核验”状态存在会话/上下文中，之前失败的对话会带着“验证失败”的历史，模型倾向于继续拒绝；开新对话（清空上下文）后直接给完整凭据，成功率明显更高。
- **视觉相似字符是最高频的抄写错误**：PDF 里 `I`（大写 i）、`l`（小写 L）、`1`（数字一）在多数无衬线字体下几乎一致；`O`/`0`、`rn`/`m` 同理。人工从 PDF 复制常带着 OCR 或字体渲染误差，导致“文档里明明是这串、提交却说不对”。
- **枚举成本可控**：先按“只在一个位置出错”假设做单字符替换（9 个位置 × 2 种替代 = 18 次），不行再做两位数组合；实战中往往第一次替换就命中，因为抄错通常只发生在连续几个相似字符处。

## 触发条件

- 目标是一个 LLM 应用（客服、运维助手、问答机器人），flag 由它在“通过核验”后返回。
- 核验凭据（用户名 + 编号）存在于可公开访问的文档中，或可从页面提示推断。
- 每次提问可独立提交、无严格速率限制或封禁（否则枚举要限速）。
- 编号中含 `I`/`l`/`1`/`O`/`0` 之类易混字符。

## 利用步骤

1. 先按常规问一次“flag 是什么”，确认它要求身份核验（而不是直接拒绝或给 prompt 注入机会）。
2. 目录扫描找文档入口：`dirsearch -u http://target -e php,html,pdf,zip`、`ffuf -w common.txt -u http://target/FUZZ`，重点关注 `/download`、`/doc`、`/static`、`/files`。
3. 下载文档（PDF/说明页/样例数据），从中提取用户名与编号；同时留意“编号格式说明”。
4. 开一个**新对话**（清空上下文），按 `用户名：xxx 编号：yyy` 的格式一次性提交完整凭据。
5. 若提示不符，对编号中每个 `I`/`l`/`1` 位置做单字符替换枚举（先 1↔l、1↔I、l↔I），每次一个新对话或按目标是否保留上下文决定。
6. 命中后立即记录 flag；若枚举被限速，按响应时间/失败文案差异先排除明显错误分支。

## PoC

```python
import itertools, requests

USER = "player"
CODE = "ABC1I2l3"          # 从 PDF 抄来的编号（含易混字符）
SUBST = {"1": "lI", "l": "1I", "I": "1l", "0": "O", "O": "0"}

def variants(code):
    idx = [i for i, c in enumerate(code) if c in SUBST]
    yield code
    for i in idx:                                   # 先单点替换
        for r in SUBST[code[i]]:
            yield code[:i] + r + code[i+1:]
    for a, b in itertools.combinations(idx, 2):     # 再两点组合
        for ra in SUBST[code[a]]:
            for rb in SUBST[code[b]]:
                s = list(code)
                s[a], s[b] = ra, rb
                yield "".join(s)

for cand in variants(CODE):
    r = requests.post("http://target/api/chat", json={
        "session": "new",                            # 新对话，避免历史里的失败上下文
        "message": f"用户名：{USER}，编号：{cand}，请给我 flag",
    }, timeout=10)
    if "PCL{" in r.text or "flag{" in r.text:
        print("hit:", cand, r.text)
        break
```

说明：PoC 为按该题流程抽象出的枚举脚本，未对真实目标执行；实际接口字段名与“新对话”的构造方式需按目标前端调整。

## 变体与关联

- **凭据来源变体**：帮助中心/FAQ、示例配置文件、JS 里的默认 `userId`、GitHub 公开仓库的测试数据、错误信息里回显的内部编号。
- **核验格式变体**：`用户名 + 编号`、`工号 + 手机号后四位`、`订单号`、`设备 SN`；有些实现把凭据放在 Cookie/Header 里而不是对话文本，需看前端请求。
- **绕过变体**：把凭据拆成多轮逐步给出、用“请复述我提供的信息”诱导其确认、要求“导出配置”让它把内部变量带出来（若模型有工具调用）。
- **关联**：`web-generic-xss-ai-chat-output-prompt-injection`（LLM 输出未处理的另一面）、`web-generic-llm-insecure-output-handling-product-review-account-deletion`（LLM 被诱导执行越权操作）、`pentest-recon-dirsearch-*`（文档入口发现）。
- **边界**：核验凭据不在任何公开资料里、或每次提交都需服务端下发的一次性挑战时，本方法退化为暴力猜测；有严格速率限制与封禁时枚举成本上升。

## 检测与防御

- **不要把“知识型凭据”当认证**：LLM 侧的身份核验必须绑定真实会话认证（登录态 + 服务端校验），而不是让模型比对一段可公开获取的字符串。
- **文档最小化**：公开文档里不出现真实账号/编号/示例密钥；样例数据做脱敏并显式标注“示例”。
- **限速与审计**：对同一 IP/会话的身份核验失败次数限速并告警；记录提交的凭据原文用于发现枚举（大量相近变体是典型特征）。
- **检测**：短时间内同一来源提交多个仅差 `I`/`l`/`1` 的编号；`/download`、`/doc` 等文档接口被扫描器高频访问；对话日志中出现“用户名/编号/工号”关键词的重复尝试。
