---
id: ai-security-agent-security-ios-lockscreen-siri-context-leak
title: iOS 锁屏 Siri 上下文越权：读取 ChatGPT 记忆、当前聊天分享链接与 Safari 页面 URL
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: ios-lockscreen-siri-context-overprivilege
aliases:
- 锁屏 Siri 读取 ChatGPT 记忆
- Siri 越权读取聊天记录链接
- Siri 泄露当前网页 URL
- iOS 锁屏助手上下文泄露
- Siri 提醒事项抓取当前页面
tags:
- ai-security
- agent-security
- ios
- siri
- chatgpt-memory
- privacy
- lockscreen
- url-leak
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T14:00:23+08:00'
  notes: 已对照原文与图 04（what did we chat about 读出记忆细节）、图 05（ChatGPT 会话加入提醒）、图 06（defcon.org 加入提醒，背景有 Netflix 播放窗口）核对；原文未给 iOS 版本，未在本机复现
---

## 一句话结论

iOS 锁屏限制只约束 App 界面，不约束 Siri 对当前上下文的读取：锁屏时对 Siri 说“what did we chat about”可读出 ChatGPT 的个性化记忆；“add this page to reminders”会把当前 ChatGPT 聊天或 Safari 页面的标题与 URL 写进提醒事项，攻击者据此取得私密聊天分享链接或正在浏览的网址。

## 原理

- **助手权限高于锁屏 UI**：Siri 作为系统级 AI 助手，可以查询 App 暴露的 Siri/快捷指令接口、读取当前前台/最近页面的上下文，并把结果写入提醒事项等系统数据。锁屏只阻止用户直接打开 App，不阻止这些 intent。
- **ChatGPT 记忆是跨会话敏感数据**：ChatGPT 的“记忆/关于你”保存昵称、职业、兴趣、健康与生活细节；Siri 的“what did we chat about”会把这些内容朗读/展示出来，锁屏时无需解锁即可获取。
- **当前页面上下文被抓取**：Siri 的“将此页面加入提醒事项”会取当前页面标题和 URL 作为提醒内容/链接。ChatGPT 网页版聊天的 URL 往往包含可分享的会话标识；Safari 则直接泄露用户正在浏览的网址（原文示例为 DEF CON 官网；截图背景另有 Netflix 播放窗口，但提醒事项中只显示 defcon.org）。
- **为什么成立**：敏感上下文存在于 App 内部状态，而 Siri 的 intent 在系统层执行，锁屏状态没有对“读取当前上下文/写入提醒”这类动作做统一授权检查，形成 UI 门禁之外的旁路。

## 触发条件

- 设备锁屏，且“锁屏时允许使用 Siri”开启。
- ChatGPT App 已登录并启用个性化记忆，或 ChatGPT 聊天页面/Safari 页面处于最近/当前上下文。
- Siri 可访问提醒事项（默认开启），且用户未对 Siri 的 App 上下文访问做限制。
- 攻击者取得设备物理接触，能在锁屏状态唤醒 Siri；不需要锁屏密码。
- 目标 iOS 版本存在该权限门禁缺失（原文未给出具体版本区间）。

## 利用步骤

1. 受害者在手机上使用 ChatGPT，开启记忆并留下含个人信息的对话；或保持某个 ChatGPT 聊天/Safari 页面为最近页面。
2. 受害者锁屏，设备留在攻击者可接触的位置。
3. 攻击者唤醒 Siri，说“Hey Siri, what did we chat about?”；Siri 读出 ChatGPT 记忆中的姓名、年龄、职业、健康状况等。
4. 或者攻击者说“Hey Siri, add this page to reminders”；Siri 把当前 ChatGPT 聊天标题与 `chatgpt.com` 链接写入提醒事项。
5. 攻击者打开提醒事项查看该条提醒，取得聊天分享链接/页面 URL；若链接可公开访问，即可在另一设备打开私密对话。
6. 对 Safari 重复第 4 步，可直接得到受害者当前浏览的网页地址（原文演示泄露 `defcon.org`，图中背景另有 Netflix 播放窗口）。
7. 变体：让 Siri 朗读/总结当前页面、把页面加入备忘录或发送给攻击者可控的分享目标。

## PoC

无代码 PoC。语音/操作序列（原文演示）：

```text
# 读取 ChatGPT 记忆
锁屏 -> “Hey Siri, what did we chat about?”
-> Siri 读出记忆：年龄、出生地、大学、兴趣、家庭成员、疾病与保险申请等

# 抓取当前 ChatGPT 会话链接
保持 ChatGPT 聊天页面为最近页面 -> 锁屏
-> “Hey Siri, add this page to reminders”
-> 提醒事项出现该聊天标题 + chatgpt.com 链接

# 抓取当前网页 URL
保持 Safari 页面（如 defcon.org）-> 锁屏
-> “Hey Siri, add this webpage to my reminders”
-> 提醒事项出现页面标题 + 网址
```

前置条件与系统版本依目标设备而定；本卡不执行任何操作。

## 变体与关联

- **读取目标变体**：ChatGPT 记忆、最近聊天标题、当前网页 URL、Safari 阅读列表、剪贴板内容（若 Siri intent 可读）。
- **写入载体变体**：提醒事项、备忘录、日历、信息草稿；凡是 Siri 能把上下文写进去的地方都可作为外带通道。
- **关联**：[[ai-security-agent-security-ios-siri-hidden-album-cache-faceid-bypass]]（同一类锁屏 Siri 越权，绕过隐藏相册 Face ID）、[[ai-security-agent-security-spaiware-chatgpt-memory-poisoning-persistent-exfil]]（ChatGPT 记忆作为攻击面）。
- **边界**：关闭锁屏 Siri、禁用 ChatGPT 记忆、系统在锁屏时对 Siri 上下文访问做解锁校验，或聊天链接需要登录/已失效时，利用受限。

## 检测与防御

- **设备侧**：关闭“锁屏时允许使用 Siri”；对包含个人信息的 App 启用应用级锁；定期清理 ChatGPT 记忆与敏感对话；不使用可公开分享的聊天链接。
- **系统/App 侧**：锁屏状态下对“读取当前页面上下文/写入提醒”类 Siri intent 强制解锁；对 URL、页面标题做脱敏或仅保存域名；ChatGPT 等 App 应对 Siri 查询记忆的接口做认证。
- **检测**：锁屏后出现 Siri 读取 ChatGPT 记忆/当前页面的 intent 日志；提醒事项中突然出现含会话 URL 的条目；Siri 在锁屏状态访问敏感 App 上下文。
- **响应**：更新到修复版本；检查并删除异常提醒事项；轮换已泄露的聊天分享链接；评估记忆中的敏感信息是否需要清理。
