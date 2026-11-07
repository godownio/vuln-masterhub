---
id: ai-security-agent-security-ios-siri-hidden-album-cache-faceid-bypass
title: iOS 隐藏相册 Face ID 绕过：锁屏 Siri 把已缓存私密照片作为附件发给 ChatGPT
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: ios-lockscreen-siri-hidden-album-cache-bypass
tags:
- ai-security
- agent-security
- ios
- siri
- mobile-assistant
- privacy
- faceid-bypass
- chatgpt
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V163
  verified_at: '2026-11-06T13:30:02+08:00'
  notes: 已对照原文与图 03（HIDDEN PHOTO 缩略图、Use Face ID to View This Item）、图 02 核对：隐藏相册缓存 + 锁屏 Siri 发送给 ChatGPT 的机制与演示一致；原文为 DEFCON33 议题摘要，未给 iOS 版本，未在本机复现
url: /docs/ai-security/agent-security/ai-security-agent-security-ios-siri-hidden-album-cache-faceid-bypass/
draft: false
kb_aliases:
- Siri 隐藏相册越权
- 私密相册 Face ID 绕过
- 锁屏 Siri 读取隐藏照片
- Siri 发送缓存照片给 ChatGPT
- iOS 隐私相册缓存泄露
---

## 一句话结论

iOS 的“隐藏相册”在用户通过 Face ID 查看后会把照片数据留在缓存中；设备锁屏时，Siri 的“把这张照片发给 ChatGPT”意图仍能拿到该缓存照片作为附件，绕过 Photos 界面的 Face ID 二次验证，导致物理接触者在不知道锁屏密码的情况下外泄私密照片。

## 原理

- **缓存与权限分离**：Photos 的隐藏相册在 UI 层要求 Face ID/Touch ID 才能进入，但成功验证后照片的解密数据/缩略图会进入系统缓存；退出相册或锁屏并不会立即清除缓存。
- **Siri 是系统级助手**：Siri 运行在比普通 App 更高的系统权限上下文，其照片选择/分享意图直接向 Photos 服务取资源。锁屏限制主要作用于 UI 呈现和 App 启动，并不等价于对每个 Siri intent 重新做生物认证。
- **意图链绕过**：用户说“Ask ChatGPT what's in this photo”或“Send this photo to ChatGPT”，Siri 弹出分享确认框并显示照片缩略图（示例中为 HIDDEN PHOTO），此时照片已被选中为附件；确认发送即把私密照片交给 ChatGPT，整个过程没有触发 Face ID。
- **为什么成立**：安全边界被假设在“Photos App 的界面”上，而 Siri 走的是系统照片服务 API；只要缓存存在且 Siri 在锁屏可用，界面层的 Face ID 就不是强制门禁。

## 触发条件

- iOS 设备启用了 Siri，且“锁屏时允许使用 Siri”（Allow Siri When Locked）处于开启状态。
- 设备安装了 ChatGPT App 并启用 Siri 集成/快捷指令，或 Siri 具备照片分享能力。
- 隐藏相册中的照片在近期被解锁查看过，缓存尚未被系统清理。
- 攻击者取得设备物理接触（锁屏状态即可），并能让 Siri 执行照片分享意图；不需要锁屏密码。
- 目标 iOS 版本存在该权限门禁缺失（原文未给出具体版本区间）。

## 利用步骤

1. 受害者正常解锁并查看隐藏相册中的私密照片，随后退出相册并锁屏；照片数据留在缓存。
2. 攻击者拿起已锁屏的设备，长按侧边按钮/说“Hey Siri”唤醒助手。
3. 对 Siri 说“Ask ChatGPT what's in this photo”或“Send this photo to ChatGPT”。
4. Siri 弹出分享确认框，缩略图显示隐藏相册照片；界面仍提示“Use Face ID to View This Item”，但附件已可选。
5. 点击 Send，照片被发送到 ChatGPT；攻击者可在对话中查看/继续转发，完成隐私外泄。
6. 变体：让 Siri 把照片加入备忘录/邮件/信息，或先发送到攻击者可控账号；也可用快捷指令自动化同样的照片读取。

## PoC

无代码 PoC。语音/操作序列（原文演示）：

```text
1. 解锁手机 -> 打开“隐藏相册” -> 查看目标照片 -> 退出并锁屏
2. 锁屏状态唤醒 Siri
3. 说：“Hey Siri, ask ChatGPT what's in this photo”
4. Siri 弹出 “Send this photo to ChatGPT?” 并显示隐藏照片缩略图
5. 点 “Send” -> 照片进入 ChatGPT 对话
```

前置条件与系统版本依目标设备而定；本卡不执行任何操作。

## 变体与关联

- **分享目标变体**：ChatGPT、信息、邮件、备忘录、第三方快捷指令；凡是 Siri 能调用的照片分享出口都可尝试。
- **缓存载体变体**：最近删除、隐藏相册、第三方私密相册 App 的预览缓存；关键在“验证后是否留下可被系统助手读取的副本”。
- **关联**：[[ai-security-agent-security-ios-lockscreen-siri-context-leak]]（同一类锁屏 Siri 越权，读取 ChatGPT 记忆与页面链接）、[[ai-security-prompt-injection-multimodal-image-instruction-smuggling]]（图片进入模型后的指令风险）。
- **边界**：若设备关闭锁屏 Siri、禁用照片分享意图、系统在锁屏时清除缓存或在 Siri intent 上强制 Face ID，利用失败；不同 iOS 版本行为可能已修复。

## 检测与防御

- **设备侧**：关闭“锁屏时允许使用 Siri”；对照片分享类快捷指令要求解锁后运行；敏感相册使用独立加密 App 并在锁屏时清除预览缓存。
- **系统/App 侧**：Siri intent 处理敏感资源前强制生物认证，不能只依赖 App UI 的门禁；锁屏状态下对照片、文件、剪贴板等资源统一做权限降级。
- **检测**：锁屏状态下出现照片分享/Siri 照片选择事件；Siri 在设备锁定后短时间内访问隐藏相册资源；异常的照片外发（ChatGPT/信息/邮件）行为。
- **响应**：更新到修复版本；审计 Siri 快捷指令与照片权限；对已泄露照片评估二次传播风险。
