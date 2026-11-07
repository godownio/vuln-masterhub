---
id: ctf-pwn-type-confusion-reclassify-adjacent-oob-perform
title: 只改 kind 不重分配导致类型混淆：chorus 写入越界覆盖相邻 exhibit 的 perform
type: scenario
domain: ctf
path: ctf/pwn
technique: reclassify-type-confusion-adjacent-oob-function-pointer
aliases:
- reclassify 类型混淆
- kind 与对象大小不匹配
- whisper 伪装 chorus
- 相邻堆块越界写
- perform 函数指针覆盖
- Museum of Echoes
tags:
- pwn
- type-confusion
- heap
- oob-write
- function-pointer
- adjacent-chunk
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:47:02+08:00'
  notes: 已对照原文 Museum of Echoes 核对：exhibit 0x30/whisper 0x50/chorus 0xb0 布局、reclassify 只改 kind/room=0x4543484f/perform、rewrite chorus 写 intro(+0x30,31) 与 refrain(+0x50,95)、refrain+0x10 越界到相邻 whisper、payload kind/room/perform 偏移、远程 0x401296/0x4012cb/0x40130d 均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

程序允许 `reclassify` 只改对象的 `kind` 字段、却不按新类型重新分配内存；把一个 0x50 的 whisper 改成 kind=2 的 chorus 后，`rewrite` 会按 chorus 布局从对象 +0x50 写入 95 字节，正好越界覆盖相邻 whisper 的 `kind/room/perform`，把 `perform` 改成隐藏的 `grand_finale` 即可拿 flag。

## 原理

- **对象按 kind 分配不同大小**：`whisper_t` 为 `exhibit_t base`（0x30）+ `line[32]` ≈ 0x50；`chorus_t` 为 base + `intro[32]` + `refrain[96]` ≈ 0xb0；`create` 按 kind 分配正确大小。
- **reclassify 只改判别字段**：`gallery[idx]->kind = kind; room = 0x4543484f; perform = kind==1 ? whisper_perform : chorus_perform;` 没有 `realloc`，对象实际仍是 0x50 的 whisper。
- **rewrite 按 kind 决定写入范围**：kind=2 时执行 `read_blob(intro, 31)`（对象 +0x30）与 `read_blob(refrain, 95)`（对象 +0x50）；第二个写从 0x50 开始，而 malloc(0x50) 相邻 chunk 的用户区间间隔是 0x60，所以 `refrain+0x10` 落到下一个 chunk 的起始。
- **相邻对象字段布局**：第二个 whisper 的 `kind` 在 +0x00、`room` 在 +0x08、`perform` 在 +0x10；越界 payload 用 0x10 填充对齐后依次写 `p32(1)+p32(0)`、`p64(0x4543484f)`、`p64(grand_finale)`。
- **触达隐藏函数**：调用第二个 exhibit 的 perform 时，若 `room == 0x4543484f` 校验通过，就间接调用 `grand_finale` 读 flag。
- **为什么成立**：类型判别与实际内存布局分离，写路径信任 kind；相邻堆块的布局可预测（0x50 chunk 间隔 0x60），一次越界写即可改函数指针。

## 触发条件

- 程序用 `kind`/type 字段决定对象布局和写入长度，但 `reclassify` 不重新分配对象。
- 存在相邻堆块（同 size 连续分配），攻击者可控制分配顺序。
- 目标对象的关键字段（函数指针、magic、类型）位于相邻 chunk 起始附近。
- 程序内有可直接读 flag 的隐藏函数，或可劫持到其他可控 sink。

## 利用步骤

1. 创建两个相邻的同类型对象（示例两个 whisper，slot 0/1），确保堆布局连续。
2. 对第一个对象调用 `reclassify(0, 2)`，把 kind 改成 chorus，但不触发重新分配。
3. 构造越界 payload：0x10 填充到达相邻 chunk 起始，写目标 `kind=1`、`room=0x4543484f`、`perform=grand_finale`。
4. 调用 `rewrite_chorus(0, intro, payload)`，利用 refrain 的 95 字节写覆盖相邻对象。
5. 调用第二个对象的 perform（示例菜单 5，slot 1），`room` 校验通过后跳到 `grand_finale`。
6. 若远程与本地构建不同，先用 `inspect` 泄露 `perform` 指针校准 PIE/函数地址，再按偏移调用。

## PoC

```python
create_whisper(0, b'A' * 0x1f)
create_whisper(1, b'B' * 0x1f)

reclassify(0, 2)                       # kind 改成 chorus，对象仍是 0x50

payload  = b'Q' * 0x10                 # 到达相邻 chunk 起始
payload += p32(1) + p32(0)             # target->kind = 1
payload += p64(0x4543484f)             # target->room = "ECHO"
payload += p64(GRAND_FINALE)           # target->perform
rewrite_chorus(0, b'C' * 0x1f, payload.ljust(0x5f, b'R'))

choose(5)                              # perform slot 1 -> grand_finale
```

原文实测：远程无 PIE，`whisper_perform=0x401296`、`chorus_perform=0x4012cb`，按函数边界校准后 `grand_finale=0x40130d`，触发后输出 flag。

## 变体与关联

- **类型混淆变体**：只改 kind/type、union 共用体、子类/父类大小不一致、反序列化按声明类型分配。
- **越界写变体**：按新类型长度写、相邻 chunk 间隔 0x60、refrain/intro 偏移、堆喷调整布局。
- **函数指针变体**：perform 回调、vtable、函数表、GOT（Full RELRO 时不可用）。
- **关联卡片**：[[ctf-pwn-negative-index-hidden-slot-encoded-fptr]]（同篇越界/隐藏函数）、[[ctf-pwn-custom-freelist-uaf-unchecked-next-arbitrary-alloc-function-table]]（函数表劫持）、[[binary-pwn-heap-cgi-vpn-strcpy-custom-ptr-callback-hijack]]（回调指针覆盖）。
- **边界**：若 reclassify 会重新分配/拷贝、或写入前校验对象大小，越界不成立；若相邻布局不可控，需堆喷/调整分配顺序。

## 检测与防御

- **CTF 验证**：先泄露 perform 指针确认 PIE/函数边界；覆盖后调用目标对象验证跳转。
- **代码修复**：reclassify 必须按新类型重新分配并迁移数据，或禁止改变对象大小；rewrite 按实际分配大小做边界检查。
- **设计防御**：对象带 size/type 双校验；函数指针放只读表或使用 CFI；相邻敏感对象加 guard 页/随机化。
- **检测信号**：reclassify 后紧跟 rewrite；写入长度超过原对象大小；相邻 chunk 首字段被改写为 magic；perform 跳到隐藏函数。
