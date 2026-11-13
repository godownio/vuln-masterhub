---
id: ctf-misc-28-mansions-four-symbol-base4
title: 二十八星宿编码：星宿归一四大神兽得四进制数字，四位数转 ASCII
type: scenario
domain: ctf
path: ctf/misc
technique: 28-mansions-four-symbol-base4-ascii
tags:
- ctf
- misc
- encoding
- 28-mansions
- base4
- ascii
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:20:20+08:00'
  notes: 已对照原文与图07二十八宿四方表核对：四方各7宿、N/S/W/E→1/3/2/0、每4位四进制转ASCII与原文脚本一致，并含壁水貐/壁水獝异体字注意点；与九宫八卦、标点2bit卡符号体系不同非同链；未验证点：未实际解码
url: /docs/ctf/misc/ctf-misc-28-mansions-four-symbol-base4/
draft: false
kb_aliases:
- 二十八星宿编码
- 四象四进制
- Watch the sky at night
- 星宿转 ASCII
- 四神兽编码
---

## 一句话结论

二十八星宿按方位分为东方青龙、北方玄武、西方白虎、南方朱雀四组（各 7 个）；把每个星宿名映射为所属方位的字母（E/S/W/N），再替换为四进制数字（如 N=1、S=3、W=2、E=0），每 4 位转一个 ASCII 字符即可还原明文。

## 原理

- 二十八宿按四方七宿分组是固定知识：
  - 东方青龙：角木蛟、亢金龙、氐土貉、房日兔、心月狐、尾火虎、箕水豹；
  - 南方朱雀：井木犴、鬼金羊、柳土獐、星日马、张月鹿、翼火蛇、轸水蚓；
  - 西方白虎：奎木狼、娄金狗、胃土雉、昴日鸡、毕月乌、觜火猴、参水猿；
  - 北方玄武：斗木獬、牛金牛、女土蝠、虚日鼠、危月燕、室火猪、壁水貐。
- 出题人把星宿名连续排列（常无分隔、每 3 个汉字一组），每个星宿唯一对应四大方位之一，即 4 种符号；一个 4 进制位正好编码 2 bit。
- 4 个四进制位（4^4=256）恰好覆盖一个字节，`chr(int(group, 4))` 得到 ASCII 字符；连续分组即得完整消息。
- 星宿名可能存在异体字（如“壁水貐/壁水獝”“觜火猴”），匹配时需按题面写法或模糊匹配后 1–2 字。

## 触发条件

- 题面给出大量星宿名（28 个名称循环出现），或图片列出二十八宿与四方对应表。
- 名称连续排列且可按 3 字切分；按四进制每 4 个一组转出的字符可打印。
- 映射 N/S/W/E → 1/3/2/0 等由题面/脚本给出，可能需要尝试不同排列。

## 利用步骤

1. 建立四方→星宿表（如上），把所有星宿名替换为方位字母 E/S/W/N。
2. 按题面规则把字母映射为四进制数字（原文：N=1、S=3、W=2、E=0）。
3. 每 4 个数字一组 `int(group, 4)` 转十进制并 `chr()`；若不可打印，调整字母→数字映射（24 种排列）或尝试反向分组。
4. 拼接字符，按 `flag{` 前缀校正；异体字导致漏配时用包含关系模糊匹配。

## PoC

```python
data = '''斗木獬角木蛟奎木狼亢金龙 牛金牛女土蝠氐土貉井木犴
虚日鼠房日兔心月狐鬼金羊 危月燕室火猪尾火虎柳土獐 ...'''
data = data.replace('\r\n', '').replace(' ', '').replace('\n', '')

dic = {
    'E': ['角木蛟', '亢金龙', '氐土貉', '房日兔', '心月狐', '尾火虎', '箕水豹'],
    'S': ['井木犴', '鬼金羊', '柳土獐', '星日马', '张月鹿', '翼火蛇', '轸水蚓'],
    'W': ['奎木狼', '娄金狗', '胃土雉', '昴日鸡', '毕月乌', '觜火猴', '参水猿'],
    'N': ['斗木獬', '牛金牛', '女土蝠', '虚日鼠', '危月燕', '室火猪', '壁水貐'],
}

letters = ''
for i in range(0, len(data), 3):
    name = data[i:i+3]
    for k, v in dic.items():
        if name in v:
            letters += k
            break

digits = letters.replace('N', '1').replace('S', '3').replace('W', '2').replace('E', '0')
print(''.join(chr(int(digits[i:i+4], 4)) for i in range(0, len(digits) - len(digits) % 4, 4)))
```

- 原文示例：[HSCSEC2023]Watch the sky at night，按上表与四进制转换还原 flag。
- 星宿表末尾“壁水貐”在部分资料写作“壁水獝”，匹配时注意。

## 变体与关联

- 同类符号编码：[[ctf-misc-bagua-nine-palace-base9-ascii]]（九宫八卦九进制）、[[crypto-classical-pigpen-variant-fence-column-decode]]、[[ctf-misc-punctuation-2bit-encoding]]（四符号 2-bit）。
- 若映射未知，可用已知明文 `flag{` 反推 4–5 组数字对应关系再验证。

## 检测与防御

- CTF 技巧，非真实漏洞；出题方可使用异体字、打乱星宿顺序或混入假星宿名。
- 实际数据编码应使用标准字符集与校验，避免依赖文化常识带来的歧义。
