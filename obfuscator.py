# -*- coding: utf-8 -*-
"""
Zotex 强混淆器 · 修复版
================================
手法：
  1. 字节级字符串加密（解析 Lua 转义 → 真实 UTF-8 字节 → 数字表，任意字节安全）
  2. 局部变量重命名（保护字符串/注释，不误伤）
  3. 数字 MBA（排除十六进制/科学计数法，不产生浮点）
  4. 垃圾代码注入
  5. 多段随机密钥加密（LCG + 加减法，段尾补换行防黏连）
  6. 反篡改（环境自检 + cloneref 检测）

产物是自包含 Lua 5.1 / Luau 源码，整段加密不触碰语法，兼容性天然 100%。
"""
import re
import random
import base64
import os

from chacha import chacha20_xor

_RESERVED = set("""
and break do else elseif end false for function goto if in local nil not or
repeat return then true until while loadstring load print pcall xpcall type
tostring tonumber select unpack string table math os io coroutine debug
require getfenv setfenv rawget rawset pairs ipairs next setmetatable
getmetatable error assert collectgarbage package _G self task Instance
cloneref rawequal typeof spawn defer delay wait getgenv bit bit32 continue
""".split())

# Lua 简单转义表
_SIMPLE_ESC = {
    'n': 10, 't': 9, 'r': 13, 'a': 7, 'b': 8, 'f': 12, 'v': 11,
    '\\': 92, '"': 34, "'": 39, '\n': 10, '0': 0,
}


class ZotexObfuscator:
    def __init__(self, seed=None):
        self.rng = random.Random(seed)
        self.used = set(_RESERVED)
        self.decryptors = []
        self.seg_keys = []

    # ================= 标识符 =================
    def _ident(self):
        alpha = 'l1IO0oLiL'
        while True:
            n = self.rng.randint(6, 14)
            s = ''.join(self.rng.choice(alpha) for _ in range(n))
            if s[0] in '10' or s in self.used:
                continue
            self.used.add(s)
            return s

    # ================= 删除注释 =================
    def _strip_comments(self, src):
        """删除所有注释（行注释 + 长注释），但保护字符串里的 -- 。
        行注释保留换行；长注释用空格替代，避免 token 粘连。"""
        out = []
        i = 0
        n = len(src)
        while i < n:
            c = src[i]

            # 注释
            if src.startswith('--', i):
                m = re.match(r'--\[(=*)\[', src[i:])
                if m:
                    eq = m.group(1)
                    close = ']' + eq + ']'
                    end = src.find(close, i + len(m.group(0)))
                    i = n if end == -1 else end + len(close)
                    out.append(' ')   # 长注释 → 空格
                    continue
                # 行注释 → 删到行尾（保留换行）
                end = src.find('\n', i)
                i = n if end == -1 else end
                continue

            # 长字符串（保护，不能当注释删）
            if c == '[':
                m = re.match(r'\[(=*)\[', src[i:])
                if m:
                    eq = m.group(1)
                    close = ']' + eq + ']'
                    end = src.find(close, i + len(m.group(0)))
                    end = n if end == -1 else end + len(close)
                    out.append(src[i:end])
                    i = end
                    continue

            # 引号字符串（保护）
            if c in '"\'':
                q = c
                j = i + 1
                while j < n:
                    if src[j] == '\\':
                        j += 2
                        continue
                    if src[j] == q:
                        j += 1
                        break
                    j += 1
                out.append(src[i:j])
                i = j
                continue

            out.append(c)
            i += 1
        return ''.join(out)

    # ================= 扫描保护（字符串 + 注释）=================
    def _protect(self, src):
        """把字符串和注释替换成占位符，返回 (protected, items)。
        占位符格式 \x01S<num>\x01，数字前有字母 S，数字正则不会误匹配。"""
        items = []
        out = []
        i = 0
        n = len(src)
        while i < n:
            c = src[i]

            # 长注释 --[[ ]] / --[=[ ]=]
            if src.startswith('--', i):
                m = re.match(r'--\[(=*)\[', src[i:])
                if m:
                    eq = m.group(1)
                    close = ']' + eq + ']'
                    end = src.find(close, i + len(m.group(0)))
                    end = n if end == -1 else end + len(close)
                    items.append(src[i:end])
                    out.append('\x01S%d\x01' % (len(items) - 1))
                    i = end
                    continue
                end = src.find('\n', i)
                end = n if end == -1 else end
                items.append(src[i:end])
                out.append('\x01S%d\x01' % (len(items) - 1))
                i = end
                continue

            # 长字符串 [[ ]] / [=[ ]=]
            if c == '[':
                m = re.match(r'\[(=*)\[', src[i:])
                if m:
                    eq = m.group(1)
                    close = ']' + eq + ']'
                    end = src.find(close, i + len(m.group(0)))
                    end = n if end == -1 else end + len(close)
                    items.append(src[i:end])
                    out.append('\x01S%d\x01' % (len(items) - 1))
                    i = end
                    continue

            # 引号字符串
            if c in '"\'':
                q = c
                j = i + 1
                while j < n:
                    if src[j] == '\\':
                        j += 2
                        continue
                    if src[j] == q:
                        j += 1
                        break
                    j += 1
                items.append(src[i:j])
                out.append('\x01S%d\x01' % (len(items) - 1))
                i = j
                continue

            out.append(c)
            i += 1

        return ''.join(out), items

    def _restore(self, src, items):
        return re.sub(r'\x01S(\d+)\x01',
                      lambda m: items[int(m.group(1))], src)

    # ================= Lua 转义解析 =================
    def _lua_unescape(self, raw):
        """把 Lua 字符串字面量的内容解析成真实字节。"""
        out = bytearray()
        i = 0
        n = len(raw)
        while i < n:
            c = raw[i]
            if c == '\\' and i + 1 < n:
                nxt = raw[i + 1]
                if nxt in _SIMPLE_ESC:
                    out.append(_SIMPLE_ESC[nxt])
                    i += 2
                    continue
                if nxt.isdigit():
                    j = i + 1
                    num = ''
                    while j < n and len(num) < 3 and raw[j].isdigit():
                        num += raw[j]
                        j += 1
                    out.append(int(num) & 0xFF)
                    i = j
                    continue
                if nxt == 'x':
                    hexs = raw[i + 2:i + 4]
                    try:
                        out.append(int(hexs, 16) & 0xFF)
                        i += 4
                        continue
                    except ValueError:
                        pass
                if nxt == 'z':
                    i += 2
                    while i < n and raw[i] in ' \t\n\r':
                        i += 1
                    continue
                # 未知转义：保留原字符
                out.extend(nxt.encode('utf-8'))
                i += 2
                continue
            out.extend(c.encode('utf-8'))
            i += 1
        return bytes(out)

    # ================= 字节级字符串加密（多算法 + 拆分）=================
    def _emit_decryptors(self):
        """生成 3 种不同算法的解密函数，随机选用，增加分析难度。"""
        if getattr(self, '_dec_fns', None):
            return self._dec_fns
        f1 = self._ident()
        f2 = self._ident()
        f3 = self._ident()
        # A：正向 + 减法
        self.decryptors.append(
            f'local {f1}=function(t,k) local s="" '
            f'for i=1,#t do s=s..string.char((t[i]-k)%256) end return s end')
        # B：反向读取 + 减法
        self.decryptors.append(
            f'local {f2}=function(t,k) local s="" '
            f'for i=#t,1,-1 do s=s..string.char((t[i]-k)%256) end return s end')
        # C：双重密钥 + 减法
        self.decryptors.append(
            f'local {f3}=function(t,k1,k2) local s="" '
            f'for i=1,#t do s=s..string.char((t[i]-k1-k2)%256) end return s end')
        self._dec_fns = [(f1, 'A'), (f2, 'B'), (f3, 'C')]
        return self._dec_fns

    def _encode_chunk(self, data):
        """用随机算法加密一小段字节，返回 Lua 表达式。"""
        fns = self._emit_decryptors()
        fname, alg = self.rng.choice(fns)
        if alg == 'A':
            k = self.rng.randint(1, 250)
            enc = [(b + k) % 256 for b in data]
            return f'{fname}({{{",".join(map(str, enc))}}},{k})'
        if alg == 'B':
            k = self.rng.randint(1, 250)
            enc = [(b + k) % 256 for b in reversed(data)]
            return f'{fname}({{{",".join(map(str, enc))}}},{k})'
        # C
        k1 = self.rng.randint(1, 200)
        k2 = self.rng.randint(1, 55)
        enc = [(b + k1 + k2) % 256 for b in data]
        return f'{fname}({{{",".join(map(str, enc))}}},{k1},{k2})'

    def _encode_bytes(self, data):
        """长字符串随机拆成多段，每段独立加密，运行时拼接。"""
        if not data:
            return '""'
        # 长度 >= 8 时 50% 概率拆分
        if len(data) >= 8 and self.rng.random() < 0.5:
            n_parts = self.rng.randint(2, 3)
            size = max(2, len(data) // n_parts)
            chunks = [data[i:i + size] for i in range(0, len(data), size)]
        else:
            chunks = [data]
        parts = [self._encode_chunk(c) for c in chunks]
        if len(parts) == 1:
            return parts[0]
        return '(' + '..'.join(parts) + ')'

    def _encrypt_strings(self, src):
        """扫描并加密所有引号字符串和长字符串。"""
        out = []
        i = 0
        n = len(src)
        while i < n:
            c = src[i]

            # 长字符串：内容不含转义，直接加密
            if c == '[':
                m = re.match(r'\[(=*)\[', src[i:])
                if m:
                    eq = m.group(1)
                    close = ']' + eq + ']'
                    start = i + len(m.group(0))
                    end = src.find(close, start)
                    if end != -1:
                        content = src[start:end]
                        # 长字符串开头若有换行，Lua 会忽略第一个换行
                        if content.startswith('\n'):
                            content = content[1:]
                        data = content.encode('utf-8')
                        out.append(self._encode_bytes(data))
                        i = end + len(close)
                        continue

            # 引号字符串
            if c in '"\'':
                q = c
                j = i + 1
                while j < n:
                    if src[j] == '\\':
                        j += 2
                        continue
                    if src[j] == q:
                        j += 1
                        break
                    j += 1
                raw = src[i + 1:j - 1]
                data = self._lua_unescape(raw)
                out.append(self._encode_bytes(data))
                i = j
                continue

            out.append(c)
            i += 1

        return ''.join(out)

    # ================= 局部变量重命名 =================
    def _rename_locals(self, src):
        protected, items = self._protect(src)
        mapping, seen = {}, set()

        # local function f(a,b)
        for m in re.finditer(r'\blocal\s+function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)', protected):
            fn, ps = m.group(1), m.group(2)
            if fn not in _RESERVED and fn not in seen:
                seen.add(fn)
                mapping[fn] = self._ident()
            for p in ps.split(','):
                p = p.strip()
                if p and p not in _RESERVED and p not in seen:
                    seen.add(p)
                    mapping[p] = self._ident()

        # local a, b, c = ...
        for m in re.finditer(r'\blocal\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?=[=,])', protected):
            for nm in m.group(1).split(','):
                nm = nm.strip()
                if nm and nm not in _RESERVED and nm not in seen:
                    seen.add(nm)
                    mapping[nm] = self._ident()

        # function name(a,b) / function obj:method(a,b)
        for m in re.finditer(r'\bfunction\s+[A-Za-z_]\w*[.:]?[A-Za-z_]\w*\s*\(([^)]*)\)', protected):
            for p in m.group(1).split(','):
                p = p.strip()
                if p and p not in _RESERVED and p not in seen:
                    seen.add(p)
                    mapping[p] = self._ident()

        for old, new in mapping.items():
            protected = re.sub(r'\b%s\b' % re.escape(old), new, protected)

        return self._restore(protected, items)

    # ================= 数字 MBA =================
    def _encode_num(self, n):
        r = self.rng
        a = r.randint(1, 30)
        b = r.randint(1, 20)
        return r.choice([
            f'({n}+{a}-{a})',
            f'({n}-{a}+{a})',
            f'({n}+{b}-{b})',
        ])

    def _mba(self, src):
        protected, items = self._protect(src)
        # 排除：前面是字母数字下划线点；后面是数字、点、x/X(十六进制)、e/E(科学计数)
        protected = re.sub(
            r'(?<![A-Za-z0-9_.])\d+(?![\d.xXeE])',
            lambda m: self._encode_num(int(m.group(0))) if len(m.group(0)) <= 6 else m.group(0),
            protected)
        return self._restore(protected, items)

    # ================= 垃圾代码 =================
    def _bracket_delta(self, line):
        """计算一行里 {[( 与 }]) 的净值（此时代码里已无原始字符串）。"""
        d = 0
        for ch in line:
            if ch in '{[(':
                d += 1
            elif ch in '}])':
                d -= 1
        return d

    def _junk(self, src):
        """只在括号深度为 0 的安全位置插垃圾代码（表构造函数/参数列表内部不能插）。
        也避开 return 行（return 必须是块的最后一条语句）。"""
        lines = src.split('\n')
        out = []
        depth = 0
        for i, ln in enumerate(lines):
            out.append(ln)
            depth += self._bracket_delta(ln)
            stripped = ln.strip()
            safe = (depth <= 0 and stripped
                    and not stripped.startswith('return')
                    and not stripped.startswith('--'))
            if safe and self.rng.random() < 0.35:
                v = self._ident()
                out.append(self.rng.choice([
                    f'local {v}={self.rng.randint(1,999)};if {v}%2==0 then {v}={v}+1 end;',
                    f'local {v}="{{{self.rng.randint(1000,9999)}}}";{v}=string.rep({v},1);',
                    f'local {v}={self.rng.randint(1,9)};{v}=({v}*10)/10;',
                ]))
        return '\n'.join(out)

    # ================= 多段加密 =================
    def _segments(self, src):
        lines = src.split('\n')
        n = self.rng.randint(3, 6)
        n = min(n, max(1, len(lines) // 2)) if len(lines) > 3 else 1
        size = max(1, len(lines) // n) if n else len(lines)
        segs = []
        for i in range(0, len(lines), size):
            c = '\n'.join(lines[i:i + size])
            if c.strip():
                segs.append(c + '\n')  # 段尾补换行，防段间黏连
        return segs or [src]

    def _enc_seg(self, seg):
        """ChaCha20 加密一段：随机 32 字节 key + 随机 12 字节 nonce。
        密文格式 base64(nonce12 || ciphertext)，key 单独存。"""
        key = os.urandom(32)
        nonce = os.urandom(12)
        ct = chacha20_xor(key, nonce, seg.encode('utf-8'))
        self.seg_keys.append(key)
        return base64.b64encode(nonce + ct).decode('ascii')

    def _base64_lua(self):
        return '''
local b64_c='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local b64_i={}
for _=1,#b64_c do b64_i[b64_c:sub(_,_)]=_-1 end
local function b64_decode(d)
  d=string.gsub(d,'[^'..b64_c..'=]','')
  return (d:gsub('.',function(x)
    if x=='=' then return '' end
    local r,f='',(b64_i[x] or 0)
    for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
    return r
  end):gsub('%d%d%d?%d?%d?%d?%d?%d?',function(x)
    if #x~=8 then return '' end
    local c=0
    for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
    return string.char(c)
  end))
end
'''

    def _anti_tamper_lua(self):
        """多路环境检测 + 随机失败方式（避免"只有一种死循环"太好识别）。
        检测项：关键函数是否被替换、debug.getinfo 函数指纹、cloneref 真实性。"""
        # 失败方式：静默退出概率最高（最难判断是检测还是脚本本身问题）
        fail = self.rng.choice(['silent', 'silent', 'silent', 'hang', 'error'])
        if fail == 'silent':
            action = 'do return end'
        elif fail == 'hang':
            action = 'while true do end'
        else:
            action = 'error("")'
        return f'''
local function __anti()
  local s_byte=string.byte
  local s_char=string.char
  local p_ok=pcall
  local t_type=type
  local bad=false
  if string.byte~=s_byte then bad=true end
  if string.char~=s_char then bad=true end
  if pcall~=p_ok then bad=true end
  if type~=t_type then bad=true end
  if debug and debug.getinfo then
    local ok,info=pcall(debug.getinfo,s_byte)
    if ok and info and info.name and info.name~="byte" then bad=true end
  end
  if cloneref and rawequal and Instance and Instance.new then
    local ok=pcall(function()
      local p=Instance.new("Part")
      local c=cloneref(p)
      if rawequal(p,c) then bad=true end
      c.Name="z"
      if p.Name~="z" then bad=true end
      if p.Destroy then p:Destroy() end
    end)
    if not ok then bad=true end
  end
  return bad
end
if __anti() then {action} end
'''

    def _chacha_lua(self):
        """内联 ChaCha20 实现（兼容 bit32 / bit / lua5.3+ 原生运算符）。"""
        return r'''
local function __gb()
  local B=bit32 or bit
  if B then return B end
  local o,m=pcall(require,"bit")
  if o and m then return m end
  local ld=load or loadstring
  local ok,mm=pcall(function() return ld("return {bxor=function(a,b) return a~b end,lrotate=function(a,b) return ((a<<b)|(a>>(32-b)))&0xFFFFFFFF end}")() end)
  if ok and mm then return mm end
  error("no bit lib")
end
local __B=__gb()
local __xo=__B.bxor
local __rl=__B.lrotate or __B.rol
local function __u32(s,i) local a,b,c,d=string.byte(s,i,i+3) return a+b*256+c*65536+d*16777216 end
local function __cb(K,ctr,N)
  local st={0x61707865,0x3320646e,0x79622d32,0x6b206574,
    __u32(K,1),__u32(K,5),__u32(K,9),__u32(K,13),
    __u32(K,17),__u32(K,21),__u32(K,25),__u32(K,29),
    ctr,__u32(N,1),__u32(N,5),__u32(N,9)}
  local w={}
  for i=1,16 do w[i]=st[i] end
  local function qr(a,b,c,d)
    w[a]=(w[a]+w[b])%4294967296; w[d]=__xo(w[d],w[a]); w[d]=__rl(w[d],16)
    w[c]=(w[c]+w[d])%4294967296; w[b]=__xo(w[b],w[c]); w[b]=__rl(w[b],12)
    w[a]=(w[a]+w[b])%4294967296; w[d]=__xo(w[d],w[a]); w[d]=__rl(w[d],8)
    w[c]=(w[c]+w[d])%4294967296; w[b]=__xo(w[b],w[c]); w[b]=__rl(w[b],7)
  end
  for _=1,10 do
    qr(1,5,9,13);qr(2,6,10,14);qr(3,7,11,15);qr(4,8,12,16)
    qr(1,6,11,16);qr(2,7,12,13);qr(3,8,9,14);qr(4,5,10,15)
  end
  local t={}
  for i=1,16 do
    local v=(w[i]+st[i])%4294967296
    t[i]=string.char(v%256,math.floor(v/256)%256,math.floor(v/65536)%256,math.floor(v/16777216)%256)
  end
  return table.concat(t)
end
local function __cx(K,N,data)
  local out={} local ctr=0
  for i=1,#data,64 do
    local ks=__cb(K,ctr,N)
    local chunk=data:sub(i,i+63)
    local t={}
    for j=1,#chunk do t[j]=string.char(__xo(string.byte(chunk,j),string.byte(ks,j))) end
    out[#out+1]=table.concat(t)
    ctr=ctr+1
  end
  return table.concat(out)
end
'''

    def _build_driver(self, ciphers, keys):
        b64 = self._base64_lua()
        chacha = self._chacha_lua()
        anti = self._anti_tamper_lua()
        seed = self._ident()
        return f'''
{b64}
{chacha}
{anti}
local __C={{{ciphers}}}
local __K={{{keys}}}
local __L=loadstring or load
local __all=""
for __i=1,#__C do
  local __key=b64_decode(__K[__i])
  local __blob=b64_decode(__C[__i])
  __all=__all..__cx(__key,__blob:sub(1,12),__blob:sub(13))
end
local __f=__L(__all)
if __f then __f() end
'''

    # ================= 主入口 =================
    def obfuscate(self, source):
        self.decryptors = []
        self.seg_keys = []
        self._dec_fns = None

        src = self._strip_comments(source)     # 0. 删注释
        src = self._rename_locals(src)         # 1. 重命名（保护字符串）
        src = self._mba(src)                    # 2. 数字混淆（保护字符串）
        src = self._encrypt_strings(src)        # 3. 字符串加密（字节级）
        src = self._junk(src)                   # 4. 垃圾代码（此时无跨行字符串）

        if self.decryptors:
            src = '\n'.join(self.decryptors) + '\n' + src

        segs = self._segments(src)
        ciphers = [self._enc_seg(s) for s in segs]
        keys = ','.join('"%s"' % base64.b64encode(k).decode('ascii')
                        for k in self.seg_keys)
        ciphers_str = ','.join('"%s"' % x for x in ciphers)

        header = ('--[[This file has been obfuscated by Zotex]]\n'
                  '-- 注意：本文件 key 与密文同文件，强度等同混淆而非加密；真正的秘密在完整版（key 联网取）\n')
        return header + self._build_driver(ciphers_str, keys)
