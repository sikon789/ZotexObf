# -*- coding: utf-8 -*-
"""
Zotex 混淆器 · render 端（纯混淆，不碰 key）
================================================
只做一件事：接收源码 → 返回混淆后的 Lua。
key 存在 PHP 虚拟主机（index.php 里），render 不涉及任何密钥。

接口：POST /api/obfuscate   {code} → {output}
"""
import os
from flask import Flask, request, jsonify

from obfuscator import ZotexObfuscator

app = Flask(__name__)


@app.post('/api/obfuscate')
def api_obfuscate():
    data = request.get_json(silent=True) or {}
    code = data.get('code', '')
    if not isinstance(code, str) or not code.strip():
        return jsonify({'error': '源码为空'}), 400
    if len(code) > 2_000_000:
        return jsonify({'error': '源码过长（>2MB）'}), 400

    try:
        obf = ZotexObfuscator(seed=None)
        output = obf.obfuscate(code)
        return jsonify({'output': output})
    except Exception as e:
        return jsonify({'error': f'混淆失败: {e}'}), 500


@app.get('/')
def index():
    return 'Zotex Obfuscator API (render)'


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
