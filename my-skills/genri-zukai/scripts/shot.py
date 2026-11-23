#!/usr/bin/env python3
"""仕組み図解の HTML を、ヘッドレスの Chrome で上から順に撮る。

使い方: python3 scripts/shot.py <図解.html> <出力フォルダ>
出力:   <出力フォルダ>/{pc,sp}-{light,dark}-NN.png
        pc = 幅 800（本文の列 768 が収まる）、sp = 幅 390（スマホ）。縦 1400px ごとに 1 枚
しくみ: 対象のページを枠（iframe）に入れて上へずらしながら撮る。枠の幅がそのまま画面の幅になる
"""
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
TILE = 1400
SIZES = {"pc": 800, "sp": 390}


def run(args):
    return subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                           "--allow-file-access-from-files", "--virtual-time-budget=4000", *args],
                          capture_output=True, text=True, timeout=120)


def main(html, out):
    if not os.path.exists(CHROME):
        print("Chrome が見つからない:", CHROME); return 2
    os.makedirs(out, exist_ok=True)
    # 前回の画像を消す（ページが短くなったとき、古い画像が残って読み違えないように）
    for f in os.listdir(out):
        if re.fullmatch(r"(pc|sp)-(light|dark)-\d+\.png", f):
            os.remove(os.path.join(out, f))
    target = "file://" + urllib.parse.quote(os.path.abspath(html))
    with tempfile.TemporaryDirectory() as tmp:
        prof = os.path.join(tmp, "profile")
        for key, w in SIZES.items():
            # 1) ページの高さを測る
            m = os.path.join(tmp, f"measure-{key}.html")
            open(m, "w", encoding="utf-8").write(f"""<!doctype html><meta charset="utf-8">
<body style="margin:0"><iframe id="f" src="{target}" style="width:{w}px;height:1000px;border:0"></iframe>
<pre id="h">?</pre><script>
document.getElementById('f').addEventListener('load', e => {{
  const d = e.target.contentDocument;
  document.getElementById('h').textContent = 'HEIGHT=' + d.documentElement.scrollHeight;
}});</script></body>""")
            r = run([f"--user-data-dir={prof}", "--dump-dom", "file://" + urllib.parse.quote(m)])
            found = re.search(r"HEIGHT=(\d+)", r.stdout)
            if not found:
                print("ページの高さを測れなかった"); return 1
            height = int(found.group(1))
            tiles = (height + TILE - 1) // TILE
            # 2) 明暗それぞれ、上から撮る
            for scheme in ("light", "dark"):
                for i in range(tiles):
                    wrap = os.path.join(tmp, f"wrap-{key}-{i}.html")
                    open(wrap, "w", encoding="utf-8").write(f"""<!doctype html><meta charset="utf-8">
<body style="margin:0;overflow:hidden;background:#888"><iframe src="{target}" scrolling="no"
style="position:absolute;left:0;top:-{i * TILE}px;width:{w}px;height:{height}px;border:0"></iframe></body>""")
                    png = os.path.join(out, f"{key}-{scheme}-{i + 1:02d}.png")
                    flags = [f"--user-data-dir={prof}", f"--window-size={max(w, 500)},{TILE}",
                             f"--screenshot={png}"]
                    if scheme == "dark":
                        flags.append("--force-dark-mode")
                    run(flags + ["file://" + urllib.parse.quote(wrap)])
            print(f"{key}（幅 {w}px）: 高さ {height}px → 明暗 各 {tiles} 枚")
    if any(SIZES[k] < 500 for k in SIZES):
        print("※ sp の画像は右側が灰色になる（Chrome の窓の最小幅のため）。灰色の左側が幅 390px の画面")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__); sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
