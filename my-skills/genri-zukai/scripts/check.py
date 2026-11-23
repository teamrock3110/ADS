#!/usr/bin/env python3
"""仕組み図解の HTML を機械で検査する。

使い方: python3 scripts/check.py <図解.html>
終了コード: 0 = 誤りなし（注意はあってもよい） / 1 = 誤りあり
"""
import re
import sys
from html.parser import HTMLParser

PALETTE = {"#1b4b68", "#10547c", "#0c6ca4", "#dc1c18", "#e46c38", "#ecf4f8",
           "#f4f8fc", "#2c4c60", "#909090", "#ffffff", "#a5c5d8"}
BANNED = ["することができ", "と言えるでしょう", "非常に", "とても", "様々な", "色々な", "いかがでしたか",
          "ぜひ", "まず結論から", "！"]
PARTS = ("fig", "note", "vs", "cards2", "terms", "steps", "calc", "takeaway")


class Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.ids = {}
        self.sec_nums = []
        self.svgs = []          # 各 svg の情報
        self.cur_svg = None
        self.in_sources = 0
        self.ext = []
        self.classes = []
        self.text_in = None
        self.buf = ""
        self.p_strong = []      # 段落ごとの strong 数
        self.cur_p = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = (a.get("class") or "").split()
        self.classes.extend(cls)
        if "id" in a:
            self.ids[a["id"]] = self.ids.get(a["id"], 0) + 1
        if tag == "footer" and "sources" in cls:
            self.in_sources = 1
        # 外部読み込み
        for k in ("src", "href"):
            v = a.get(k) or ""
            if re.match(r"(https?:)?//", v):
                if tag == "a" and self.in_sources:
                    continue
                if tag == "a":
                    continue  # 本文のリンクは読み込みではない
                self.ext.append(f"<{tag} {k}={v}>")
        if tag == "span" and "sec-num" in cls:
            self.text_in = "secnum"; self.buf = ""
        if tag == "svg" and a.get("viewbox") is not None and "icon" not in cls and "icon-sm" not in cls:
            self.cur_svg = {"viewBox": a.get("viewbox"), "title": False, "desc": False,
                            "sizes": [], "colors": [], "texts": 0}
        if self.cur_svg is not None:
            if tag == "title": self.cur_svg["title"] = True
            if tag == "desc": self.cur_svg["desc"] = True
            if tag == "text": self.cur_svg["texts"] += 1
            if "font-size" in a:
                try: self.cur_svg["sizes"].append(float(a["font-size"]))
                except ValueError: pass
            for k in ("fill", "stroke", "stop-color"):
                v = (a.get(k) or "").lower()
                if v.startswith("#"):
                    self.cur_svg["colors"].append(v)
        if tag == "p":
            self.cur_p = 0
        if tag == "strong" and self.cur_p is not None:
            self.cur_p += 1
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag == "svg" and self.cur_svg is not None:
            self.svgs.append(self.cur_svg); self.cur_svg = None
        if tag == "span" and self.text_in == "secnum":
            self.sec_nums.append(self.buf.strip()); self.text_in = None
        if tag == "footer":
            self.in_sources = 0
        if tag == "p" and self.cur_p is not None:
            self.p_strong.append(self.cur_p); self.cur_p = None
        if self.stack:
            self.stack.pop()

    def handle_data(self, data):
        if self.text_in:
            self.buf += data


def main(path):
    html = open(path, encoding="utf-8").read()
    errors, warns = [], []
    c = Collector()
    c.feed(html)

    # 外部読み込み
    if c.ext:
        errors.append("外部から読み込んでいる: " + ", ".join(c.ext[:5]))
    if re.search(r"@import|url\(\s*['\"]?https?:", html):
        errors.append("CSS が外部を読み込んでいる（@import / url(http…)）")

    # 書き残し
    left = re.findall(r"\{\{[^}]*\}\}", html)
    if left:
        errors.append(f"テンプレートの穴が残っている: {left[:5]}")

    # id の重複
    dup = [k for k, v in c.ids.items() if v > 1]
    if dup:
        errors.append(f"id が重複している（図の id に接頭辞を付ける）: {dup[:8]}")

    # セクション番号
    want = [f"{i:02d}" for i in range(1, len(c.sec_nums) + 1)]
    if c.sec_nums != want:
        errors.append(f"セクション番号が 01 からの通しになっていない: {c.sec_nums}")
    n = len(c.sec_nums)
    if not 6 <= n <= 10:
        warns.append(f"セクションが {n} 個（目安 6〜10）")

    # 図
    figs = len(c.svgs)
    if figs < max(1, n // 2):
        warns.append(f"図が {figs} 枚でセクション {n} 個に対して少ない（目安：各セクション 1 枚）")
    for i, s in enumerate(c.svgs, 1):
        if (s["viewBox"] or "").split() != ["0", "0", "1280", "720"]:
            errors.append(f"図{i}: viewBox が 0 0 1280 720 でない（{s['viewBox']}）")
        if not (s["title"] and s["desc"]):
            errors.append(f"図{i}: <title> と <desc> の両方が要る")
        small = [x for x in s["sizes"] if x < 22]
        if small:
            errors.append(f"図{i}: 22 未満の字がある {sorted(set(small))}")
        bad = sorted(set(x for x in s["colors"] if x not in PALETTE))
        if bad:
            errors.append(f"図{i}: 決められた色以外を使っている {bad}")
        if s["texts"] == 0:
            warns.append(f"図{i}: 字が 1 つもない（タイトルを含めて確かめる）")

    # 部品
    need = {"hero": "表紙", "overview": "今回の全体像", "closing": "まとめ", "sources": "出典"}
    for k, v in need.items():
        if k not in c.classes:
            errors.append(f"{v}（.{k}）がない")
    if "principle" not in c.classes:
        errors.append("まとめに原理の 1 文（.principle）がない")
    cards = c.classes.count("card")
    parts = c.classes.count("part")
    if cards and parts and cards != parts and cards != parts - 1:
        warns.append(f"全体像のカード {cards} 枚とパート {parts} 個が合わない（導入パートを除いて一致させる）")
    if c.classes.count("bridge") < max(0, n - 2):
        warns.append("橋渡し（.bridge）が少ない。最後以外のセクションの終わりに置く")
    if re.search(r'<a [^>]*href="https?://', html.split('class="sources"')[-1]) is None:
        errors.append("出典にリンクがない")

    # 本文に色を直書き
    body = html.split("<body", 1)[-1]
    body_wo_svg = re.sub(r"<svg.*?</svg>", "", body, flags=re.S)
    if re.search(r'style="[^"]*color', body_wo_svg):
        errors.append("本文の要素に style で色を書いている")
    if re.search(r"#[0-9a-fA-F]{3,6}\b", re.sub(r"<script.*?</script>", "", body_wo_svg, flags=re.S)):
        warns.append("本文（図の外）に 16 進の色がある")

    # 文章
    text = re.sub(r"<[^>]+>", "", re.sub(r"<(style|script|svg)\b.*?</\1>", "", html, flags=re.S))
    for w in BANNED:
        if w in text:
            warns.append(f"使わない言い回し「{w}」がある")
    many = sum(1 for x in c.p_strong if x > 1)
    if many:
        warns.append(f"strong が 2 か所以上ある段落が {many} 個")

    # 図の中の 1 行の字数（タイトルは 28 字、ほかは 16 字まで）
    for i, svg in enumerate(re.findall(r"<svg\b(?:(?!<svg\b).)*?viewBox=\"0 0 1280 720\".*?</svg>", html, flags=re.S), 1):
        for attrs, txt in re.findall(r"<(?:text|tspan)\b([^>]*)>([^<]+)<", svg):
            t = txt.strip()
            limit = 28 if 'font-size="38"' in attrs else 16
            if len(t) > limit:
                warns.append(f"図{i}: 1 行が長い（{len(t)} 字）「{t[:20]}…」。行を分けるか削る")

    # 表のような図（左寄せの字が 6 つ以上＝項目名と値を並べた形）
    for i, svg in enumerate(re.findall(r"<svg\b(?:(?!<svg\b).)*?viewBox=\"0 0 1280 720\".*?</svg>", html, flags=re.S), 1):
        left = [a for a in re.findall(r"<text\b([^>]*)>", svg)
                if "text-anchor" not in a and 'font-size="38"' not in a]
        if len(left) >= 6:
            warns.append(f"図{i}: 表のような図に見える（左寄せの字が {len(left)} 個）。場面で描くか、本文の .vs / .terms に移す")

    # セクションごとの部品の数
    for chunk in html.split('<section class="sec"')[1:]:
        chunk = chunk.split("</section>", 1)[0]
        num = re.search(r'sec-num">(\d+)', chunk)
        found = [k for k in PARTS for _ in re.findall(r'class="(?:[^"]*\s)?' + k + r'(?:\s[^"]*)?"', chunk)]
        if len(found) > 3:
            warns.append(f"セクション {num.group(1) if num else '?'}: 部品が {len(found)} 個（3 つまで）{found}")

    # 橋渡しの形（問い／予告）が 3 回続いていないか
    kinds = []
    for b in re.findall(r'class="bridge"[^>]*>(.*?)</p>', html, flags=re.S):
        b = re.sub(r"<[^>]+>", "", b).strip()
        kinds.append("問い" if b.endswith(("でしょうか。", "？", "か。")) else "予告")
    for j in range(len(kinds) - 2):
        if kinds[j] == kinds[j + 1] == kinds[j + 2]:
            warns.append(f"橋渡しの形「{kinds[j]}」が 3 回続いている（{j + 1}〜{j + 3} 個目）")
            break

    # 長い文（本文の段落、80 字超）
    long_n = 0
    main_html = re.sub(r"<(svg|style|script)\b.*?</\1>", "", html, flags=re.S)
    for ptxt in re.findall(r"<p\b[^>]*>(.*?)</p>", main_html, flags=re.S):
        for sent in re.sub(r"<[^>]+>", "", ptxt).split("。"):
            if len(sent.strip()) > 80:
                long_n += 1
    if long_n:
        warns.append(f"80 字を超える文が {long_n} 個（目安 60 字）")

    for e in errors:
        print("誤り:", e)
    for w in warns:
        print("注意:", w)
    print(f"--- セクション {n} / 図 {figs} / 誤り {len(errors)} / 注意 {len(warns)}")
    return 1 if errors else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(2)
    sys.exit(main(sys.argv[1]))
