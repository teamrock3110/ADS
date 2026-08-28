/**
 * Fortinet PSIRT Watcher for Google Apps Script  (v5 / 台帳の読みやすさ改善)
 * ==================================================================
 * v4 からの変更点:
 *   1. 公開日を日付型にする（"Tue, 14 Jul 2026..." → 2026/07/14）
 *   2. 「理由」列を追加し、判定の根拠を必ず書かせる
 *   3. 「非該当」なら優先度を空にする（コードで強制。判定との矛盾を防ぐ）
 *   4. 判定できなかった行を次回の実行で自動的に拾い直す
 *   5. 列の並びを「判断に使う順」に変更（生データは右側へ）
 *
 * 列構成が変わるため、既存の台帳はデータ行を全削除してから使ってください。
 *   手順: migrateLedgerHeaders() → 2行目以降を全削除 → main()
 *
 * ------------------------------------------------------------------
 * スクリプト プロパティ:
 *   GEMINI_API_KEY / ANTHROPIC_API_KEY / SLACK_WEBHOOK_URL
 */

// ============================================================
// 設定
// ============================================================

/** 'gemini' か 'claude' */
const AI_PROVIDER = 'gemini';

const GEMINI_MODEL = 'gemini-3.6-flash';
const CLAUDE_MODEL = 'claude-sonnet-5';

const RSS_URL = 'https://filestore.fortinet.com/fortiguard/rss/ir.xml';

const SHEET_LEDGER = '台帳';
const SHEET_ASSET = '資産';

const MAX_ITEMS_PER_RUN = 30;

/** 1回の AI 呼び出しで処理する件数 */
const AI_CHUNK_SIZE = 10;

/** 判定が入っていない扱いにする値 */
const UNJUDGED_VALUES = ['', '未判定', '取得失敗'];

const LEDGER_HEADERS = [
  // --- 判断に使う列 ---
  '取得日時', '公開日', 'FG-IR', 'タイトル',
  '判定', '優先度', '理由', '影響機能名', '何が起きるか(日本語)', '対応方針',
  '修正バージョン', '自社該当バージョン',
  // --- 補助情報 ---
  'CVSS', '深刻度', '無認証リモート', '緩和策', 'CVE', 'CWE',
  // --- 生データ（確認用） ---
  'CVSSベクター', '影響機能', '何が起きるか', '影響バージョン', 'URL', '判定AI'
];

const ASSET_HEADERS = ['製品', 'バージョン', '台数', 'インターネット公開', '備考'];

// ============================================================
// エントリポイント
// ============================================================

function setup() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  let ledger = ss.getSheetByName(SHEET_LEDGER);
  if (!ledger) {
    ledger = ss.insertSheet(SHEET_LEDGER);
    ledger.appendRow(LEDGER_HEADERS);
    ledger.setFrozenRows(1);
    Logger.log('「台帳」シートを作成しました。');
  } else {
    Logger.log('「台帳」シートは既にあります。migrateLedgerHeaders() で列を更新してください。');
  }

  let asset = ss.getSheetByName(SHEET_ASSET);
  if (!asset) {
    asset = ss.insertSheet(SHEET_ASSET);
    asset.appendRow(ASSET_HEADERS);
    asset.appendRow(['FortiOS', '7.4.5', 2, 'あり', 'SSL-VPN 有効']);
    asset.appendRow(['FortiClientEMS', '7.2.4', 1, 'なし', '']);
    asset.appendRow(['FortiClient Windows', '7.2.4', 250, 'なし', '']);
    asset.setFrozenRows(1);
    Logger.log('「資産」シートを作成しました。中身を自社の内容に書き換えてください。');
  } else {
    Logger.log('「資産」シートは既にあります。');
  }
}

/** 台帳の見出し行を最新の構成に更新する。列順が変わったのでデータ行は削除してください。 */
function migrateLedgerHeaders() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh) throw new Error('「台帳」シートがありません。setup() を実行してください。');
  sh.getRange(1, 1, 1, LEDGER_HEADERS.length).setValues([LEDGER_HEADERS]);
  sh.setFrozenRows(1);
  Logger.log('台帳の見出しを ' + LEDGER_HEADERS.length + ' 列に更新しました。');
  Logger.log('※ v5 は列順が変わっています。2行目以降のデータは削除してから main() を実行してください。');
}

function createDailyTrigger() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (t.getHandlerFunction() === 'main') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('main').timeBased().atHour(9).everyDays(1).create();
  Logger.log('毎日 9 時台に main() を実行するトリガーを作成しました。');
}

function main() {
  // 前回判定できなかった行を消しておく。既読から外れ、今回拾い直される。
  const purged = purgeUnjudgedRows_();
  if (purged) Logger.log('判定できていなかった ' + purged + ' 行を削除し、再取得対象にしました。');

  const items = fetchRssItems_();
  const known = getKnownIrNumbers_();
  const newItems = items
    .filter(function (it) { return known.indexOf(it.ir) === -1; })
    .slice(0, MAX_ITEMS_PER_RUN);

  if (newItems.length === 0) {
    Logger.log('新着なし。');
    return;
  }
  Logger.log('新着 ' + newItems.length + ' 件を処理します。');

  const assets = readAssets_();

  newItems.forEach(function (it) {
    try {
      const csaf = fetchCsaf_(it.link);
      if (csaf) Object.assign(it, csaf);
    } catch (e) {
      it.error = String(e);
      Logger.log('CSAF 取得失敗: ' + it.ir + ' / ' + e);
    }
    it.selfAffected = filterAffectedForAssets_(it.affected, assets);
    Utilities.sleep(500);
  });

  let verdicts = {};
  try {
    verdicts = judgeWithAI_(newItems, assets);
  } catch (e) {
    Logger.log('判定に失敗しました。判定なしで記録します: ' + e);
  }

  writeLedger_(newItems, verdicts);
  notifySlack_(newItems, verdicts);
  Logger.log('完了しました。');
}

// ============================================================
// 1. RSS 取得
// ============================================================

/** "Tue, 14 Jul 2026 00:00:00 -0700" を Date にする。失敗したら元の文字列を返す。 */
function parsePubDate_(s) {
  if (!s) return '';
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d;
}

function fetchRssItems_() {
  const res = UrlFetchApp.fetch(RSS_URL, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('RSS 取得失敗 HTTP ' + res.getResponseCode());
  }

  const root = XmlService.parse(res.getContentText()).getRootElement();
  const items = root.getChild('channel').getChildren('item');

  return items.map(function (item) {
    const link = item.getChildText('link');
    const descHtml = item.getChildText('description') || '';
    const descText = descHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    const m = /FG-IR-[\w-]+/.exec(link || '');
    return {
      ir: m ? m[0] : link,
      title: item.getChildText('title'),
      link: link,
      pubDate: parsePubDate_(item.getChildText('pubDate')),
      summary: descText
    };
  });
}

// ============================================================
// 2. 台帳の既読チェックと後始末
// ============================================================

function getKnownIrNumbers_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 2) return [];
  const col = LEDGER_HEADERS.indexOf('FG-IR') + 1;
  return sh.getRange(2, col, sh.getLastRow() - 1, 1).getValues()
    .map(function (r) { return String(r[0]).trim(); });
}

/** 判定が入っていない行を削除する。戻り値は削除した行数。 */
function purgeUnjudgedRows_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 2) return 0;

  const col = LEDGER_HEADERS.indexOf('判定') + 1;
  const values = sh.getRange(2, col, sh.getLastRow() - 1, 1).getValues();

  let removed = 0;
  // 下から消さないと行番号がずれる
  for (let i = values.length - 1; i >= 0; i--) {
    if (UNJUDGED_VALUES.indexOf(String(values[i][0]).trim()) !== -1) {
      sh.deleteRow(i + 2);
      removed++;
    }
  }
  return removed;
}

// ============================================================
// 3. CSAF の取得
// ============================================================

function pushUnique_(arr, val) {
  if (val && arr.indexOf(val) === -1) arr.push(val);
}

/** CVSS ベクターから「無認証・リモート・操作不要」かを判定する。LLM 不使用。 */
function isUnauthRemote_(vector) {
  if (!vector) return false;
  return /AV:N/.test(vector) && /PR:N/.test(vector) && /UI:N/.test(vector);
}

/** 影響バージョンから、自社が持っている製品の行だけを残す。LLM 不使用。 */
function filterAffectedForAssets_(affectedStr, assets) {
  if (!affectedStr) return '';
  const keys = assets
    .map(function (a) { return String(a['製品'] || '').toLowerCase().split(/\s+/)[0]; })
    .filter(function (k) { return k; });
  if (!keys.length) return affectedStr;

  const hits = affectedStr.split('\n').filter(function (line) {
    const lower = line.toLowerCase();
    return keys.some(function (k) { return lower.indexOf(k) === 0; });
  });
  return hits.join('\n');
}

function fetchCsaf_(advisoryUrl) {
  const html = UrlFetchApp.fetch(advisoryUrl, { muteHttpExceptions: true }).getContentText();
  const m = /csaf_url=(https:\/\/[^"'&\s]+\.json)/.exec(html);
  if (!m) return null;

  const res = UrlFetchApp.fetch(m[1], { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) return null;
  const csaf = JSON.parse(res.getContentText());

  const cves = [], affected = [], fixes = [], features = [];
  const impacts = [], cwes = [], vectors = [], workarounds = [];
  let maxScore = 0, severity = '', unauthRemote = false;

  (csaf.vulnerabilities || []).forEach(function (v) {
    pushUnique_(cves, v.cve);
    if (v.cwe && v.cwe.id) pushUnique_(cwes, v.cwe.id + ' ' + (v.cwe.name || ''));

    ((v.product_status && v.product_status.known_affected) || []).forEach(function (a) {
      pushUnique_(affected, a);
    });

    (v.remediations || []).forEach(function (r) {
      if (r.category === 'vendor_fix') pushUnique_(fixes, r.details);
    });

    (v.notes || []).forEach(function (n) {
      const text = (n.text || '').trim();
      if (!text) return;
      if (n.category === 'summary') {
        pushUnique_(features, text);
      } else if ((n.title || '').toLowerCase().indexOf('workaround') !== -1) {
        if (text.toUpperCase() !== 'N/A') pushUnique_(workarounds, text);
      }
    });

    (v.threats || []).forEach(function (t) {
      if (t.category === 'impact') pushUnique_(impacts, t.details);
    });

    (v.scores || []).forEach(function (s) {
      const c = s.cvss_v3 || {};
      if (c.vectorString) {
        pushUnique_(vectors, c.vectorString);
        if (isUnauthRemote_(c.vectorString)) unauthRemote = true;
      }
      if (c.baseScore && c.baseScore > maxScore) {
        maxScore = c.baseScore;
        severity = c.baseSeverity || '';
      }
    });
  });

  return {
    cves: cves.join(', '),
    cvss: maxScore || '',
    severity: severity,
    affected: affected.join('\n'),
    fixes: fixes.join('\n'),
    features: features.join('\n'),
    impacts: impacts.join(', '),
    cwes: cwes.join(', '),
    vectors: vectors.join('\n'),
    unauthRemote: unauthRemote ? 'はい' : 'いいえ',
    workarounds: workarounds.length ? workarounds.join('\n') : 'なし'
  };
}

// ============================================================
// 4. AI 判定
// ============================================================

function readAssets_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_ASSET);
  if (!sh || sh.getLastRow() < 2) return [];
  const values = sh.getRange(2, 1, sh.getLastRow() - 1, ASSET_HEADERS.length).getValues();
  return values.filter(function (r) { return r[0]; }).map(function (r) {
    return { 製品: r[0], バージョン: r[1], 台数: r[2], 公開: r[3], 備考: r[4] };
  });
}

function judgeWithAI_(items, assets) {
  const map = {};

  for (let i = 0; i < items.length; i += AI_CHUNK_SIZE) {
    const chunk = items.slice(i, i + AI_CHUNK_SIZE);
    const label = (i / AI_CHUNK_SIZE + 1) + '回目(' + chunk.length + '件)';

    try {
      const prompt = buildJudgePrompt_(chunk, assets);
      const text = (AI_PROVIDER === 'claude') ? callClaude_(prompt) : callGemini_(prompt);

      const s = text.indexOf('[');
      const e = text.lastIndexOf(']');
      if (s === -1 || e === -1) throw new Error('JSON配列が見つかりません: ' + text.slice(0, 200));

      JSON.parse(text.slice(s, e + 1)).forEach(function (v) { map[v.ir] = v; });
      Logger.log('判定 ' + label + ' 成功');
    } catch (err) {
      Logger.log('判定 ' + label + ' 失敗: ' + err);
    }
    Utilities.sleep(1000);
  }

  Logger.log('判定に使用: ' + AI_PROVIDER + ' / 成功 ' + Object.keys(map).length + ' / 全 ' + items.length + ' 件');
  return map;
}

function buildJudgePrompt_(items, assets) {
  const advisories = items.map(function (it) {
    return {
      ir: it.ir,
      title: it.title,
      影響機能の記述: it.features,
      影響の種類: it.impacts,
      脆弱性の種類: it.cwes,
      cvss: it.cvss,
      severity: it.severity,
      無認証リモート: it.unauthRemote,
      対象製品の全影響バージョン: it.affected,
      自社該当バージョン: it.selfAffected,
      修正バージョン: it.fixes,
      緩和策: it.workarounds
    };
  });

  return 'あなたは社内の情報システム担当者です。以下の自社資産と、Fortinet が公開した脆弱性情報を突き合わせ、' +
    '各アドバイザリについて対応要否を判定してください。読み手は非エンジニアを含みます。\n\n' +
    '【自社資産】\n' + JSON.stringify(assets, null, 1) + '\n\n' +
    '【アドバイザリ】\n' + JSON.stringify(advisories, null, 1) + '\n\n' +
    '出力する各項目のルール:\n' +
    '- 判定: 「該当」「非該当」「要確認」のいずれか。自社該当バージョンが空なら非該当。' +
    'バージョン範囲が資産に一致すれば該当。判断材料が足りない場合のみ要確認。\n' +
    '- 優先度: 「緊急」「高」「中」「低」。ただし判定が「非該当」のときは必ず「-」とする。' +
    '「無認証リモート」が「はい」かつ資産がインターネット公開なら緊急。CVSS だけで機械的に決めない。\n' +
    '- 理由: 必ず「【理由】」で始め、判定の根拠になった事実だけを書く。感想や一般論は書かない。\n' +
    '    非該当の場合は、対象製品名を具体的に挙げ、それが自社資産にないことを書く。\n' +
    '      例:【理由】対象は FortiWeb / FortiADC。いずれも自社資産に登録がないため。\n' +
    '    該当の場合は、自社のバージョンと影響範囲の関係、影響機能を書く。\n' +
    '      例:【理由】自社の FortiOS 7.4.5 は影響範囲 7.4.0〜7.4.8 に含まれる。影響機能は captive portal。\n' +
    '    要確認の場合は、何が分からないから確認が要るのかを書く。\n' +
    '- 影響機能名: 「影響機能の記述」から機能の名前だけを抜き出す。' +
    '例:「Buffer over-read in captive portal」→「captive portal」。' +
    '複数あればカンマ区切り。特定できない場合のみ「不明」。推測で補わない。\n' +
    '- 何が起きるか: 攻撃が成立したときに何が起きるかを日本語1〜2文で。専門用語を避け、' +
    '非エンジニアが状況を想像できる書き方にする。アドバイザリに書かれた範囲だけを使い、' +
    '書かれていない被害を推測して付け加えない。\n' +
    '- 対応方針: 日本語1〜2文。何をすべきかを言い切る。緩和策があればそれにも触れる。\n' +
    '- 修正バージョン: 自社が上げるべき具体的なバージョンのみ。\n\n' +
    '出力は次のスキーマの JSON 配列のみ。前置き・コードフェンス・説明を一切含めないこと。\n' +
    '[{"ir":"FG-IR-...","判定":"該当","優先度":"高","理由":"【理由】...",' +
    '"影響機能名":"captive portal","何が起きるか":"...","対応方針":"...","修正バージョン":"..."}]';
}

function callGemini_(prompt) {
  const apiKey = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
  if (!apiKey) throw new Error('GEMINI_API_KEY がスクリプト プロパティに未設定です。');

  const url = 'https://generativelanguage.googleapis.com/v1beta/models/' +
              GEMINI_MODEL + ':generateContent';

  const options = {
    method: 'post',
    contentType: 'application/json',
    headers: { 'x-goog-api-key': apiKey },
    muteHttpExceptions: true,
    payload: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { responseMimeType: 'application/json', maxOutputTokens: 32768 }
    })
  };

  let res;
  for (let attempt = 1; attempt <= 3; attempt++) {
    res = UrlFetchApp.fetch(url, options);
    const code = res.getResponseCode();
    if (code === 200) break;

    if ((code === 503 || code === 429) && attempt < 3) {
      const wait = attempt * 5000;
      Logger.log('HTTP ' + code + ' のため ' + (wait / 1000) + '秒待って再試行します（' + attempt + '回目）');
      Utilities.sleep(wait);
      continue;
    }
    throw new Error('Gemini API エラー HTTP ' + code + ': ' + res.getContentText());
  }

  const body = JSON.parse(res.getContentText());
  const cand = (body.candidates || [])[0];

  if (cand && cand.finishReason && cand.finishReason !== 'STOP') {
    Logger.log('警告: finishReason=' + cand.finishReason + '（出力が途中で終わった可能性）');
  }

  const parts = (cand && cand.content && cand.content.parts) || [];
  return parts.map(function (p) { return p.text || ''; }).join('');
}

function callClaude_(prompt) {
  const apiKey = PropertiesService.getScriptProperties().getProperty('ANTHROPIC_API_KEY');
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY がスクリプト プロパティに未設定です。');

  const res = UrlFetchApp.fetch('https://api.anthropic.com/v1/messages', {
    method: 'post',
    contentType: 'application/json',
    headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
    muteHttpExceptions: true,
    payload: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: 8000,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (res.getResponseCode() !== 200) {
    throw new Error('Claude API エラー HTTP ' + res.getResponseCode() + ': ' + res.getContentText());
  }

  return (JSON.parse(res.getContentText()).content || [])
    .filter(function (c) { return c.type === 'text'; })
    .map(function (c) { return c.text; })
    .join('');
}

// ============================================================
// 5. 台帳への記録と Slack 通知
// ============================================================

function writeLedger_(items, verdicts) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh) throw new Error('「台帳」シートがありません。setup() を先に実行してください。');

  const now = new Date();

  const rows = items.map(function (it) {
    const v = verdicts[it.ir] || {};
    const verdict = v['判定'] || (it.error ? '取得失敗' : '未判定');
    // 非該当なら優先度は持たせない（判定との矛盾を防ぐ。コードで強制する）
    const priority = (verdict === '非該当') ? '' : (v['優先度'] || '');

    return [
      now,
      it.pubDate || '',
      it.ir,
      it.title,
      verdict,
      priority,
      v['理由'] || '',
      v['影響機能名'] || '',
      v['何が起きるか'] || '',
      v['対応方針'] || '',
      v['修正バージョン'] || it.fixes || '',
      it.selfAffected || '',
      it.cvss || '',
      it.severity || '',
      it.unauthRemote || '',
      it.workarounds || '',
      it.cves || '',
      it.cwes || '',
      it.vectors || '',
      it.features || '',
      it.impacts || '',
      it.affected || '',
      it.link,
      AI_PROVIDER
    ];
  });

  const startRow = sh.getLastRow() + 1;
  sh.getRange(startRow, 1, rows.length, LEDGER_HEADERS.length).setValues(rows);

  // 日付列の表示形式を整える
  const cDetected = LEDGER_HEADERS.indexOf('取得日時') + 1;
  const cPub = LEDGER_HEADERS.indexOf('公開日') + 1;
  sh.getRange(startRow, cDetected, rows.length, 1).setNumberFormat('yyyy/mm/dd hh:mm');
  sh.getRange(startRow, cPub, rows.length, 1).setNumberFormat('yyyy/mm/dd');
}

function notifySlack_(items, verdicts) {
  const url = PropertiesService.getScriptProperties().getProperty('SLACK_WEBHOOK_URL');
  if (!url) { Logger.log('SLACK_WEBHOOK_URL 未設定のため通知をスキップします。'); return; }

  const hits = items.filter(function (it) {
    const v = verdicts[it.ir] || {};
    return v['判定'] !== '非該当';
  });

  const lines = ['*Fortinet 脆弱性 新着 ' + items.length + ' 件（うち要対応 ' + hits.length + ' 件）*'];

  hits.forEach(function (it) {
    const v = verdicts[it.ir] || {};
    const icon = (v['優先度'] === '緊急') ? ':rotating_light:' : ':warning:';
    lines.push(
      icon + ' *<' + it.link + '|' + it.ir + '>* ' + it.title +
      '\n　判定: ' + (v['判定'] || '未判定') +
      ' / 優先度: ' + (v['優先度'] || '-') +
      ' / CVSS: ' + (it.cvss || '-') +
      ' / 無認証リモート: ' + (it.unauthRemote || '-') +
      (v['理由'] ? '\n　' + v['理由'] : '') +
      (v['影響機能名'] ? '\n　影響機能: ' + v['影響機能名'] : '') +
      (v['何が起きるか'] ? '\n　何が起きるか: ' + v['何が起きるか'] : '') +
      '\n　' + (v['対応方針'] || '（判定なし。手動で確認してください）') +
      (v['修正バージョン'] ? '\n　修正: ' + v['修正バージョン'] : '') +
      (it.workarounds && it.workarounds !== 'なし' ? '\n　緩和策: ' + it.workarounds : '')
    );
  });

  if (hits.length === 0) lines.push('自社資産に該当するものはありませんでした。');

  UrlFetchApp.fetch(url, {
    method: 'post',
    contentType: 'application/json',
    muteHttpExceptions: true,
    payload: JSON.stringify({ text: lines.join('\n\n') })
  });
}

// ============================================================
// 動作確認用
// ============================================================

function testProps() {
  const p = PropertiesService.getScriptProperties();
  Logger.log('AI_PROVIDER        : ' + AI_PROVIDER);
  Logger.log('GEMINI_API_KEY     : ' + (p.getProperty('GEMINI_API_KEY') ? 'OK' : '未設定'));
  Logger.log('ANTHROPIC_API_KEY  : ' + (p.getProperty('ANTHROPIC_API_KEY') ? 'OK' : '未設定'));
  Logger.log('SLACK_WEBHOOK_URL  : ' + (p.getProperty('SLACK_WEBHOOK_URL') ? 'OK' : '未設定'));
}

function testRss() {
  const items = fetchRssItems_();
  Logger.log('取得件数: ' + items.length);
  Logger.log(JSON.stringify(items[0], null, 2));
}

function testCsaf() {
  Logger.log(JSON.stringify(fetchCsaf_('https://fortiguard.fortinet.com/psirt/FG-IR-26-154'), null, 2));
}

function testFilter() {
  const csaf = fetchCsaf_('https://fortiguard.fortinet.com/psirt/FG-IR-26-154');
  const assets = readAssets_();
  Logger.log('--- 全件 ---\n' + csaf.affected);
  Logger.log('--- 自社該当のみ ---\n' + filterAffectedForAssets_(csaf.affected, assets));
}

/** 該当ケースと非該当ケースの両方で、理由が書かれるか確認する。 */
function testAi() {
  const dummy = [
    {
      ir: 'FG-IR-26-154',
      title: 'Buffer overread in authd and wad daemon',
      features: 'Buffer over-read in captive portal',
      impacts: 'Information disclosure',
      cwes: 'CWE-126 Buffer Over-read',
      cvss: 4.1, severity: 'MEDIUM', unauthRemote: 'いいえ',
      affected: 'FortiOS >=7.4.0|<=7.4.8',
      selfAffected: 'FortiOS >=7.4.0|<=7.4.8',
      fixes: 'FortiOS 7.4: Upgrade to 7.4.9 or above',
      workarounds: 'なし'
    },
    {
      ir: 'FG-IR-26-999',
      title: 'SQL injection in FortiWeb',
      features: 'SQL injection in management interface',
      impacts: 'Execute unauthorized code or commands',
      cwes: 'CWE-89 SQL Injection',
      cvss: 9.1, severity: 'CRITICAL', unauthRemote: 'はい',
      affected: 'FortiWeb >=7.0.0|<=7.0.5',
      selfAffected: '',
      fixes: 'FortiWeb 7.0: Upgrade to 7.0.6 or above',
      workarounds: 'なし'
    }
  ];
  const assets = [{ 製品: 'FortiOS', バージョン: '7.4.5', 台数: 2, 公開: 'あり', 備考: 'SSL-VPN 有効' }];
  Logger.log(JSON.stringify(judgeWithAI_(dummy, assets), null, 2));
}
