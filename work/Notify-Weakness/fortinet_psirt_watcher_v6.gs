/**
 * Fortinet PSIRT Watcher for Google Apps Script  (v6 / 行の単位と判定責務の見直し)
 * ==================================================================
 * v5 からの変更点（すべて実データ50件の検証にもとづく。詳細は設計書v3）:
 *
 *   1. 行の単位を「アドバイザリ1件」から「CVE × 対象製品 1件」に変更した。
 *      CSAF の vulnerabilities[] 要素がちょうどこの粒度で公開されているため、
 *      分割ロジックは不要で、v5 がやっていた「まとめる」処理をやめるだけでよい。
 *      これにより CVSS・深刻度・影響バージョン・修正版がどの CVE の
 *      どの製品のものか、セルを見ただけで確定する。
 *
 *   2. 通知判定をコードに戻した。v5 は AI にバージョン該非を判断させていたが、
 *      これは決定的な計算であり AI を使う理由がない。実測で 30 行中 20 行が
 *      「未判定」になっていた原因もここにある（AI 応答が落ちると判定ごと消える）。
 *      v6 は全行の通知判定をコードで確定させ、AI が落ちても判定は残る。
 *
 *   3. 自社利用バージョンを実際に数値比較するようにした。v5 の
 *      filterAffectedForAssets_() は製品名の前方一致だけで、バージョンを
 *      一切見ていなかった。つまり「自社該当バージョン」列は
 *      「自社が持っている製品の影響バージョン行」でしかなかった。
 *
 *   4. アドバイザリ HTML の取得をやめた。CSAF の URL は RSS のタイトルと
 *      FG-IR 番号から組み立てられる（実測 50/50 で成功）。
 *      取得先が filestore.fortinet.com だけになり、通信回数も半分になる。
 *
 *   5. 列構成を 17 列に整理した（レビュー指摘を反映）。
 *      優先度・CWE・CVSSベクター・取得日時などの根拠のない列や重複列を削除し、
 *      「利用有無の確認方法／確認コマンド」を追加した。
 *
 *   6. 未判定行の削除をやめた。v5 は判定できなかった行を消して再取得していたが、
 *      これは取得済みの事実まで捨てる。v6 は行を残し、AI 列が空の行だけを
 *      次回に埋め直す（backfillAiColumns_）。
 *
 * 列構成が変わるため、既存の台帳はデータ行を全削除してから使ってください。
 *   手順: migrateLedgerHeaders() → 2行目以降を全削除 → main()
 *
 * ------------------------------------------------------------------
 * スクリプト プロパティ:
 *   GEMINI_API_KEY / ANTHROPIC_API_KEY / SLACK_WEBHOOK_URL
 *
 * CSAF とは:
 *   Fortinet が脆弱性情報を機械可読な JSON で公開しているファイルのこと。
 *   HTML を読み取る必要がなく、影響バージョン・修正版・CVSS・影響の種類が
 *   構造化された状態で入っている。
 */

// ============================================================
// 設定
// ============================================================

/** 'gemini' か 'claude' */
const AI_PROVIDER = 'gemini';

const GEMINI_MODEL = 'gemini-3.6-flash';
const CLAUDE_MODEL = 'claude-sonnet-5';

const RSS_URL = 'https://filestore.fortinet.com/fortiguard/rss/ir.xml';
const CSAF_BASE = 'https://filestore.fortinet.com/fortiguard/psirt/csaf_';

const SHEET_LEDGER = '台帳';
const SHEET_ASSET = '資産';

/**
 * 処理したアドバイザリを 1 行ずつ記録するシート。
 *
 * 台帳には自社製品の行しか書かない。そのままだと、他社製品だけのアドバイザリは
 * 台帳に痕跡が残らず、次回また新着として取り直してしまう（1.8 で直したのと同じ失敗）。
 * さらに「今月 Fortinet から公表：N 件」という分母も出せなくなる。
 * 取得した事実はここに残し、台帳は判断に使う行だけに保つ。
 */
const SHEET_STATE = '処理済み';

/** 1回の実行で処理するアドバイザリ数の上限（GAS の 6 分制限対策） */
const MAX_ADVISORIES_PER_RUN = 25;

/**
 * 「対象外」の行を台帳に残す期間（か月）。0 で無制限。
 *
 * 古い行が邪魔になるのは「対象外」だけである。
 * 対象と要確認は、古くても自社がまだ直していない事実を指しているので必ず残す。
 * 実データで一律カットを試したところ、まだ影響下にある対象 2 件
 * （CVE-2025-31514 / CVE-2025-54821）が消えた。年齢で切ってはいけない。
 *
 * 対象外を落としても分母は壊れない。処理済みシートには全件残る。
 */
const KEEP_OUT_OF_SCOPE_MONTHS = 3;

/** Slack に個別表示する最大件数。超えた分は「ほか N 件」にまとめる */
const SLACK_MAX_ITEMS = 5;

/** 影響ありが 0 件のときも Slack に流すか。日次実行では false が静か */
const NOTIFY_WHEN_NO_HITS = false;

/** 1回の AI 呼び出しで処理する行数。AI に渡すのは通知対象と判定不能だけなので小さくてよい */
const AI_CHUNK_SIZE = 5;

/**
 * 自社影響の値。
 * 「対象」は自社バージョンが影響範囲に入っていることであって、
 * 影響機能を使っていることでも、被害が確定したことでもない。
 * 使っているかを調べるのは人であり、その方法を「利用有無の確認方法」に出す。
 */
const V_TARGET = 'あり';
const V_OUT = 'なし';
const V_UNKNOWN = '要確認';   // 判定に必要な情報が足りず、自動で決められなかった

/**
 * 台帳の列。左ほど判断に使う。
 * 16 列目までがレビューで合意した構成。17 列目の「公開日」だけは追加している。
 * 理由: 月次サマリの「今月Fortinetから公表: N件」は公開日がないと出せない。
 *       分母の確定が本ツールの第一目的なので、参照情報として右端に置いて残した。
 */
/**
 * 台帳の列（12列）。
 *
 * 「対応を決めるのに要るか」だけで選んでいる。実データで確かめて落とした列:
 *   深刻度               … CVSS の関数（56/56 が帯と一致）
 *   無認証リモート       … 通知対象10行が全て「いいえ」。優先度判定が保留中で行き先がない
 *   自社利用バージョン   … 値が1種類しかなく、通知判定根拠に10/10で再掲されている
 *   脆弱性の影響バージョン … 通知対象10行で計44行。根拠が該当範囲だけを10/10で名指ししている
 *   対応方針             … 修正バージョンの日本語訳でしかない
 *
 * 落とした情報は消えていない。バージョンの根拠は「通知判定根拠」の1文に、
 * 修正指示は「対応」に日本語で入る。
 */
/**
 * 台帳の 12 列。並びは「読む順序」で決めている。
 *
 * 根拠（2026-08-12 に一次情報で確認）:
 *  ・NN/g「最初の列は人が読める識別子にする」「列順は利用者にとっての重要度を反映する」
 *      https://www.nngroup.com/articles/data-tables/
 *  ・GOV.UK「多くの人が探している情報を最初の数列に置く」
 *      https://guidance.publishing.service.gov.uk/formatting-content/text-formatting/tables/
 *  ・CISA KEV の実物は cveID を先頭に置き、CVSS 列を持たない
 *  ・IPA「ソフトウェア脆弱性関連情報管理シート」は
 *      ソフトウェア → 利用バージョン → 影響を受けるか → CVSS → … の順。
 *      危険度から入る設計にはなっていない
 *
 * 公開日を先頭にしたのは、実際の読み方が「今月の公表はどれか」から始まるため。
 * RSS 50 件は 9 か月分にまたがっており、台帳でも複数月が混在する。
 */
const LEDGER_HEADERS = [
  // --- A. いつ・何の件か・自社に関係あるか（左 5 列は固定表示） ---
  '最終更新日',           // 1  Fortinet が最後に情報を変えた日
  'CVE',                  // 2  人が読める識別子
  '自社影響',             // 3  あり / なし / 要確認
  'CVSS',                 // 4  「8.3（HIGH）」のように帯を併記
  '対象サービス／製品',   // 5
  // --- B. 何の脆弱性か。総論 → 概論 の順で読ませる ---
  '脆弱性名',             // 6  まず正式名（英語）
  'ユーザ影響',           // 7  その影響をざっくり一言で
  '影響機能名',           // 8  だから影響する機能はこれ
  // --- C. なぜそう判定したか ---
  '判定根拠',             // 9
  // --- D. で、何をするか ---
  '利用有無の確認方法',   // 10
  '対応',                 // 11
  // --- E. 出典 ---
  'Fortinetアドバイザリ'  // 12
];

/** 資産シート。「製品」には Fortinet が使う製品名をそのまま書く（listProductNames_ で確認できる） */
const ASSET_HEADERS = ['製品', 'バージョン', '台数', 'インターネット公開', '備考'];

/** 処理済みシート。分母（今月の公表件数）はここから数える。 */
const STATE_HEADERS = ['最終更新日', '初回公表日', 'FG-IR', 'タイトル', '台帳の行数', '対象製品'];

/**
 * 影響機能名の統制語彙。表記ゆれを抑えるため AI にこの中から選ばせる。
 * 実データ（台帳50件）で CLI / CLI command / CLI commands のような
 * ゆれが出ていたことへの対処。該当する語がなければ原文の語句をそのまま使わせる。
 */
const FEATURE_VOCAB = [
  'SSL-VPN', 'IPsec VPN', 'captive portal', 'web filter', 'CLI', 'GUI（管理画面）',
  'REST API', 'SSH', 'SNMP', 'LDAP認証', 'SAML認証', '二要素認証（2FA）',
  'FortiGuard通信', 'ログ・デバッグ出力', '管理者アカウント', 'HA（冗長構成）',
  'wireless controller（CAPWAP）', 'アンチウイルス／IPSエンジン',
  'security fabric', 'FortiToken', 'AD Connector', 'セキュリティプロファイル'
];

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
    formatLedger_(ledger);
    Logger.log('「台帳」シートを作成しました。');
  } else {
    Logger.log('「台帳」シートは既にあります。migrateLedgerHeaders() で列を更新してください。');
  }

  let asset = ss.getSheetByName(SHEET_ASSET);
  if (!asset) {
    asset = ss.insertSheet(SHEET_ASSET);
    asset.appendRow(ASSET_HEADERS);
    asset.appendRow(['FortiOS', '7.4.6', 2, 'あり', 'SSL-VPN 有効']);
    asset.setFrozenRows(1);
    Logger.log('「資産」シートを作成しました。中身を自社の内容に書き換えてください。');
    Logger.log('※「製品」列は Fortinet の製品名表記に合わせてください。listProductNames_() で実際の表記を一覧できます。');
    Logger.log('※ ここに書いた製品だけが台帳に載ります。');
  } else {
    Logger.log('「資産」シートは既にあります。');
  }

  let state = ss.getSheetByName(SHEET_STATE);
  if (!state) {
    state = ss.insertSheet(SHEET_STATE);
    state.appendRow(STATE_HEADERS);
    state.setFrozenRows(1);
    state.setColumnWidth(1, 100);
    state.setColumnWidth(2, 100);
    state.setColumnWidth(3, 130);
    state.setColumnWidth(4, 400);
    state.setColumnWidth(5, 90);
    state.setColumnWidth(6, 280);
    Logger.log('「処理済み」シートを作成しました。分母（今月の公表件数）はここから数えます。');
  } else {
    Logger.log('「処理済み」シートは既にあります。');
  }
}

/** 台帳の見出し行を最新の構成に更新する。列順が変わったのでデータ行は削除してください。 */
function migrateLedgerHeaders() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh) throw new Error('「台帳」シートがありません。setup() を実行してください。');

  // 列数が減る移行では、見出しを上書きするだけでは足りない。
  // v5 は 24 列だったため、18 列目以降に古い見出し（CWE / CVSSベクター /
  // 影響機能 / 何が起きるか / 影響バージョン / URL / 判定AI）が残る。
  const lastCol = sh.getLastColumn();
  if (lastCol > LEDGER_HEADERS.length) {
    sh.deleteColumns(LEDGER_HEADERS.length + 1, lastCol - LEDGER_HEADERS.length);
    Logger.log('余分な ' + (lastCol - LEDGER_HEADERS.length) + ' 列（v5 の残骸）を削除しました。');
  }

  sh.getRange(1, 1, 1, LEDGER_HEADERS.length).setValues([LEDGER_HEADERS]);
  sh.setFrozenRows(1);
  formatLedger_(sh);
  Logger.log('台帳の見出しを ' + LEDGER_HEADERS.length + ' 列に更新しました。');

  // 処理済みシートの見出しも合わせる。
  // 既読判定は列の位置で読むため、見出しが古いままだと
  // 「FG-IR」の位置にタイトルを読みに行き、既読が一切当たらなくなる。
  const state = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_STATE);
  if (state) {
    const cur = state.getRange(1, 1, 1, Math.max(state.getLastColumn(), 1)).getDisplayValues()[0];
    const same = cur.length === STATE_HEADERS.length &&
                 STATE_HEADERS.every(function (h, i) { return cur[i] === h; });
    if (!same) {
      if (state.getLastColumn() > STATE_HEADERS.length) {
        state.deleteColumns(STATE_HEADERS.length + 1, state.getLastColumn() - STATE_HEADERS.length);
      }
      state.getRange(1, 1, 1, STATE_HEADERS.length).setValues([STATE_HEADERS]);
      state.setFrozenRows(1);
      Logger.log('処理済みシートの見出しを更新しました（列の意味が変わったため、2行目以降も削除してください）。');
    }
  } else {
    Logger.log('※「処理済み」シートがありません。setup() を実行してください。');
  }

  Logger.log('※ 列構成が変わっています。台帳・処理済みとも 2 行目以降を削除してから main() を実行してください。');
}

function createDailyTrigger() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (t.getHandlerFunction() === 'main') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('main').timeBased().atHour(9).everyDays(1).create();
  Logger.log('毎日 9 時台に main() を実行するトリガーを作成しました。');
}

function main() {
  const assets = readAssets_();
  if (!assets.length) {
    Logger.log('警告: 資産シートが空です。すべての行が「要確認」になります。');
  }

  const items = fetchRssItems_();

  // RSS 全件の CSAF を取得する。
  //
  // Fortinet は既存のアドバイザリを改訂して、影響製品や影響バージョンを追加する。
  // 実測では RSS 50 件のうち 6 件が改訂もので、うち 3 件が FortiOS を含んでいた。
  // 改訂されても FG-IR 番号は変わらず、RSS の pubDate も初回公表日のまま動かない。
  // つまり「最終更新日」は CSAF を開かないと分からない。
  // FG-IR だけで既読判定すると、改訂で新たに自社が対象になった件を永久に見落とす。
  const fetched = fetchAllCsaf_(items);

  const known = getKnownAdvisories_();
  warnIfFeedOverflowed_(items, known);

  const todo = fetched.filter(function (f) {
    const prev = known[f.item.ir];
    if (!prev) return true;                       // 新規
    return prev !== ymd_(f.updatedAt);            // 改訂された
  }).slice(0, MAX_ADVISORIES_PER_RUN);

  const revised = todo.filter(function (f) { return known[f.item.ir]; });
  if (revised.length) {
    Logger.log('改訂を検知: ' + revised.map(function (f) {
      return f.item.ir + '（' + known[f.item.ir] + ' → ' + ymd_(f.updatedAt) + '）';
    }).join(', '));
  }

  if (todo.length === 0) {
    Logger.log('新着・改訂ともになし。AI 未生成行の補完だけ行います。');
    backfillAiColumns_();
    return;
  }
  Logger.log('処理対象 ' + todo.length + ' 件（新規 ' + (todo.length - revised.length) +
             ' / 改訂 ' + revised.length + '）');

  // 改訂されたアドバイザリは、古い行を消してから入れ直す。
  // 残したままだと、同じ FG-IR の古い判定と新しい判定が並ぶ。
  if (revised.length) {
    const ids = revised.map(function (f) { return f.item.ir; });
    removeRowsFor_(ids);
  }

  // 1アドバイザリ → 複数行（CVE × 製品）に展開する
  let rows = [];
  todo.forEach(function (f) {
    if (f.error) {
      Logger.log('CSAF 取得失敗: ' + f.item.ir + ' / ' + f.error);
      rows.push(errorRow_(f.item, f.error));
      return;
    }
    rows = rows.concat(extractRows_(f.csaf, f.item));
  });
  Logger.log('展開後の行数: ' + rows.length);

  // 自社影響はコードで確定させる。AI の成否に依存させない
  rows.forEach(function (r) { decideNotification_(r, assets); });

  const counts = countVerdicts_(rows);
  Logger.log('全 ' + rows.length + ' 行: 対象 ' + counts[V_TARGET] +
             ' / 要確認 ' + counts[V_UNKNOWN] + ' / 対象外 ' + counts[V_OUT]);
  logUnownedProducts_(rows);

  // 取得した事実は、台帳に載せるかどうかに関わらず全件記録する。
  // ここが既読管理と分母の根拠になる。
  writeState_(todo, rows);

  // 台帳に載せるのは判断に使う行だけ
  const ledgerRows = rows.filter(function (r) { return isLedgerRow_(r, assets); });
  Logger.log('台帳に載せる行: ' + ledgerRows.length + ' / ' + rows.length +
             '（自社製品以外の対象外 ' + (rows.length - ledgerRows.length) + ' 行は処理済みシートのみ）');

  // AI に渡すのは対象と要確認だけ
  const needAi = ledgerRows.filter(function (r) { return r.verdict !== V_OUT; });
  if (needAi.length) {
    try {
      enrichWithAI_(needAi);
    } catch (e) {
      Logger.log('AI 生成に失敗しました。自社影響と根拠は記録されます: ' + e);
    }
  }

  writeLedger_(ledgerRows);
  sortLedger_();
  notifySlack_(ledgerRows);
  Logger.log('完了しました。');
}

/**
 * 台帳に載せる行かどうか。
 *
 * 載せるのは次のいずれか。
 *   ・自社が保有している製品の行（対象・対象外を問わない）
 *     → 対象外であっても「なぜ対応不要か」の根拠になるため残す
 *   ・製品を特定できなかった行（CSAF に脆弱性情報が無いアドバイザリなど）
 *     → 人が読まないと判断できないため、必ず表に出す
 *
 * 保有していない製品の行は台帳に載せない。処理済みシートには残る。
 */
function isLedgerRow_(row, assets) {
  if (!row.product) return true;
  if (!assetsForProduct_(assets, row.product).length) return false;

  // 古い「対象外」は落とす。
  // 対象と要確認は年齢で切らない。古いということは、その分だけ長く直していないという意味であり、
  // 消す理由にならない（一律カットを試すと、まだ影響下の対象が消えることを実データで確認済み）。
  if (row.verdict === V_OUT && isStaleOutOfScope_(row.pubDate)) return false;

  return true;
}

/** 「対象外」を台帳から落としてよいほど古いか。 */
function isStaleOutOfScope_(pubDate) {
  if (!KEEP_OUT_OF_SCOPE_MONTHS) return false;
  if (!(pubDate instanceof Date) || isNaN(pubDate.getTime())) return false;

  const limit = new Date();
  limit.setMonth(limit.getMonth() - KEEP_OUT_OF_SCOPE_MONTHS);
  return pubDate < limit;
}

// ============================================================
// 1. RSS 取得と CSAF の URL 導出
// ============================================================

/** "Tue, 14 Jul 2026 00:00:00 -0700" を Date にする。失敗したら元の文字列を返す。 */
function parsePubDate_(s) {
  if (!s) return '';
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d;
}

/**
 * アドバイザリのタイトルを CSAF ファイル名のスラッグに変換する。
 * 例: "Buffer overread in authd and wad daemon"
 *      → "buffer-overread-in-authd-and-wad-daemon"
 * 実測: RSS 50 件すべてでこの規則から正しい URL を組み立てられた。
 */
function slugifyTitle_(title) {
  return String(title || '')
    .toLowerCase()
    .replace(/['"‘’“”]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function csafUrlFor_(item) {
  return CSAF_BASE + slugifyTitle_(item.title) + '_' + String(item.ir).toLowerCase() + '.json';
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
    const m = /FG-IR-[\w-]+/.exec(link || '');
    return {
      ir: m ? m[0] : link,
      title: item.getChildText('title'),
      link: link,
      pubDate: parsePubDate_(item.getChildText('pubDate'))
    };
  });
}

// ============================================================
// 2. CSAF の取得と行への展開
// ============================================================

/**
 * CSAF を取得する。まず RSS のタイトルから URL を組み立てて取りにいき、
 * 失敗した場合だけアドバイザリ HTML から csaf_url を拾う経路に落とす。
 * HTML 経路は社内プロキシで遮断される場合があるため、あくまで保険。
 */
function fetchCsaf_(item) {
  const direct = csafUrlFor_(item);
  let res = UrlFetchApp.fetch(direct, { muteHttpExceptions: true });
  if (res.getResponseCode() === 200) return JSON.parse(res.getContentText());

  Logger.log('スラッグ導出に失敗（HTTP ' + res.getResponseCode() + '）。HTML 経由で再試行: ' + item.ir);
  const html = UrlFetchApp.fetch(item.link, { muteHttpExceptions: true }).getContentText();
  const m = /csaf_url=(https:\/\/[^"'&\s]+\.json)/.exec(html);
  if (!m) throw new Error('CSAF の URL を特定できませんでした');

  res = UrlFetchApp.fetch(m[1], { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) throw new Error('CSAF 取得失敗 HTTP ' + res.getResponseCode());
  return JSON.parse(res.getContentText());
}

/**
 * RSS の枠から取りこぼした可能性を検知する。
 *
 * Fortinet の RSS は常に 50 件しか持たない。実測の公表ペースは月 11 件（最大 18 件）
 * なので、3 か月ほど実行しないと古いものが枠から押し出され、二度と流れてこない。
 * **押し出されてもエラーにはならず、静かに消える。** 分母を主張するツールでは致命的なので、
 * 前回との「重なり」を数えて連続性を確かめる。
 *
 * 重なりが 0 件＝ RSS の全件が未知＝前回以降に 50 件以上入れ替わった、
 * つまり取りこぼしたかどうかを自力では判断できない状態である。
 */
function warnIfFeedOverflowed_(items, known) {
  if (!Object.keys(known).length) return;   // 初回は判定できない

  const overlap = items.filter(function (it) { return known[it.ir]; }).length;

  if (overlap === 0) {
    Logger.log('警告: RSS 50 件のいずれも記録にありません。');
    Logger.log('  前回の実行から 50 件以上が入れ替わり、枠から押し出されたものがある可能性があります。');
    Logger.log('  https://www.fortiguard.com/psirt を人が確認し、抜けが無いか突き合わせてください。');
  } else if (overlap < 5) {
    Logger.log('注意: 前回との重なりが ' + overlap + ' 件しかありません（50 件中）。');
    Logger.log('  実行間隔が空きすぎています。取りこぼす前に実行頻度を上げてください。');
  } else {
    Logger.log('前回との重なり: ' + overlap + ' / ' + items.length + ' 件（連続性あり）');
  }
}

/** Date を 'yyyy-mm-dd' にする。既読判定の突合キーに使うため文字列で揃える。 */
function ymd_(d) {
  if (!(d instanceof Date) || isNaN(d.getTime())) return String(d || '');
  return d.getFullYear() + '-' +
         ('0' + (d.getMonth() + 1)).slice(-2) + '-' +
         ('0' + d.getDate()).slice(-2);
}

/**
 * RSS 全件の CSAF をまとめて取得する。
 *
 * UrlFetchApp.fetchAll() は複数リクエストを並行して投げるため、
 * 1 件ずつ fetch するより大幅に速い（50 件でも数秒）。
 * 改訂の検知には全件の最終更新日が要るので、既読のものも取りに行く。
 *
 * 戻り値: [{ item, csaf, updatedAt, error }]
 */
function fetchAllCsaf_(items) {
  const reqs = items.map(function (it) {
    return { url: csafUrlFor_(it), muteHttpExceptions: true };
  });

  let res;
  try {
    res = UrlFetchApp.fetchAll(reqs);
  } catch (e) {
    Logger.log('fetchAll に失敗したため 1 件ずつ取得します: ' + e);
    res = reqs.map(function (r) { return UrlFetchApp.fetch(r.url, r); });
  }

  let ok = 0;
  const out = items.map(function (it, i) {
    const r = res[i];
    try {
      if (!r || r.getResponseCode() !== 200) {
        // スラッグ導出が外れた場合だけ HTML 経由に落とす
        const csaf = fetchCsaf_(it);
        ok++;
        return { item: it, csaf: csaf, updatedAt: csafUpdatedAt_(csaf, it), error: '' };
      }
      const csaf = JSON.parse(r.getContentText());
      ok++;
      return { item: it, csaf: csaf, updatedAt: csafUpdatedAt_(csaf, it), error: '' };
    } catch (e) {
      return { item: it, csaf: null, updatedAt: it.pubDate, error: String(e) };
    }
  });

  Logger.log('CSAF 取得: ' + ok + ' / ' + items.length + ' 件');
  return out;
}

function csafUpdatedAt_(csaf, item) {
  const t = ((csaf || {}).document || {}).tracking || {};
  if (t.current_release_date) return new Date(t.current_release_date);
  if (t.initial_release_date) return new Date(t.initial_release_date);
  return item.pubDate;
}

/** CVSS ベクターから「無認証・リモート・利用者操作不要」かを判定する。LLM 不使用。 */
function isUnauthRemote_(vector) {
  if (!vector) return false;
  return /AV:N/.test(vector) && /PR:N/.test(vector) && /UI:N/.test(vector);
}

function noteText_(v, matcher) {
  const notes = v.notes || [];
  for (let i = 0; i < notes.length; i++) {
    if (matcher(notes[i])) return String(notes[i].text || '').trim();
  }
  return '';
}

/**
 * CSAF の vulnerabilities[] を、そのまま台帳の行にする。
 * 実測（50アドバイザリ / 97要素）で、1要素に複数製品系列が混在した例は 0 件だった。
 * つまり CSAF の 1 要素が「CVE × 製品」1 行にちょうど対応する。
 */
function extractRows_(csaf, item) {
  const doc = csaf.document || {};
  const tracking = doc.tracking || {};
  const advisoryId = tracking.id || item.ir;
  // 台帳に出すのは「最終更新日」であって初回公表日ではない。
  // Fortinet は既存アドバイザリを改訂して影響製品・影響バージョンを追加する。
  // 初回公表日で並べると、改訂で新たに自社が対象になった件が
  // 何か月も前の日付として沈み、「今月見るべきもの」から漏れる。
  // 初回公表日は処理済みシートに残す。
  const updatedAt = tracking.current_release_date
    ? new Date(tracking.current_release_date)
    : (tracking.initial_release_date ? new Date(tracking.initial_release_date) : item.pubDate);
  const initialAt = tracking.initial_release_date
    ? new Date(tracking.initial_release_date)
    : updatedAt;

  // 脆弱性名は document.title を使う。
  // vulnerabilities[].title は "FortiOS - LOW - FG-IR-24-257" のような
  // 製品・深刻度・IDを並べた内部管理用の文字列で、脆弱性の名前ではない。
  const vulnName = String(doc.title || item.title || '').trim();

  // CSAF に vulnerabilities キーが無いアドバイザリがある（実測 50 件中 3 件）。
  // Linux Kernel や npm パッケージなど他社製コンポーネント由来の告知で、
  // 製品・バージョンの対応表が CSAF に載っていない（product_tree も空）。
  //
  // ここで空配列を返すと行が 1 つも作られない。行が無いということは
  // 16 列目に FG-IR が残らないため既読にもならず、
  //   ・分母から永久に欠落する（本ツールの第一目的を壊す）
  //   ・毎回取得し直し、実行枠を食い続ける
  // という二重の実害になる。1 行立てて人に回す。
  const vulns = csaf.vulnerabilities || [];
  if (!vulns.length) {
    Logger.log('vulnerabilities なし: ' + advisoryId + '（判定不能として1行記録します）');
    return [noVulnRow_(item, advisoryId, updatedAt, initialAt, vulnName)];
  }

  return vulns.map(function (v) {
    // 製品名は scores[].products が正。known_affected の先頭語では
    // "FortiSOAR PaaS" のような空白入りの名前を切り落としてしまう。
    const products = [];
    let score = '', severity = '', vector = '';

    (v.scores || []).forEach(function (s) {
      (s.products || []).forEach(function (p) { pushUnique_(products, p); });
      const c = s.cvss_v4 || s.cvss_v3 || {};
      if (c.vectorString && !vector) vector = c.vectorString;
      if (c.baseScore !== undefined && (score === '' || c.baseScore > score)) {
        score = c.baseScore;
        severity = c.baseSeverity || '';
      }
    });

    const affected = ((v.product_status || {}).known_affected || []);
    const product = products[0] || guessProductFromAffected_(affected);

    const fixes = [];
    (v.remediations || []).forEach(function (r) {
      if (r.category === 'vendor_fix' && r.details) pushUnique_(fixes, r.details);
    });

    const workaround = noteText_(v, function (n) {
      return String(n.title || '').toLowerCase().indexOf('workaround') !== -1;
    });

    return {
      advisoryId: advisoryId,
      advisoryUrl: item.link,
      pubDate: updatedAt,
      initialDate: initialAt,
      title: vulnName,
      cve: v.cve || '',
      product: product,
      cvss: score,
      severity: severity,
      vector: vector,
      unauthRemote: isUnauthRemote_(vector) ? 'はい' : 'いいえ',
      affected: affected,                       // 配列のまま持つ
      summary: noteText_(v, function (n) { return n.category === 'summary'; }),
      impact: (v.threats || [])
        .filter(function (t) { return t.category === 'impact'; })
        .map(function (t) { return t.details; })
        .join(', '),
      fixesRaw: fixes.join('\n'),
      workaround: (workaround && workaround.toUpperCase() !== 'N/A') ? workaround : '',
      // 以下はこのあと埋める
      verdict: '', reason: '', selfVersion: '', fixVersion: '',
      feature: '', impactJa: '', howToCheck: '', plan: ''
    };
  });
}

/**
 * CSAF に脆弱性情報が無いアドバイザリ用の 1 行。
 * 使える情報はタイトル・公開日・URL だけなので、判定はせず人に回す。
 * タイトルに CVE 番号が書かれていることがあるので拾う
 * （例: "Linux Kernel Vulnerability copy.fail - CVE-2026-31431"）。
 */
function noVulnRow_(item, advisoryId, pubDate, initialAt, vulnName) {
  const m = /CVE-\d{4}-\d{4,}/.exec(vulnName || '');
  return {
    advisoryId: advisoryId,
    advisoryUrl: item.link,
    pubDate: pubDate,
    initialDate: initialAt,
    title: vulnName,
    cve: m ? m[0] : '',
    product: '',
    cvss: '', severity: '', vector: '', unauthRemote: '',
    affected: [], summary: vulnName, impact: '', fixesRaw: '', workaround: '',
    verdict: V_UNKNOWN,
    reason: 'この情報元だけでは自社への影響を自動判定できません。アドバイザリを人が読んで判定してください。',
    selfVersion: '', fixVersion: '',
    feature: '', impactJa: '', howToCheck: '', plan: ''
  };
}

/** scores に products がない場合の保険。既知の製品名で最長一致させる。 */
function guessProductFromAffected_(affected) {
  if (!affected.length) return '';
  const first = String(affected[0]);
  const m = /^([A-Za-z][\w-]*(?:\s(?:PaaS|Cloud|on-premise|Manager))?)/.exec(first);
  return m ? m[1] : first.split(' ')[0];
}

function errorRow_(item, msg) {
  return {
    advisoryId: item.ir, advisoryUrl: item.link,
    pubDate: item.pubDate, initialDate: item.pubDate,
    title: item.title, cve: '', product: '', cvss: '', severity: '', vector: '',
    unauthRemote: '', affected: [], summary: '', impact: '', fixesRaw: '',
    workaround: '', verdict: V_UNKNOWN,
    reason: 'アドバイザリ情報を取得できませんでした（' + msg + '）。手動で確認してください。',
    selfVersion: '', fixVersion: '', feature: '', impactJa: '', howToCheck: '', plan: ''
  };
}

function pushUnique_(arr, val) {
  if (val && arr.indexOf(val) === -1) arr.push(val);
}

// ============================================================
// 3. バージョン比較（コードで実行・LLM 不使用）
// ============================================================

/** "7.4.5" → [7,4,5]。数値に解釈できない要素があれば null（＝比較不能）を返す。 */
function parseVersion_(s) {
  if (s === undefined || s === null || s === '') return null;
  const parts = String(s).trim().split('.');
  const nums = [];
  for (let i = 0; i < parts.length; i++) {
    const n = parseInt(parts[i], 10);
    if (isNaN(n) || !/^\d+$/.test(parts[i].trim())) return null;
    nums.push(n);
  }
  return nums.length ? nums : null;
}

/** a < b なら -1、a > b なら 1、等しければ 0。桁数が違う場合は 0 で埋める。 */
function compareVersion_(a, b) {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = (a[i] === undefined) ? 0 : a[i];
    const y = (b[i] === undefined) ? 0 : b[i];
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** known_affected の文字列から製品名の部分を取り除き、バージョン表記だけにする。 */
function stripProductPrefix_(entry, product) {
  const e = String(entry || '').trim();
  if (product && e.toLowerCase().indexOf(String(product).toLowerCase()) === 0) {
    return e.slice(String(product).length).trim();
  }
  // 製品名が分からない場合は、先頭の英字トークンを落とす
  return e.replace(/^[A-Za-z][\w-]*\s*/, '').trim();
}

/**
 * バージョン表記 1 件に自社バージョンが含まれるかを判定する。
 * true / false / null（表記を解釈できず判定不能）を返す。
 *
 * 実データ 50 アドバイザリで確認できた表記は次の 7 種類:
 *   >=7.4.0|<=7.4.8      範囲            137件
 *   7.2 all versions     マイナー系列全体 127件
 *   7.6.0                単一バージョン    13件
 *   7.2.2 and above      下限のみ           3件
 *   all versions         製品全体           2件
 *   >=7.4|<=7.4.13       2桁の下限          1件
 *   25.1.c               非数値を含む       1件（→ null を返す）
 */
function matchesSpec_(ver, body) {
  const b = String(body || '').trim();
  if (!b) return null;

  if (/^all versions$/i.test(b)) return true;

  let m = /^(\d+(?:\.\d+)*)\s+all versions$/i.exec(b);
  if (m) {
    const base = parseVersion_(m[1]);
    if (!base) return null;
    for (let i = 0; i < base.length; i++) {
      if ((ver[i] === undefined ? 0 : ver[i]) !== base[i]) return false;
    }
    return true;
  }

  m = /^>=\s*([^\s|]+)\s*\|\s*<=\s*([^\s|]+)$/.exec(b);
  if (m) {
    const lo = parseVersion_(m[1]), hi = parseVersion_(m[2]);
    if (!lo || !hi) return null;
    return compareVersion_(ver, lo) >= 0 && compareVersion_(ver, hi) <= 0;
  }

  m = /^([^\s]+)\s+and above$/i.exec(b);
  if (m) {
    const lo2 = parseVersion_(m[1]);
    if (!lo2) return null;
    return compareVersion_(ver, lo2) >= 0;
  }

  m = /^([^\s]+)$/.exec(b);
  if (m) {
    const ex = parseVersion_(m[1]);
    if (!ex) return null;
    return compareVersion_(ver, ex) === 0;
  }

  return null;  // 未知の表記。推測せず判定不能にする
}

/**
 * 自社バージョン（複数可）と影響バージョン一覧を突き合わせる。
 * 戻り値: { hit: bool, unknown: bool, matched: '一致した表記' }
 */
function judgeVersions_(assetVersions, affectedEntries, product) {
  let unknown = false, matched = '';

  for (let i = 0; i < assetVersions.length; i++) {
    const ver = parseVersion_(assetVersions[i]);
    if (!ver) { unknown = true; continue; }

    for (let j = 0; j < affectedEntries.length; j++) {
      const body = stripProductPrefix_(affectedEntries[j], product);
      const r = matchesSpec_(ver, body);
      if (r === true) return { hit: true, unknown: false, matched: affectedEntries[j] };
      if (r === null) unknown = true;
    }
  }
  return { hit: false, unknown: unknown, matched: matched };
}

// ============================================================
// 4. 通知判定（コードで実行・LLM 不使用）
// ============================================================

/**
 * 影響バージョンの表記を、人が読める形にする。
 * CSAF の生の表記は「自分が対象なのか」が一目で分からない。
 *
 *   FortiOS >=7.4.0|<=7.4.8   → 7.4.0〜7.4.8
 *   FortiOS 7.4 all versions  → 7.4 系すべて
 *   FortiOS 7.2.2 and above   → 7.2.2 以上
 *   FortiOS 7.6.0             → 7.6.0
 */
function jpRange_(entry, product) {
  const b = stripProductPrefix_(entry, product);
  let m = /^>=\s*([^\s|]+)\s*\|\s*<=\s*([^\s|]+)$/.exec(b);
  if (m) return m[1] + '〜' + m[2];
  m = /^(\S+)\s+all versions$/i.exec(b);
  if (m) return m[1] + ' 系すべて';
  if (/^all versions$/i.test(b)) return '全バージョン';
  m = /^(\S+)\s+and above$/i.exec(b);
  if (m) return m[1] + ' 以上';
  return b;
}

/** 影響バージョンの一覧をまとめて読みやすくする。 */
function jpRanges_(entries, product) {
  return entries.map(function (e) { return jpRange_(e, product); }).join('、');
}

/**
 * 自社が使っている系列（例 7.4）に対応する影響範囲を 1 件だけ返す。
 *
 * 対象外の根拠に「7.6.0、7.4.0〜7.4.7、7.2 系すべて、7.0 系すべて、6.4 系すべて」と
 * 全部並べても、7.4.11 の利用者が読むのは 7.4 系の行だけである。
 * 戻り値: { branch: '7.4', range: '7.4.0〜7.4.7' } / 該当なしは null
 */
function branchRange_(row, versions) {
  for (let i = 0; i < versions.length; i++) {
    const v = parseVersion_(versions[i]);
    if (!v || v.length < 2) continue;
    const branch = v.slice(0, 2).join('.');

    for (let j = 0; j < row.affected.length; j++) {
      const body = stripProductPrefix_(row.affected[j], row.product);
      const head = /^(?:>=\s*)?(\d+(?:\.\d+)+)/.exec(body);
      if (!head) continue;
      if (head[1].split('.').slice(0, 2).join('.') === branch) {
        return { branch: branch, range: jpRange_(row.affected[j], row.product) };
      }
    }
  }
  return null;
}

/** 製品名を突合用に正規化する。"FortiClient EMS" と "FortiClientEMS" を同じ扱いにする。 */
function normProduct_(s) {
  return String(s || '').toLowerCase().replace(/[\s_-]/g, '');
}

function readAssets_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_ASSET);
  if (!sh || sh.getLastRow() < 2) return [];
  const values = sh.getRange(2, 1, sh.getLastRow() - 1, ASSET_HEADERS.length).getValues();
  return values.filter(function (r) { return r[0]; }).map(function (r) {
    return {
      product: String(r[0]).trim(),
      version: String(r[1]).trim(),
      count: r[2],
      internetFacing: String(r[3]).trim(),
      note: String(r[4]).trim()
    };
  });
}

function assetsForProduct_(assets, product) {
  const p = normProduct_(product);
  if (!p) return [];
  return assets.filter(function (a) { return normProduct_(a.product) === p; });
}

/**
 * 通知判定を決める。
 *   通知対象 : 自社が対象製品を保有し、自社利用バージョンが影響範囲に含まれる
 *   対象外   : 対象製品を保有していない、または利用バージョンが影響範囲外
 *   判定不能 : 製品は保有しているがバージョンが不明、または表記を解釈できない
 *
 * 「通知対象」は影響機能を実際に使っていることを意味しない。
 * それを確認するのは人であり、確認方法は 13 列目に AI が書く。
 */
function decideNotification_(row, assets) {
  if (row.verdict === V_UNKNOWN && row.reason) return;  // errorRow_ は上書きしない

  row.fixVersion = pickFixVersion_(row);

  if (!row.product) {
    row.verdict = V_UNKNOWN;
    row.reason = '対象製品を特定できないため';
    return;
  }

  const mine = assetsForProduct_(assets, row.product);
  if (!mine.length) {
    row.verdict = V_OUT;
    row.reason = row.product + ' を自社で使用していないため';
    return;
  }

  const versions = mine.map(function (a) { return a.version; }).filter(function (v) { return v; });
  row.selfVersion = mine.map(function (a) { return row.product + ' ' + (a.version || '（バージョン未記入）'); }).join('\n');

  if (!versions.length) {
    row.verdict = V_UNKNOWN;
    row.reason = '資産シートにバージョン未記入のため';
    return;
  }

  const res = judgeVersions_(versions, row.affected, row.product);

  // 根拠は「〜のため」で終わる 1 行に収める。
  // 具体的なバージョン番号は 5 列目・アドバイザリ列から辿れるので繰り返さない。
  if (res.hit) {
    row.verdict = V_TARGET;
    row.reason = '利用中のバージョンが対象のため';
    narrowFixVersion_(row, assets);   // 自社が使っている系列の修正指示に絞る
  } else if (res.unknown) {
    row.verdict = V_UNKNOWN;
    row.reason = 'バージョン表記を解釈できず自動判定できないため';
  } else {
    // 対象外の根拠は「対応不要と言い切る材料」なので、
    // 影響範囲を全部並べる代わりに、自社の系列に対応する範囲だけを示す。
    // 7.4.11 の利用者にとって 7.0 系や 6.4 系の範囲は読む理由がない。
    row.verdict = V_OUT;
    const b = branchRange_(row, versions);
    row.reason = b
      ? b.branch + ' 系の影響は ' + b.range + ' までのため'
      : '利用中の系列が影響対象外のため';
  }
}

/**
 * 修正バージョンを、自社が使っている系列の行だけ抜き出す。
 * remediations の details は
 *   "FortiOS 7.6: Upgrade to 7.6.4 or above\nFortiOS 7.4: Upgrade to 7.4.9 or above\n..."
 * のように系列ごとに1行で並ぶ。全部を1セルに入れると読み手が自分の行を探すことになる。
 */
function pickFixVersion_(row) {
  const raw = String(row.fixesRaw || '').trim();
  if (!raw) return '';
  const lines = raw.split('\n').map(function (s) { return s.trim(); }).filter(function (s) { return s; });
  return lines.join('\n');
}

/** 自社バージョンが決まったあとに、該当系列の修正指示だけへ絞り込む。 */
function narrowFixVersion_(row, assets) {
  const mine = assetsForProduct_(assets, row.product);
  if (!mine.length || !row.fixesRaw) return;

  const branches = mine.map(function (a) {
    const v = parseVersion_(a.version);
    return v ? v.slice(0, 2).join('.') : '';
  }).filter(function (b) { return b; });
  if (!branches.length) return;

  const hits = row.fixesRaw.split('\n').filter(function (line) {
    return branches.some(function (b) {
      return new RegExp('\\s' + b.replace('.', '\\.') + '\\s*:').test(line);
    });
  });
  if (hits.length) row.fixVersion = hits.join('\n');
}

/**
 * 「資産シートに無いから対象外」にした製品を毎回ログに出す。
 *
 * この判定は資産シートの記載だけを根拠にしているため、
 * 登録漏れがあると「持っていない」と誤って断定し、静かに見逃す。
 * しかもエラーは出ず、根拠欄を読むのは対象外の行を開いたときだけで、
 * 対象外は普通読まれない。見逃しゼロが必須（設計書 6.4）なので、
 * 前提を毎回目に見える形にする。
 *
 * 現在のスコープは FortiOS のみ（設計書 3.1）。
 * ここに並ぶ製品名は本来すべて自社非保有のはずで、
 * 見覚えのある製品が出てきたら資産シートを疑う。
 */
function logUnownedProducts_(rows) {
  const c = {};
  rows.forEach(function (r) {
    if (r.verdict === V_OUT && r.reason.indexOf('保有していない') !== -1) {
      c[r.product] = (c[r.product] || 0) + 1;
    }
  });
  const names = Object.keys(c).sort();
  if (!names.length) return;

  Logger.log('--- 資産シートに無いため「対象外」にした製品（' + names.length + '種）---');
  Logger.log(names.map(function (n) { return n + '(' + c[n] + '行)'; }).join(' / '));
  Logger.log('※ この中に自社で使っている製品があれば、資産シートに追加して再実行してください。');
  Logger.log('※ 登録漏れはそのまま「対象外」になり、通知対象の見逃しになります。');
}

/**
 * CSAF の修正指示を日本語の短い一文にする。コードで変換するので AI を使わない。
 *
 * 実データで確認できた文型は3つだけ（延べ 443 行）:
 *   "FortiOS 7.4: Upgrade to 7.4.9 or above"   → 7.4.9 以上へ更新
 *   "FortiOS 7.2: Migrate to a fixed release"  → 7.2 に修正版なし。上位系列へ移行が必要
 *   "FortiOS 8.0: Not Applicable"              → 影響しないので表示しない
 *
 * v6 初版は同じ内容を AI に「対応方針」として日本語化させていたが、
 * 修正バージョン列の訳文にしかなっていなかった。決定的な変換に AI を使う理由がない。
 */
function jpFix_(row) {
  const narrowed = String(row.fixVersion || '').trim();
  if (!narrowed) return '';

  return narrowed.split('\n').map(function (line) {
    const t = line.trim();
    if (!t) return '';

    const m = /^(.+?)\s*:\s*(.+)$/.exec(t);
    if (!m) return t;
    const branch = m[1].trim(), action = m[2].trim();

    if (/Not Applicable/i.test(action)) return '';          // 影響しない系列は出さない
    if (/do not need to perform any action/i.test(action)) return '対応不要';

    const u = /Upgrade to\s+(?:upcoming\s+)?([\d.]+)\s+or above/i.exec(action);
    if (u) {
      return u[1] + ' 以上に更新が必要' + (/upcoming/i.test(action) ? '（未リリース）' : '');
    }

    // 「Migrate to a fixed release」は「この系列に修正版はない」という意味でしかなく、
    // どこへ上げればよいかが書かれていない。同じアドバイザリの他系列に
    // ベンダー自身が示した更新先があるので、そこから移行先を引く（推測はしない）。
    if (/Migrate to a fixed release/i.test(action)) {
      const b = branch.replace(/^\S+\s*/, '');
      const target = migrateTarget_(row, branch);
      // 「何をすればよいか」を先に言い、理由を括弧に回す
      return target
        ? target + ' 以上に更新が必要（' + b + ' 系に修正版なし）'
        : '上位系列への移行が必要（' + b + ' 系に修正版なし）';
    }
    return action;
  }).filter(function (s) { return s; }).join('\n');
}

/**
 * 「修正版なし」の系列に対する移行先を、同じアドバイザリの他系列の
 * 「Upgrade to X or above」から引く。自社の系列より上で最も低いものを返す。
 * 見つからなければ空文字（推測して埋めない）。
 */
function migrateTarget_(row, branchLabel) {
  const cur = parseVersion_(String(branchLabel).replace(/^\S+\s*/, ''));
  if (!cur) return '';

  let best = null;
  String(row.fixesRaw || '').split('\n').forEach(function (line) {
    const m = /^(.+?)\s*:\s*(.+)$/.exec(line.trim());
    if (!m) return;
    const b = parseVersion_(m[1].replace(/^\S+\s*/, ''));
    const u = /Upgrade to\s+(?:upcoming\s+)?([\d.]+)\s+or above/i.exec(m[2]);
    if (!b || !u) return;
    if (compareVersion_(b, cur) <= 0) return;               // 自社系列より上だけ
    const v = parseVersion_(u[1]);
    if (!v) return;
    if (!best || compareVersion_(v, best.v) < 0) best = { v: v, s: u[1] };
  });
  return best ? best.s : '';
}

function countVerdicts_(rows) {
  const c = {};
  c[V_TARGET] = 0; c[V_OUT] = 0; c[V_UNKNOWN] = 0;
  rows.forEach(function (r) { if (c[r.verdict] !== undefined) c[r.verdict]++; });
  return c;
}

// ============================================================
// 5. AI による日本語化（通知対象と判定不能の行のみ）
// ============================================================

function enrichWithAI_(rows) {
  let ok = 0;

  for (let i = 0; i < rows.length; i += AI_CHUNK_SIZE) {
    const chunk = rows.slice(i, i + AI_CHUNK_SIZE);
    const label = (Math.floor(i / AI_CHUNK_SIZE) + 1) + '回目(' + chunk.length + '件)';

    try {
      const prompt = buildEnrichPrompt_(chunk);
      const text = (AI_PROVIDER === 'claude') ? callClaude_(prompt) : callGemini_(prompt);

      const s = text.indexOf('[');
      const e = text.lastIndexOf(']');
      if (s === -1 || e === -1) throw new Error('JSON配列が見つかりません: ' + text.slice(0, 200));

      const parsed = JSON.parse(text.slice(s, e + 1));
      const byKey = {};
      parsed.forEach(function (v) { byKey[v.key] = v; });

      chunk.forEach(function (r) {
        const v = byKey[rowKey_(r)];
        if (!v) return;
        r.feature = v['影響機能名'] || '';
        r.impactJa = v['ユーザ影響'] || '';
        r.howToCheck = v['確認方法'] || '';
        ok++;
      });
      Logger.log('AI 生成 ' + label + ' 成功');
    } catch (err) {
      Logger.log('AI 生成 ' + label + ' 失敗: ' + err);
    }
    Utilities.sleep(1000);
  }

  Logger.log('AI 生成: ' + AI_PROVIDER + ' / 成功 ' + ok + ' / 対象 ' + rows.length + ' 行');
}

function rowKey_(r) {
  return r.advisoryId + '|' + r.cve + '|' + r.product;
}

function buildEnrichPrompt_(rows) {
  const payload = rows.map(function (r) {
    return {
      key: rowKey_(r),
      自社影響: r.verdict,
      対象製品: r.product,
      CVE: r.cve,
      脆弱性名: r.title,
      アドバイザリの記述: r.summary,
      影響の種類: r.impact,
      CVSS: r.cvss,
      深刻度: r.severity,
      自社利用バージョン: r.selfVersion,
      脆弱性の影響バージョン: r.affected.join(' / '),
      ベンダー提示の緩和策: r.workaround || 'なし'
    };
  });

  return [
    'あなたは社内の情報システム担当者です。Fortinet が公開した脆弱性情報を、',
    '担当者が読んで次の行動を判断できる日本語に整理してください。読み手は非エンジニアを含みます。',
    '',
    '【前提】',
    '- 「自社影響」は既にコードで確定済みです。あなたが判定をやり直す必要はありません。',
    '- あなたには自社の機器設定も利用実態も渡されていません。',
    '  したがって影響機能を「使用中」「未使用」と判定してはいけません。',
    '- アドバイザリに書かれていないことを推測して書かないでください。',
    '',
    '【入力】',
    JSON.stringify(payload, null, 1),
    '',
    '【出力する項目のルール】',
    '',
    '■ 影響機能名',
    '  どの機能が影響を受けるかを書きます。製品名は機能名ではありません。',
    '  誤り: 「FortiSIEM」「FortiClient EMS」（これらは製品名）',
    '  正しい: 「captive portal」「web filter」「SSL-VPN」',
    '  「アドバイザリの記述」から機能を表す語句を取り出してください。',
    '  例:「Buffer over-read in captive portal」→「captive portal」',
    '    「Information Disclosure in SSL_VPN web-mode」→「SSL-VPN（web モード）」',
    '  次の統制語彙に該当するものがあれば、その表記に揃えてください（表記ゆれを防ぐため）:',
    '    ' + FEATURE_VOCAB.join(' / '),
    '  語彙にない場合は原文の語句をそのまま使ってください。',
    '  機能を特定できない場合は、推測せず「不明・要確認」と書いてください。',
    '',
    '■ ユーザ影響',
    '  攻撃されたときに何が起きるかを、**20〜30 字程度の一言**で書きます。',
    '  **文章にしないでください。体言止めか、短い一文で言い切ります。**',
    '',
    '  良い例:',
    '   ・認証画面から内部情報が漏れる',
    '   ・管理者権限を奪われる',
    '   ・接続元IP制限を回避され管理操作される',
    '   ・ログに認証情報が平文で残る',
    '   ・利用者のブラウザで不正なスクリプトが動く',
    '',
    '  悪い例（長すぎ・決まり文句）:',
    '   ・「ネットワーク接続時に認証を求める画面（captive portal）の処理において、',
    '     メモリ上のデータが不当に読み取られる脆弱性です。…具体的な業務影響は要確認です。」',
    '',
    '  守ること:',
    '  ・専門用語は非エンジニアに通じる言葉に置き換える（captive portal →「認証画面」）',
    '  ・英語原文の直訳や、脆弱性名をなぞっただけにしない',
    '  ・「具体的な業務影響は要確認」などの決まり文句を付けない',
    '  ・アドバイザリに書かれていない被害を足さない',
    '',
    '■ 確認方法（自社影響が「あり」の行のみ。それ以外は空文字）',
    '  影響機能を自社で使っているかを、担当者が自分で確認できるようにします。',
    '  **この列の価値は具体性です。手順を書かずに終わらせないでください。**',
    '',
    '  **前置きの文は一切書かないでください。いきなり ・【確認箇所】 から始めます。**',
    '  （「下記の方法で確認してください」のような案内文は、列名がすでに言っているので不要です）',
    '',
    '  ・【確認箇所】どの設定を見るか',
    '  ・【コマンド】読み取り専用コマンド',
    '  ・【見るところ】出力のどの項目を見るか。どの値なら使用している可能性があるか',
    '',
    '  例（影響機能名が SSL-VPN の場合）。この 3 行だけを返します:',
    '',
    '  ・【確認箇所】SSL-VPN の設定',
    '  ・【コマンド】show vpn ssl settings',
    '  ・【見るところ】status が enable なら使用しています',
    '',
    '  FortiOS の**参照系コマンドは製品一般の公開知識なので、書いてください。**',
    '  `show` `get` `diagnose` で始まる読み取り専用のものに限ります。',
    '  設定を変更するコマンド（`set`、`execute` の実行系）は書かないでください。',
    '',
    '  守ること:',
    '  ・1 項目 1 行。各行は短く。説明的な文章を足さない',
    '  ・**自社固有の**画面名・プロファイル名・ポリシー名は推測して書かない（製品標準の設定名は可）',
    '  ・コマンドに自信がない場合は【コマンド】の行だけ省き、他の 2 行は書く',
    '  ・「特定できません」と書いてよいのは、**影響機能名が「不明・要確認」になった行だけ**です',
    '  ・「使用中」「未使用」という結論は絶対に書かない（あなたは自社の設定を見ていません）',
    '',
    '  自社影響が「要確認」の行では、確認方法の代わりに',
    '  「何を確認すれば判定できるようになるか」を書いてください。',
    '',
    '※ 修正版や移行の要否はコード側で機械的に出力するため、あなたは書かないでください。',
    '',
    '出力は次のスキーマの JSON 配列のみ。前置き・コードフェンス・説明を一切含めないこと。',
    '[{"key":"FG-IR-26-154|CVE-2025-43892|FortiOS","影響機能名":"captive portal",',
    '  "ユーザ影響":"...","確認方法":"..."}]'
  ].join('\n');
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
// 6. 台帳への記録
// ============================================================

const COL = {};
LEDGER_HEADERS.forEach(function (h, i) { COL[h] = i + 1; });

/**
 * 既読のアドバイザリ ID を集める。
 *
 * 台帳ではなく処理済みシートから読む。台帳には自社製品の行しか無いため、
 * 台帳を既読の根拠にすると、他社製品だけのアドバイザリを毎回取り直してしまう。
 */
function getKnownAdvisories_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_STATE);
  if (!sh || sh.getLastRow() < 2) return {};

  const values = sh.getRange(2, 1, sh.getLastRow() - 1, STATE_HEADERS.length).getValues();
  const cUpd = STATE_HEADERS.indexOf('最終更新日');
  const cIr = STATE_HEADERS.indexOf('FG-IR');

  const map = {};
  values.forEach(function (r) {
    const ir = String(r[cIr]).trim();
    if (ir) map[ir] = ymd_(r[cUpd]);
  });
  return map;
}

/**
 * 指定したアドバイザリの行を、台帳と処理済みシートから消す。
 * 改訂されたアドバイザリを入れ直す前に呼ぶ。
 */
function removeRowsFor_(advisoryIds) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const targets = {};
  advisoryIds.forEach(function (id) { targets[id] = true; });

  const specs = [
    { sh: ss.getSheetByName(SHEET_LEDGER), col: COL['Fortinetアドバイザリ'], width: LEDGER_HEADERS.length },
    { sh: ss.getSheetByName(SHEET_STATE), col: STATE_HEADERS.indexOf('FG-IR') + 1, width: STATE_HEADERS.length }
  ];

  specs.forEach(function (spec) {
    const sh = spec.sh;
    if (!sh || sh.getLastRow() < 2) return;
    const n = sh.getLastRow() - 1;
    const ids = sh.getRange(2, spec.col, n, 1).getDisplayValues();

    let removed = 0;
    // 下から消さないと行番号がずれる
    for (let i = ids.length - 1; i >= 0; i--) {
      if (targets[String(ids[i][0]).trim()]) { sh.deleteRow(i + 2); removed++; }
    }
    if (removed) Logger.log(sh.getName() + ' から古い ' + removed + ' 行を削除しました（改訂のため入れ直します）。');
  });
}

/**
 * 処理したアドバイザリを 1 件 1 行で記録する。
 * 「今月 Fortinet から公表：N 件」の分母はこのシートを数えて出す。
 */
function writeState_(todo, rows) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(SHEET_STATE);
  if (!sh) {
    sh = ss.insertSheet(SHEET_STATE);
    sh.appendRow(STATE_HEADERS);
    sh.setFrozenRows(1);
  }

  const assets = readAssets_();
  const byAdvisory = {};
  rows.forEach(function (r) {
    const a = byAdvisory[r.advisoryId] ||
      (byAdvisory[r.advisoryId] = { products: [], ledger: 0, initial: r.initialDate });
    pushUnique_(a.products, r.product);
    if (isLedgerRow_(r, assets)) a.ledger++;
  });

  const values = todo.map(function (f) {
    const a = byAdvisory[f.item.ir] || { products: [], ledger: 0, initial: f.updatedAt };
    return [
      f.updatedAt || '',            // 最終更新日（既読判定のキー）
      a.initial || f.updatedAt || '', // 初回公表日
      f.item.ir,
      f.item.title,
      a.ledger,
      a.products.join(', ')
    ];
  });

  const startRow = sh.getLastRow() + 1;
  sh.getRange(startRow, 1, values.length, STATE_HEADERS.length).setValues(values);
  sh.getRange(startRow, 1, values.length, 2).setNumberFormat('yyyy/mm/dd');
  Logger.log('処理済みシートに ' + values.length + ' 件のアドバイザリを記録しました。');
}

/** 月ごとの公表件数と、台帳に載った行数を数える。月次サマリの分母。 */
function countByMonth() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_STATE);
  if (!sh || sh.getLastRow() < 2) { Logger.log('処理済みシートが空です。'); return; }

  const values = sh.getRange(2, 1, sh.getLastRow() - 1, STATE_HEADERS.length).getValues();
  const cLedger = STATE_HEADERS.indexOf('台帳の行数');
  const m = {};
  values.forEach(function (r) {
    const d = r[0];   // 最終更新日。改訂された月に計上する
    const key = (d instanceof Date)
      ? d.getFullYear() + '/' + ('0' + (d.getMonth() + 1)).slice(-2)
      : '(公開日不明)';
    const s = m[key] || (m[key] = { adv: 0, ledger: 0 });
    s.adv++;
    s.ledger += Number(r[cLedger]) || 0;
  });

  Logger.log('--- 月別（最終更新日で集計）---');
  Object.keys(m).sort().reverse().forEach(function (k) {
    Logger.log(k + '  Fortinetからの公表 ' + m[k].adv + ' 件 / 台帳に記録 ' + m[k].ledger + ' 行');
  });
}

function toRowArray_(r) {
  const advisoryCell = r.advisoryUrl
    ? '=HYPERLINK("' + r.advisoryUrl + '","' + r.advisoryId + '")'
    : r.advisoryId;

  // 対応は「自社が動く必要がある行」だけに出す。
  // 保有していない製品や影響範囲外の行に修正指示を並べても、読む理由がない。
  // 対象外の行がそれぞれ 5〜10 行の修正指示を抱えるのが、情報量の最大の発生源だった。
  const action = (r.verdict === V_OUT) ? '' : jpFix_(r);

  // CVSS は数値に帯を併記する。数値だけだと非エンジニアに伝わらず、
  // 帯だけだと粒度が粗い。
  const cvss = (r.cvss === '' || r.cvss === undefined)
    ? ''
    : String(r.cvss) + (r.severity ? '（' + r.severity + '）' : '');

  // 並びは LEDGER_HEADERS と 1 対 1 で対応させること
  return [
    r.pubDate || '',                  // 1  最終更新日
    r.cve || '',                      // 2  CVE
    r.verdict || '',                  // 3  自社影響
    cvss,                             // 4  CVSS
    r.product || '不明',              // 5  対象サービス／製品
    r.title || '',                    // 6  脆弱性名
    r.impactJa || '',                 // 7  ユーザ影響
    r.feature || '',                  // 8  影響機能名
    r.reason || '',                   // 9  判定根拠
    r.howToCheck || '',               // 10 利用有無の確認方法
    action,                           // 11 対応
    advisoryCell                      // 12 Fortinetアドバイザリ
  ];
}

function writeLedger_(rows) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh) throw new Error('「台帳」シートがありません。setup() を先に実行してください。');
  if (!rows.length) return;

  const values = rows.map(toRowArray_);
  const startRow = sh.getLastRow() + 1;
  sh.getRange(startRow, 1, values.length, LEDGER_HEADERS.length).setValues(values);
  sh.getRange(startRow, COL['最終更新日'], values.length, 1).setNumberFormat('yyyy/mm/dd');
  Logger.log('台帳に ' + values.length + ' 行を追記しました。');
}

/** 通知対象 → 判定不能 → 対象外 の順、同じ判定なら公開日の新しい順に並べ替える。 */
function sortLedger_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 3) return;

  const n = sh.getLastRow() - 1;
  const range = sh.getRange(2, 1, n, LEDGER_HEADERS.length);
  const rank = {};
  rank[V_TARGET] = 0; rank[V_UNKNOWN] = 1; rank[V_OUT] = 2;

  const formulas = range.getFormulas();
  const values = range.getValues();
  // 数式セル（アドバイザリ列）は数式のまま持ち回る
  for (let i = 0; i < values.length; i++) {
    const f = formulas[i][COL['Fortinetアドバイザリ'] - 1];
    if (f) values[i][COL['Fortinetアドバイザリ'] - 1] = f;
  }

  values.sort(function (a, b) {
    const ra = rank[a[COL['自社影響'] - 1]], rb = rank[b[COL['自社影響'] - 1]];
    const va = (ra === undefined) ? 3 : ra, vb = (rb === undefined) ? 3 : rb;
    if (va !== vb) return va - vb;
    const da = a[COL['最終更新日'] - 1], db = b[COL['最終更新日'] - 1];
    if (da instanceof Date && db instanceof Date) return db - da;
    return 0;
  });

  range.setValues(values);
}

function formatLedger_(sh) {
  sh.getRange(1, 1, 1, LEDGER_HEADERS.length)
    .setFontWeight('bold')
    .setBackground('#f0f0f0');

  //          更新日 CVE  影響 CVSS 製品 脆弱性名 ユーザ影響 機能 根拠 確認 対応 出典
  const widths = [90, 140, 70, 95, 120, 250, 230, 140, 240, 360, 230, 130];
  widths.forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });

  // 右の説明列（判定根拠・確認方法・対応）を読むあいだ、
  // 「いつの・どのCVEの・何が起きる件か」を見失わないよう左 5 列を固定する。
  sh.setFrozenColumns(5);

  const all = sh.getRange(1, 1, sh.getMaxRows(), LEDGER_HEADERS.length);
  all.setVerticalAlignment('top');
  all.setWrap(true);
}

/**
 * AI 列が空のまま残っている行を埋め直す。
 * v5 は判定できなかった行を削除して再取得していたが、取得済みの事実まで捨ててしまう。
 * v6 は通知判定をコードで確定させているので、行は残したまま AI 列だけ補える。
 */
function backfillAiColumns_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 2) return;

  const n = sh.getLastRow() - 1;
  const values = sh.getRange(2, 1, n, LEDGER_HEADERS.length).getValues();
  const display = sh.getRange(2, 1, n, LEDGER_HEADERS.length).getDisplayValues();

  // AI が要る行（通知対象・判定不能で AI影響要約 が空）の位置を、行キーで引けるようにする
  const wanted = {};
  let count = 0;
  for (let i = 0; i < values.length; i++) {
    const verdict = values[i][COL['自社影響'] - 1];
    if (verdict !== V_TARGET && verdict !== V_UNKNOWN) continue;
    if (String(values[i][COL['ユーザ影響'] - 1]).trim()) continue;

    const key = display[i][COL['Fortinetアドバイザリ'] - 1] + '|' +
                values[i][COL['CVE'] - 1] + '|' +
                values[i][COL['対象サービス／製品'] - 1];
    wanted[key] = {
      rowIndex: i + 2,
      advisoryId: display[i][COL['Fortinetアドバイザリ'] - 1],
      title: values[i][COL['脆弱性名'] - 1]
    };
    count++;
  }

  if (!count) { Logger.log('AI 補完が必要な行はありません。'); return; }
  Logger.log('AI 補完対象: ' + count + ' 行');

  // 台帳には AI の入力（アドバイザリ本文・影響の種類など）を持たせていないため、
  // 該当アドバイザリの CSAF を取り直して同じ材料を組み立てる。
  // 対象は毎回数行なので、取得コストは問題にならない。
  const assets = readAssets_();
  const byAdvisory = {};
  Object.keys(wanted).forEach(function (k) {
    const w = wanted[k];
    byAdvisory[w.advisoryId] = w.title;
  });

  const targets = [];
  Object.keys(byAdvisory).forEach(function (ir) {
    const item = {
      ir: ir,
      title: byAdvisory[ir],
      link: 'https://fortiguard.fortinet.com/psirt/' + ir,
      pubDate: ''
    };
    try {
      const rows = extractRows_(fetchCsaf_(item), item);
      rows.forEach(function (r) {
        decideNotification_(r, assets);
        const w = wanted[rowKey_(r)];
        if (w) { r.rowIndex = w.rowIndex; targets.push(r); }
      });
    } catch (e) {
      Logger.log('AI 補完のための再取得に失敗: ' + ir + ' / ' + e);
    }
    Utilities.sleep(300);
  });

  if (!targets.length) { Logger.log('再取得できた対象がありませんでした。'); return; }

  try {
    enrichWithAI_(targets);
  } catch (e) {
    Logger.log('AI 補完に失敗しました: ' + e);
    return;
  }

  let written = 0;
  targets.forEach(function (t) {
    if (!t.impactJa) return;
    sh.getRange(t.rowIndex, COL['影響機能名']).setValue(t.feature);
    sh.getRange(t.rowIndex, COL['ユーザ影響']).setValue(t.impactJa);
    sh.getRange(t.rowIndex, COL['利用有無の確認方法']).setValue(t.howToCheck);
    written++;
  });
  Logger.log('AI 補完: ' + written + ' / ' + targets.length + ' 行を書き戻しました。');
  Logger.log('AI 補完を書き戻しました。');
}

// ============================================================
// 7. Slack 通知
// ============================================================

/**
 * Slack 通知。
 *
 * 通知の仕事は「何件あるか・どれが一番まずいか・どこを見るか」の 3 つだけ。
 * 確認コマンドや判定根拠は台帳の仕事なので載せない。
 * 初版は 1 件あたり 7 行を平文で流しており、要素がすべて同じ太さで並ぶため目が滑った。
 *
 * Block Kit を使い、1 件を「太字の被害 → 小さい灰色のメタ情報 → 対応」の 3 層にする。
 * 太字だけ追えば全体が掴めて、詳しく見たい行だけメタ情報を読む形にした。
 */
function notifySlack_(rows) {
  const url = PropertiesService.getScriptProperties().getProperty('SLACK_WEBHOOK_URL');
  if (!url) { Logger.log('SLACK_WEBHOOK_URL 未設定のため通知をスキップします。'); return; }

  const c = countVerdicts_(rows);
  const hits = rows
    .filter(function (r) { return r.verdict === V_TARGET || r.verdict === V_UNKNOWN; })
    .sort(function (a, b) {
      // 影響ありを先に、その中は CVSS の高い順。「どれが一番まずいか」を 1 行目で見せる
      if (a.verdict !== b.verdict) return a.verdict === V_TARGET ? -1 : 1;
      return (Number(b.cvss) || 0) - (Number(a.cvss) || 0);
    });

  if (!hits.length && !NOTIFY_WHEN_NO_HITS) {
    Logger.log('影響ありの新着なし。Slack 通知はスキップします。');
    return;
  }

  const sheetUrl = SpreadsheetApp.getActiveSpreadsheet().getUrl();
  const worst = hits.length ? Math.max.apply(null, hits.map(function (r) { return Number(r.cvss) || 0; })) : 0;
  const icon = !hits.length ? ':white_check_mark:' : (worst >= 7 ? ':rotating_light:' : ':warning:');

  const headline = hits.length
    ? '影響あり ' + c[V_TARGET] + '件 ／ 要確認 ' + c[V_UNKNOWN] + '件'
    : '影響ありなし（新着 ' + rows.length + ' 件）';

  const blocks = [{
    type: 'header',
    text: { type: 'plain_text', text: icon + ' Fortinet ' + headline, emoji: true }
  }];

  // 1 件 = 3 ブロック。「何が起きるか → 何の件か → どうするか」の順に読ませる
  hits.slice(0, SLACK_MAX_ITEMS).forEach(function (r, i) {
    if (i > 0) blocks.push({ type: 'divider' });

    // (1) 太字 ＝ 何が起きるか。ここだけ追えば全体が掴める
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: '*' + (r.impactJa || r.title || r.cve) + '*' }
    });

    // (2) 小さい灰色 ＝ 何の件か。識別に必要な最小限
    const meta = [
      (r.verdict === V_TARGET ? '影響あり' : '要確認'),
      r.cve ? '<' + r.advisoryUrl + '|' + r.cve + '>' : r.advisoryId,
      r.cvss !== '' && r.cvss !== undefined ? 'CVSS ' + r.cvss : null,
      r.feature || null
    ].filter(function (x) { return x; }).join('  ·  ');
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: meta }] });

    // (3) どうするか。結論なので通常の太さで置く
    const action = jpFix_(r);
    if (action) {
      blocks.push({
        type: 'section',
        text: { type: 'mrkdwn', text: ':hammer_and_wrench:  ' + action }
      });
    }
  });

  const rest = hits.length - SLACK_MAX_ITEMS;
  const footer = [];
  if (rest > 0) footer.push('ほか ' + rest + ' 件');
  if (c[V_OUT]) footer.push('影響なし ' + c[V_OUT] + '件は台帳のみ');
  footer.push('<' + sheetUrl + '|台帳を開く>（確認コマンド・判定根拠はこちら）');

  blocks.push({ type: 'divider' });
  blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: footer.join('  ·  ') }] });

  UrlFetchApp.fetch(url, {
    method: 'post',
    contentType: 'application/json',
    muteHttpExceptions: true,
    payload: JSON.stringify({
      text: 'Fortinet ' + headline,   // 通知プレビューとモバイル用のフォールバック
      blocks: blocks
    })
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
  Logger.log('先頭: ' + JSON.stringify(items[0], null, 2));
  Logger.log('組み立てた CSAF URL: ' + csafUrlFor_(items[0]));
}

/** RSS 全件について、タイトルから組み立てた CSAF URL が実在するか確かめる。 */
function testCsafUrls() {
  const items = fetchRssItems_();
  let ok = 0;
  const fails = [];
  items.forEach(function (it) {
    const res = UrlFetchApp.fetch(csafUrlFor_(it), { muteHttpExceptions: true, method: 'get' });
    if (res.getResponseCode() === 200) ok++;
    else fails.push(it.ir + ' (' + res.getResponseCode() + ') ' + it.title);
    Utilities.sleep(150);
  });
  Logger.log('CSAF URL 導出: 成功 ' + ok + ' / ' + items.length);
  fails.forEach(function (f) { Logger.log('  失敗: ' + f); });
}

function testCsaf() {
  const item = { ir: 'FG-IR-26-154', title: 'Buffer overread in authd and wad daemon',
                 link: 'https://fortiguard.fortinet.com/psirt/FG-IR-26-154', pubDate: '' };
  const rows = extractRows_(fetchCsaf_(item), item);
  Logger.log('展開行数: ' + rows.length + '（期待値 3: CVE 2件 × 製品 FortiOS/FortiProxy）');
  rows.forEach(function (r) {
    Logger.log([r.cve, r.product, r.cvss, r.severity, r.unauthRemote, '| ' + r.affected.join(' / ')].join(' '));
  });
}

/** バージョン比較の単体テスト。実データで確認した 7 種類の表記を網羅している。 */
function testVersion() {
  const cases = [
    ['7.4.5', '>=7.4.0|<=7.4.8', true],
    ['7.4.9', '>=7.4.0|<=7.4.8', false],
    ['7.4.0', '>=7.4.0|<=7.4.8', true],
    ['7.4.8', '>=7.4.0|<=7.4.8', true],
    ['7.2.1', '7.2 all versions', true],
    ['7.4.1', '7.2 all versions', false],
    ['7.6.0', '7.6.0', true],
    ['7.6.1', '7.6.0', false],
    ['7.2.5', '7.2.2 and above', true],
    ['7.2.1', '7.2.2 and above', false],
    ['5.0.4', 'all versions', true],
    ['7.4.5', '>=7.4|<=7.4.13', true],
    ['7.4.5', '25.1.c', null],
    ['7.4.5', '謎の表記', null]
  ];

  let pass = 0;
  cases.forEach(function (c) {
    const v = parseVersion_(c[0]);
    const got = v ? matchesSpec_(v, c[1]) : null;
    const ok = (got === c[2]);
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + c[0] + ' vs "' + c[1] + '" → ' + got + '（期待 ' + c[2] + '）');
  });
  Logger.log('バージョン比較: ' + pass + ' / ' + cases.length + ' 件が期待どおり');
}

/** 資産シートを使って通知判定だけを流す。AI も書き込みもしない。 */
function testJudge() {
  const assets = readAssets_();
  Logger.log('資産: ' + JSON.stringify(assets));

  const items = fetchRssItems_().slice(0, 5);
  let rows = [];
  items.forEach(function (it) {
    try { rows = rows.concat(extractRows_(fetchCsaf_(it), it)); }
    catch (e) { Logger.log('取得失敗 ' + it.ir + ': ' + e); }
    Utilities.sleep(300);
  });

  rows.forEach(function (r) { decideNotification_(r, assets); });
  const c = countVerdicts_(rows);
  Logger.log('--- ' + rows.length + ' 行 / 通知対象 ' + c[V_TARGET] + ' 判定不能 ' + c[V_UNKNOWN] + ' 対象外 ' + c[V_OUT] + ' ---');
  rows.forEach(function (r) {
    Logger.log([r.verdict, r.product, r.cve].join(' | ') + '\n    ' + r.reason);
  });
}

/** 資産シートに書くべき製品名を、実際の公開情報から一覧する。 */
function listProductNames_() {
  const items = fetchRssItems_();
  const names = {};
  items.slice(0, 20).forEach(function (it) {
    try {
      extractRows_(fetchCsaf_(it), it).forEach(function (r) {
        if (r.product) names[r.product] = (names[r.product] || 0) + 1;
      });
    } catch (e) { /* 取得できないものは飛ばす */ }
    Utilities.sleep(200);
  });
  Object.keys(names).sort().forEach(function (k) { Logger.log(k + '  (' + names[k] + ')'); });
}

/** AI 生成だけを 1 行分試す。 */
function testAi() {
  const dummy = [{
    advisoryId: 'FG-IR-26-154', cve: 'CVE-2025-43892', product: 'FortiOS',
    title: 'Buffer overread in authd and wad daemon',
    summary: 'Buffer over-read in captive portal',
    impact: 'Information disclosure',
    cvss: 4.1, severity: 'MEDIUM', unauthRemote: 'いいえ',
    verdict: V_TARGET,
    selfVersion: 'FortiOS 7.4.5',
    affected: ['FortiOS >=7.4.0|<=7.4.8', 'FortiOS 7.2 all versions'],
    fixesRaw: 'FortiOS 7.6: Upgrade to 7.6.4 or above\nFortiOS 7.4: Upgrade to 7.4.9 or above',
    workaround: '',
    feature: '', impactJa: '', howToCheck: '', plan: ''
  }];
  enrichWithAI_(dummy);
  Logger.log(JSON.stringify(dummy[0], null, 2));
}
