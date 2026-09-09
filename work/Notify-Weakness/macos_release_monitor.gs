/**
 * macOS 正式版リリース監視モジュール
 *
 * 毎朝 Apple 公式から macOS 正式版の公開を検知し、「早めに当てるか・定期更新まで待てるか」を
 * 固定ルールで一次判定して Slack へ 1 通出す。**判定はコード。AI は日本語の要約だけ。**
 *
 * 設計の根拠・実測データ・是正 16 件は `引き継ぎ_macOS対応_設計確定.md`（git）にある。
 * 運用手順は GAS の readme.gs 側に書く。ここには書かない。
 *
 * 既存 NW 機器ウォッチャー（fortinet_psirt_watcher_v7.gs）とは
 * トリガー・シート・台帳を分けてある。共有しているのは次の 4 つだけ。
 *   postSlack_          Slack 送信（応答コードを返す。投げないので下でラップする）
 *   kevCatalogWithStatus_  CISA KEV の取得（取得可否と出典まで返す）
 *   callGemini_         Gemini 呼び出し（responseSchema を渡す）
 *   sharedAiCountToday_ 当日の AI 消費数（NW と合算。無料枠を食い合わないため）
 *
 * このファイルを貼らなくても NW 側は動く（writeRunLog_ は typeof で守ってある）。
 */

// ============================================================
// 設定
// ============================================================

/* 確認用ファイルから参照できるよう、トップレベルは const ではなく var で宣言する。
 * Apps Script は別ファイルのトップレベル const を参照できないことがある（README §5）。 */

/*
 * Apple Software Lookup Service（gdmf.apple.com）は使えない。**再挑戦しないこと。**
 *
 * 2026-09-08 実測: gdmf の証明書は Apple 独自の Apple Root CA に繋がっていて公的 CA に繋がっていない
 * （support.apple.com は Apple Public EV Server RSA CA 1 - G1 で公的）。
 * macOS のキーチェーンは Apple Root CA を信頼しているのでローカルの curl は通るが、
 * Google の信頼ストアには無いため Apps Script からは必ず SSL Error になる。
 * UrlFetchApp の validateHttpsCertificates:false も試したが、未信頼ルートは救われなかった（実測）。
 *
 * 失うのは 15.x / 14.x のような旧メジャー系統のビルド番号表示だけで、
 * 検知・配布判断・CVE・KEV は Developer RSS と Security Index の 2 情報源で動く。
 */
var MACOS_SECURITY_INDEX_URL = 'https://support.apple.com/en-us/100100';

var MACOS_SHEET_LEDGER = 'macOS台帳';
var MACOS_SHEET_MANAGED = 'macOS管理OS';
var MACOS_SHEET_RUNLOG = 'macOS実行履歴';

var MACOS_TZ = 'Asia/Tokyo';

/**
 * NW は 9 時台。macOS はその後に回す。
 *
 * Gemini の無料枠は 1 日 20 回程度で、先に走ったほうが枠を取る。
 * プレ運用で観測しているのは NW 台帳の AI 3 列なので、**NW に先を譲る。**
 */
var MACOS_DAILY_HOUR = 10;

var MACOS_INITIALIZED_PROP = 'MACOS_INITIALIZED';
var MACOS_LAST_RUN_PROP = 'MACOS_LAST_RUN_AT';
var MACOS_TRIGGER_FN = 'macosDaily';

var MACOS_AI_MAX_FACTS = 20;
var MACOS_AI_PROMPT_VERSION = '1.0';

/**
 * macOS が 1 日に使ってよい AI 回数の上限（NW との合算値で見る）。
 * 合算が これ以上なら AI を呼ばず「AI要約なし」で送る。配布判断は AI に依存しないので止まらない。
 */
var MACOS_AI_DAILY_BUDGET = 12;

/**
 * 台帳に載せる公開日の範囲（日）。これより古いリリースは記録しない。
 *
 * Apple Security Releases は 2024 年まで遡って 81 件返す（2026-09-08 実測）。
 * 全部載せると台帳が読めなくなるうえ、2 年前のリリースに対して今できることは無い。
 *
 * 90 日にした理由は、**管理中のどのメジャー系統についても最新リリースが必ず 1 件は入る**幅だから
 * （Apple は現行サポート中のメジャーに少なくとも四半期に 1 回はセキュリティ更新を出す）。
 * それ以上の根拠は無いので、短くしたいなら下げてよい。
 */
var MACOS_HISTORY_DAYS = 90;


/**
 * この実行で AI を諦めたか。**1 件目が失敗した時点で、その実行では以降呼ばない。**
 *
 * Gemini が 503（過負荷）を返すときは他のリリースでも同じように返る。
 * 既存の callGeminiModel_ は 5 秒→10 秒と待って 3 回試し、**再試行のたびに
 * countAiRequest_() を呼ぶ**ので、粘るほど 1 日の枠を空振りで削り、
 * さらに待ち時間で 6 分の実行制限に近づく。粘る価値がない。
 *
 * AI を諦めても配布判断の通知は送る。AI は補助機能。
 */
var macosAiDownThisRun_ = false;

/** この実行の開始時刻。AI に入る前に経過時間を見て、6 分制限に当てないため。 */
var macosRunStartedAt_ = 0;

/** AI に入ってよい残り時間の下限（ミリ秒）。1 リリース分の再試行は最悪 70 秒ほどかかる。 */
var MACOS_AI_TIME_GUARD_MS = 180000;

/** 追跡状態。人が「適用済」と手入力できるよう日本語にしてある。 */
var MACOS_TRACK_ACTIVE = '追跡中';
var MACOS_TRACK_BACKFILL = '初期取込';
var MACOS_TRACK_DONE = '適用済';

/** 一度も調べていない、という状態。「調べたが分からない」と区別する。 */
var MACOS_NOT_EVALUATED = '未評価';

/** 通知状態。PENDING / FAILED のあいだは翌日以降も再送対象（設計確定書 §2.7・引き継ぎ §22.5）。 */
var MACOS_N_PENDING = 'PENDING';
var MACOS_N_SUCCESS = 'SUCCESS';
var MACOS_N_FAILED = 'FAILED';
var MACOS_N_NA = '対象外';

/**
 * 台帳の列。**シートの見出し文字列をキーにしない。**
 *
 * v3.2 は見出し行の文字列をそのまま JS のキーにしていたため、見出しを日本語にすると
 * 全参照が undefined になり、Phase 2/3 が積み上げた値が毎日の upsert で無音で全消去された
 * （設計確定書 §2.4）。key はコード側の名前、label はシートの見出し。両者は独立している。
 */
var MACOS_LEDGER_COLS = [
  { key: 'version',        label: 'バージョン' },
  { key: 'postingDate',    label: '公開日' },
  { key: 'managedOs',      label: '管理対象' },
  { key: 'tracking',       label: '追跡状態' },
  { key: 'securityStatus', label: 'Security状態' },
  { key: 'securityUrl',    label: 'Apple公式URL' },
  { key: 'cveList',        label: '公開CVE' },
  { key: 'appleExploited', label: 'Apple実悪用' },
  { key: 'exploitContext', label: '実悪用の記載' },
  { key: 'kevList',        label: 'CISA KEV一致' },
  { key: 'kevCheckedAt',   label: 'KEV最終照合' },
  { key: 'decision',       label: '配布判断' },
  { key: 'prevDecision',   label: '前回の配布判断' },
  { key: 'reasonCode',     label: '判定理由' },
  { key: 'noticeState',    label: '通知状態' },
  { key: 'noticedAt',      label: '最終通知' },
  { key: 'aiStatus',       label: 'AI状態' },
  { key: 'aiSummary',      label: 'AI要約' },
  { key: 'aiChanges',      label: 'AI主な修正' },
  { key: 'lastError',      label: '最終エラー' },
  { key: 'internalJson',   label: '内部データ' }
];

var MACOS_MANAGED_HEADERS = ['メジャーバージョン', '管理対象', '備考'];
var MACOS_RUNLOG_HEADERS = ['実行日時', '結果', '検知', '新規', '判定変化', '緊急',
                            '通知', '失敗', '所要秒', 'AI呼び出し', '備考'];

// ============================================================
// エントリポイント
// ============================================================

/**
 * 日次実行。**トリガーはこの関数に張る。**NW の main() とは別トリガー。
 *
 * Lock は残してある。LockService は OAuth スコープを必要とせずコストが無く、
 * upsert が「全件読む → 無ければ追加」の read-modify-write なので、
 * 実行が重なると同じリリースが 2 行入る（設計確定書 §2.13）。
 */
function macosDaily() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(30000)) throw new Error('macOS: 直前の実行がまだ動いています。');

  const started = Date.now();
  macosRunStartedAt_ = started;
  macosAiDownThisRun_ = false;
  const aiAtStart = macosAiCountToday_();
  const stats = { detected: 0, added: 0, changed: 0, emergency: 0, notified: 0, failed: 0, notes: [] };
  let errorText = '';

  try {
    const readiness = macosCheckReadiness_();
    readiness.errors.forEach(function (e) { stats.notes.push(e); });

    const src = macosSafeSource_('Security Index', macosFetchSecurityIndex_);
    if (!src.ok) throw new Error(src.error);

    const releases = macosCollectReleases_(src.data);
    stats.detected = releases.length;

    // 新しいメジャー OS が出たら、管理OS シートに行だけ用意しておく。
    // **値は空欄のまま。**自動で TRUE にすると、持っていない OS を管理対象と宣言してしまう。
    // 行が無いと担当者は「何を足せばいいか」から考えることになるので、そこだけ肩代わりする。
    const addedMajors = macosEnsureManagedRows_(releases);
    if (addedMajors.length) {
      stats.notes.push('管理OS シートに新しいメジャー ' + addedMajors.join(',') + ' の行を追加しました（TRUE/FALSE の入力が必要）');
    }

    const props = PropertiesService.getScriptProperties();
    const initialized = props.getProperty(MACOS_INITIALIZED_PROP) === 'TRUE';

    const led = macosLoadLedger_();

    // 古くなった初期取込の行を落とす。人が判断した行（追跡中・適用済）は消さない。
    const before = led.recs.length;
    led.recs = led.recs.filter(function (r) {
      if (String(r.tracking).trim() !== MACOS_TRACK_BACKFILL) return true;
      const age = macosDaysSince_(r.postingDate);
      return age === null || age <= MACOS_HISTORY_DAYS;
    });
    const pruned = before - led.recs.length;
    if (pruned) stats.notes.push(String(MACOS_HISTORY_DAYS) + ' 日より古い初期取込 ' + pruned + ' 件を台帳から外しました');

    if (led.blank || led.dup) {
      stats.notes.push('台帳を整理: 空行 ' + led.blank + ' 件を除外 / 重複 ' + led.dup + ' 件を統合');
    }

    // 台帳が空なら、INITIALIZED が TRUE でも初回取込として扱う。
    //
    // 人が台帳を消したあと INITIALIZED が TRUE のままだと、公開中の全リリース（実測 81 件）が
    // 「追跡中・通知 PENDING」で入り直し、**その場で 81 通 Slack に飛ぶ。**
    // 通知は「初期化より後に新しく出たもの」だけ、という約束をここで守る。
    const ledgerWasEmpty = led.recs.length === 0;
    const asBackfill = !initialized || ledgerWasEmpty;
    if (initialized && ledgerWasEmpty) {
      stats.notes.push('台帳が空だったため初回取込としてやり直しました（通知は送っていません）');
      Logger.log('台帳が空でした。初回取込としてやり直します。通知は送りません。');
    }

    stats.added = macosUpsertReleases_(led, releases, asBackfill);

    // 初回は「いま出ているもの」を記録するだけ。追跡もしないし通知もしない。
    //
    // Security Index は 2024 年まで遡って 81 行返す（2026-09-08 実測）。
    // 素直に追跡対象にすると翌日 87 通の Slack が飛び、6 分制限で途中死し、
    // 通知状態が PENDING のまま残って翌日また最初からになる（設計確定書 §2.3）。
    if (asBackfill) {
      macosSaveLedger_(led);
      props.setProperty(MACOS_INITIALIZED_PROP, 'TRUE');
      stats.notes.push('初回取込 ' + stats.added + ' 件を記録（追跡対象外・通知なし）');
      return;
    }

    const kev = kevCatalogWithStatus_();
    if (!kev.ok) stats.notes.push('KEV照合不可：' + kev.error);
    else if (kev.source !== 'CISA') stats.notes.push('KEV出典：' + kev.source);

    macosRunPhase2_(led, kev, stats);
    macosSaveLedger_(led);
  } catch (e) {
    errorText = String(e && e.message ? e.message : e);
    throw e;
  } finally {
    try {
      PropertiesService.getScriptProperties().setProperty(MACOS_LAST_RUN_PROP, macosNow_());
    } catch (e) { Logger.log('macOS 最終実行日時の記録に失敗: ' + e); }
    macosWriteRunLog_(stats, errorText, started, macosAiCountToday_() - aiAtStart);
    lock.releaseLock();
  }
}

function macosSafeSource_(name, fn) {
  try {
    return { ok: true, data: fn(), error: '' };
  } catch (e) {
    const msg = name + ' 取得失敗: ' + String(e && e.message ? e.message : e);
    Logger.log(msg);
    return { ok: false, data: [], error: msg };
  }
}

// ============================================================
// Phase 1: 情報源
// ============================================================

/** Apple Security Releases 一覧。**公開日と詳細ページ URL はここが正。** */
function macosFetchSecurityIndex_() {
  return macosParseSecurityIndex_(macosFetchText_(MACOS_SECURITY_INDEX_URL, 'Security Index'));
}

function macosParseSecurityIndex_(html) {
  const rows = html.match(/<tr\b[^>]*>[\s\S]*?<\/tr>/gi) || [];
  const out = [];

  rows.forEach(function (row) {
    const td = row.match(/<td\b[^>]*>([\s\S]*?)<\/td>/i);
    if (!td) return;
    const cellHtml = td[1];
    const cell = macosDecodeHtml_(macosStripTags_(cellHtml)).replace(/\s+/g, ' ').trim();

    // 「macOS Sonoma 14.3」形式にも当てる。
    // 「Security Update 2026-001 Catalina」のような macOS X.Y.Z 形式でない名前は対象外。
    const vm = cell.match(/^macOS\s+(?:[A-Za-z]+\s+)?(\d+(?:\.\d+){0,2})\b/i);
    if (!vm) return;

    const rowText = macosDecodeHtml_(macosStripTags_(row)).replace(/\s+/g, ' ').trim();
    const date = macosSecurityDate_(rowText);
    if (!date) return;

    const href = cellHtml.match(/<a\b[^>]*href=["']([^"']+)["'][^>]*>/i);
    let url = href ? href[1].trim() : '';
    if (url && /^\//.test(url)) url = 'https://support.apple.com' + url;
    if (url && !/^https:\/\//i.test(url)) url = '';

    out.push({
      version: vm[1],
      secDate: date,
      securityUrl: url,
      noPublishedCve: /This update has no published CVE entries\./i.test(rowText)
    });
  });
  return out;
}

function macosSecurityDate_(text) {
  let m = text.match(/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s+(\d{4})\b/i);
  if (m) {
    const d = new Date(m[1] + ' ' + m[2] + ', ' + m[3] + ' UTC');
    return isNaN(d.getTime()) ? '' : Utilities.formatDate(d, 'UTC', 'yyyy-MM-dd');
  }
  m = text.match(/\b(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{4})\b/i);
  if (m) {
    const d = new Date(m[2] + ' ' + m[1] + ', ' + m[3] + ' UTC');
    return isNaN(d.getTime()) ? '' : Utilities.formatDate(d, 'UTC', 'yyyy-MM-dd');
  }
  return '';
}

/**
 * Apple Security Releases の行を **バージョン単位で** 畳む。
 *
 * 同じ版の行が複数あれば新しいほうを採る。日付では畳まない。
 * Apple は 1 バージョンにつきセキュリティページを 1 つしか出さない。
 */
function macosCollectReleases_(rows) {
  const byVersion = {};
  const order = [];
  (rows || []).forEach(function (r) {
    const v = r.version;
    if (!byVersion[v]) { byVersion[v] = { version: v, postingDate: '', securityUrl: '', noPublishedCve: false }; order.push(v); }
    const t = byVersion[v];
    if (!t.postingDate || r.secDate > t.postingDate) {
      t.postingDate = r.secDate;
      if (r.securityUrl) t.securityUrl = r.securityUrl;
    }
    t.noPublishedCve = t.noPublishedCve || r.noPublishedCve;
  });
  return order.map(function (v) { return byVersion[v]; });
}

// ============================================================
// 台帳
// ============================================================

function macosHeaders_() {
  return MACOS_LEDGER_COLS.map(function (c) { return c.label; });
}

function macosRowToRec_(row) {
  const rec = {};
  MACOS_LEDGER_COLS.forEach(function (c, i) {
    const v = row[i];
    rec[c.key] = (v === undefined || v === null) ? '' : v;
  });
  return rec;
}

function macosRecToRow_(rec) {
  return MACOS_LEDGER_COLS.map(function (c) {
    const v = rec[c.key];
    return (v === undefined || v === null) ? '' : v;
  });
}

/**
 * 台帳を 1 回だけ読む。行ごとに読み書きすると 10 行で数十秒かかる。
 *
 * 読むときに **空行と重複行をここで畳む。**
 * 台帳は「1 リリース 1 行」が前提で、重複が残ると同じリリースの通知が二重に飛ぶ。
 * 2026-09-08 実測: 81 版に対して 162 行が居座っていた（下記 macosSaveLedger_ の消し漏れが原因）。
 */
function macosLoadLedger_() {
  const sh = macosSheet_(MACOS_SHEET_LEDGER);
  const last = sh.getLastRow();
  const width = MACOS_LEDGER_COLS.length;
  const raw = (last < 2) ? [] : sh.getRange(2, 1, last - 1, width).getValues();

  const byVersion = {};
  const order = [];
  let blank = 0, dup = 0;

  raw.forEach(function (row) {
    const rec = macosRowToRec_(row);
    const v = String(rec.version || '').trim();
    if (!v) { blank++; return; }
    if (!byVersion[v]) { byVersion[v] = rec; order.push(v); return; }
    // 同じ版が複数あったら、情報量の多いほうを残す。
    if (macosFilledCount_(rec) > macosFilledCount_(byVersion[v])) byVersion[v] = rec;
    dup++;
  });

  if (blank || dup) {
    Logger.log('台帳を整理しました: 空行 ' + blank + ' 件を除外 / 重複 ' + dup + ' 件を統合');
  }
  return {
    sheet: sh,
    recs: order.map(function (v) { return byVersion[v]; }),
    blank: blank,
    dup: dup
  };
}

/** 中身の入っているセルの数。重複行のどちらを残すかの判断に使う。 */
function macosFilledCount_(rec) {
  let n = 0;
  MACOS_LEDGER_COLS.forEach(function (c) {
    if (String(rec[c.key] === undefined || rec[c.key] === null ? '' : rec[c.key]).trim()) n++;
  });
  return n;
}

/**
 * 台帳を 1 回だけ書く。
 *
 * 書式を「@（書式なしテキスト）」に固定してから書く。
 * これをしないと Sheets が値を勝手に解釈し、'TRUE' が真偽値に、'15.10' が 15.1 になる。
 * 前者は `=== 'FALSE'` の比較が成立しなくなり、後者は読み戻しが一致せず毎日重複行になる
 * （設計確定書 §2.6）。
 */
function macosSaveLedger_(led) {
  if (!led.recs.length) return;
  const values = led.recs.map(macosRecToRow_);

  // **書く前にシートを広げる。**
  // 人が「行を削除」で台帳を空にすると、シートの行数そのものが減る。
  // getRange(2, 1, 81, 29) はシートの行数を超えると例外になり、
  // 「実行は完了したのに台帳が空」という分かりにくい壊れ方をする（2026-09-08 実測）。
  const needRows = values.length + 1;               // 見出し行の分
  const haveRows = led.sheet.getMaxRows();
  if (haveRows < needRows) led.sheet.insertRowsAfter(haveRows, needRows - haveRows);

  const needCols = MACOS_LEDGER_COLS.length;
  const haveCols = led.sheet.getMaxColumns();
  if (haveCols < needCols) led.sheet.insertColumnsAfter(haveCols, needCols - haveCols);

  const range = led.sheet.getRange(2, 1, values.length, needCols);
  range.setNumberFormat('@');
  range.setValues(values);

  // **書いた行より下に残った古い行を消す。**
  // 消さないと、台帳が一度でも縮んだときに古い行が居座り、
  // 次の読み込みでそれも読み込まれて重複が固定化する（2026-09-08 実測で 81 版 → 162 行）。
  const lastRow = led.sheet.getLastRow();
  const firstStale = values.length + 2;
  if (lastRow >= firstStale) {
    led.sheet.getRange(firstStale, 1, lastRow - firstStale + 1, needCols).clearContent();
  }
}

/**
 * リリースを台帳へ反映する。**鍵はバージョン。**
 *
 * v3.2 は `macOS|版|ビルド|公開日` を鍵にしていたが、情報源によって「日付」の意味が違ううえ
 * フィード更新で動くものもあり、同じリリースが毎回「新規」になって速報が繰り返し出る
 * （設計確定書 §2.1）。ビルドは Apple が使い回さないので版とビルドで十分に一意。
 *
 * 同じ版でビルドだけ変わった場合（Apple の差し替え）は、同一リリースの更新として扱い、
 * 追跡中なら通知をやり直す。行を分けると「どちらを配ったか」が台帳から読めなくなる。
 *
 * @return {number} 新規に追加した行数
 */
function macosUpsertReleases_(led, releases, isBackfill) {
  const byVersion = {};
  led.recs.forEach(function (rec) { byVersion[String(rec.version)] = rec; });

  let added = 0;

  releases.forEach(function (r) {
    const managed = macosManagedState_(r.version);
    const existing = byVersion[r.version];

    if (!existing) {
      // 監視を始める前の古いリリースは記録しない。いま対応できることが無く、台帳を読めなくする。
      const age = macosDaysSince_(r.postingDate);
      if (age !== null && age > MACOS_HISTORY_DAYS) return;

      const rec = {};
      MACOS_LEDGER_COLS.forEach(function (c) { rec[c.key] = ''; });
      rec.version = r.version;
      rec.postingDate = r.postingDate;
      rec.managedOs = managed;
      rec.securityUrl = r.securityUrl || '';

      if (isBackfill) {
        // 監視を始める前からあったリリース。**一度も調べていない。**
        // PENDING や UNKNOWN を入れると「調べたが分からなかった」ように読める。
        // 実際は見ていないので、そう書く（README §4.1 空欄に意味を持たせない）。
        rec.tracking = MACOS_TRACK_BACKFILL;
        rec.securityStatus = MACOS_NOT_EVALUATED;
        rec.appleExploited = MACOS_NOT_EVALUATED;
        rec.decision = MACOS_NOT_EVALUATED;
        rec.noticeState = MACOS_N_NA;
        rec.aiStatus = MACOS_NOT_EVALUATED;
      } else {
        rec.tracking = MACOS_TRACK_ACTIVE;
        rec.securityStatus = r.noPublishedCve ? 'NO_PUBLISHED_CVE' : (r.securityUrl ? 'PENDING_DETAIL' : 'PENDING_INDEX');
        rec.appleExploited = 'UNKNOWN';
        rec.decision = 'PENDING';
        rec.reasonCode = 'INFORMATION_INCOMPLETE';
        rec.aiStatus = 'PENDING';
        rec.noticeState = MACOS_N_PENDING;
      }

      led.recs.push(rec);
      byVersion[r.version] = rec;
      added++;
      return;
    }

    if (r.postingDate) existing.postingDate = r.postingDate;
    existing.managedOs = managed;
    if (r.securityUrl) existing.securityUrl = r.securityUrl;
    if (r.noPublishedCve) existing.securityStatus = 'NO_PUBLISHED_CVE';
    else if (!existing.securityStatus || existing.securityStatus === 'PENDING_INDEX') {
      existing.securityStatus = existing.securityUrl ? 'PENDING_DETAIL' : 'PENDING_INDEX';
    }
  });

  return added;
}

/**
 * 情報源に出てきたメジャー系統のうち、管理OS シートに無いものの行を作る。
 * **値は空欄のまま**にする。TRUE/FALSE を決めるのは人。
 *
 * @return {Array} 追加したメジャーの一覧
 */
function macosEnsureManagedRows_(releases) {
  const sh = macosSheet_(MACOS_SHEET_MANAGED);
  const last = sh.getLastRow();
  const known = {};
  if (last >= 2) {
    sh.getRange(2, 1, last - 1, 1).getValues().forEach(function (r) {
      const v = String(r[0] || '').trim();
      if (v) known[v] = true;
    });
  }

  const add = [];
  (releases || []).forEach(function (r) {
    const major = String(r.version || '').split('.')[0];
    if (!/^\d+$/.test(major) || known[major] || add.indexOf(major) >= 0) return;
    add.push(major);
  });
  if (!add.length) return [];

  add.sort(function (a, b) { return Number(b) - Number(a); });
  const rows = add.map(function (m) { return [m, '', '運用前に TRUE / FALSE を入れてください']; });
  sh.getRange(sh.getLastRow() + 1, 1, rows.length, 3).setValues(rows);
  Logger.log('管理OS シートに ' + add.join(',') + ' の行を追加しました。TRUE / FALSE を入れてください。');
  return add;
}

/**
 * 管理対象かどうか。**未設定は UNKNOWN。**サンプル値を自動で TRUE にしない。
 * 文字列で返す（真偽値で返すと台帳側の比較が型でずれる）。
 */
function macosManagedState_(version) {
  const major = String(version || '').split('.')[0];
  const sh = macosSheet_(MACOS_SHEET_MANAGED);
  const last = sh.getLastRow();
  if (last < 2) return 'UNKNOWN';
  const values = sh.getRange(2, 1, last - 1, 2).getValues();
  for (let i = 0; i < values.length; i++) {
    if (String(values[i][0]).trim() !== major) continue;
    const v = values[i][1];
    if (v === true || /^TRUE$/i.test(String(v).trim())) return 'TRUE';
    if (v === false || /^FALSE$/i.test(String(v).trim())) return 'FALSE';
    return 'UNKNOWN';
  }
  return 'UNKNOWN';
}

// ============================================================
// Phase 2: Apple セキュリティ情報・KEV・配布判断
// ============================================================

function macosRunPhase2_(led, kev, stats) {
  const pending = [];

  led.recs.forEach(function (rec) {
    if (String(rec.tracking) !== MACOS_TRACK_ACTIVE) return;

    try {
      macosUpdateSecurity_(rec);

      if (kev.ok && macosShouldCheckKev_(rec)) {
        rec.kevList = macosMatchKev_(rec.cveList, kev.map).join(',');
        rec.kevCheckedAt = macosNow_();
      }

      const before = String(rec.decision || 'PENDING').toUpperCase();
      const ev = macosEvaluateDecision_(rec, kev.ok);
      rec.reasonCode = ev.reason;

      if (before !== ev.decision) {
        rec.prevDecision = before;
        rec.decision = ev.decision;
        rec.noticeState = MACOS_N_PENDING;
        stats.changed++;
      }

      // **管理対象外と宣言した系統は Slack に出さない。**
      // 対応しないと決めたものを毎回知らせても判断は増えない。
      // ただし台帳には残す。「見落とした」のか「判断して外した」のかを後から区別するため
      // （README §1.0「対応しなくてよいと説得する材料」）。
      if (macosNormBool_(rec.managedOs) === 'FALSE') rec.noticeState = MACOS_N_NA;
      if (ev.decision === 'EMERGENCY') stats.emergency++;
    } catch (e) {
      rec.lastError = 'PHASE2: ' + String(e && e.message ? e.message : e);
      stats.failed++;
      Logger.log('macOS ' + rec.version + ': ' + rec.lastError);
    }
  });

  // 通知は判定がすべて出そろってから。
  // PENDING / FAILED のあいだは翌日以降も対象なので、送信失敗が黙って消えない。
  led.recs.forEach(function (rec) {
    if (String(rec.tracking) === MACOS_TRACK_ACTIVE && macosNeedsNotice_(rec.noticeState)) {
      pending.push(rec);
    }
  });

  pending.forEach(function (rec) {
    try {
      macosSendDecisionNotice_(rec, kev);
      stats.notified++;
    } catch (e) {
      stats.failed++;
      Logger.log('macOS Slack 送信失敗 (' + rec.version + '): ' + e);
    }
  });

  if (macosAiDownThisRun_) stats.notes.push('AI が応答しないため、この実行は AI 要約なしで通知しました');
}

function macosNeedsNotice_(state) {
  const s = String(state || '');
  return s === MACOS_N_PENDING || s === MACOS_N_FAILED;
}

/** 管理対象外と新メジャー OS は Apple 詳細も KEV も取りに行かない（判定に使わないため）。 */
function macosShouldFetchSecurity_(rec) {
  if (String(rec.tracking).trim() === MACOS_TRACK_BACKFILL) return false;
  if (macosNormBool_(rec.managedOs) === 'FALSE') return false;
  if (macosIsMajorUpgrade_(rec.version)) return false;
  return true;
}

function macosShouldCheckKev_(rec) {
  return macosShouldFetchSecurity_(rec);
}

/**
 * Apple のセキュリティ詳細ページを読み直す。
 *
 * **取れなかったら PENDING_DETAIL にする。**以前取れていた CVE は診断用に残すが、
 * 「前は緑だったから今日も緑」にはしない。分からないものを緑にしないのが原則 2。
 */
function macosUpdateSecurity_(rec) {
  if (!macosShouldFetchSecurity_(rec)) return;

  if (String(rec.securityStatus) === 'NO_PUBLISHED_CVE') {
    rec.cveList = '';
    rec.appleExploited = 'FALSE';
    rec.exploitContext = '';
    return;
  }

  if (!rec.securityUrl) {
    rec.securityStatus = 'PENDING_INDEX';
    return;
  }

  try {
    const d = macosFetchSecurityDetail_(rec.securityUrl, rec.version);
    const cves = d.cves.join(',');
    const exploited = d.appleExploited ? 'TRUE' : 'FALSE';

    const changed = String(rec.cveList || '') !== cves ||
                    String(rec.appleExploited || '') !== exploited ||
                    String(rec.securityStatus || '') !== 'FOUND';

    rec.securityStatus = 'FOUND';
    rec.cveList = cves;
    rec.appleExploited = exploited;
    rec.exploitContext = macosClip_(d.exploitContexts.join(' | '), 900);
    rec.lastError = '';

    // 事実は台帳に持たない。毎日取り直すので持つ必要がなく、
    // 数十件あるとセルの 5 万字上限に当たる。AI の再実行防止は指紋だけで足りる。
    rec.__facts = d.facts;

    if (changed) {
      rec.aiStatus = 'PENDING';
      rec.noticeState = MACOS_N_PENDING;
    }
  } catch (e) {
    rec.securityStatus = 'PENDING_DETAIL';
    rec.lastError = 'APPLE_SECURITY: ' + String(e && e.message ? e.message : e);
  }
}

function macosFetchSecurityDetail_(url, expectedVersion) {
  if (!/^https:\/\/support\.apple\.com\//i.test(String(url || ''))) {
    throw new Error('Apple 公式以外の URL は読まない: ' + url);
  }
  return macosParseSecurityDetail_(macosFetchText_(url, 'Apple Security 詳細'), expectedVersion);
}

function macosParseSecurityDetail_(html, expectedVersion) {
  const text = macosDecodeHtml_(macosStripTags_(html)).replace(/\s+/g, ' ').trim();
  if (!text) throw new Error('本文が空');

  // 別バージョンのページを掴んでいないか確かめる。
  if (expectedVersion) {
    const esc = String(expectedVersion).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (!new RegExp('\\bmacOS\\b[\\s\\S]{0,120}\\b' + esc + '\\b', 'i').test(text)) {
      throw new Error('ページのバージョンが一致しない（期待 ' + expectedVersion + '）');
    }
  }

  const cves = macosUnique_((text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(function (x) { return x.toUpperCase(); }));
  const facts = macosParseSecurityFacts_(html);

  // Apple が実悪用を明記した文を根拠として拾う。判定には TRUE/FALSE だけを使い、
  // 文そのものは Slack と台帳に残す（判断ではなく判断の根拠を残す）。
  const contexts = [];
  const re = /[^.?!]{0,500}Apple is aware of a report that this issue may have been[^.?!]{0,500}exploited[^.?!]*[.?!]/gi;
  let m;
  while ((m = re.exec(text)) !== null) contexts.push(m[0].trim());

  if (!cves.length && !facts.length) throw new Error('CVE も修正項目も読み取れない（ページ構造の変更の可能性）');

  return { cves: cves, appleExploited: contexts.length > 0, exploitContexts: macosUnique_(contexts), facts: facts };
}

function macosParseSecurityFacts_(html) {
  const facts = [];
  const re = /<h([2-4])\b[^>]*>([\s\S]*?)<\/h\1>([\s\S]*?)(?=<h[2-4]\b|$)/gi;
  let m;
  while ((m = re.exec(String(html || ''))) !== null) {
    const component = macosDecodeHtml_(macosStripTags_(m[2])).replace(/\s+/g, ' ').trim();
    const body = macosDecodeHtml_(macosStripTags_(m[3])).replace(/\s+/g, ' ').trim();
    if (!body || !/\bImpact\s*:/i.test(body)) continue;

    const im = body.match(/\bImpact\s*:\s*([\s\S]*?)(?=\s+Description\s*:|\s+CVE-\d{4}-\d{4,7}|\s+Entry\s+(?:added|updated)|$)/i);
    const dm = body.match(/\bDescription\s*:\s*([\s\S]*?)(?=\s+CVE-\d{4}-\d{4,7}|\s+Entry\s+(?:added|updated)|$)/i);
    const cves = macosUnique_((body.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(function (x) { return x.toUpperCase(); }));
    const impact = im ? im[1].trim() : '';
    const description = dm ? dm[1].trim() : '';
    if (!impact && !description && !cves.length) continue;

    facts.push({ id: 'F' + (facts.length + 1), component: component || '不明', impact: impact, description: description, cves: cves });
  }
  return facts;
}

function macosMatchKev_(cveList, kevMap) {
  const ids = macosParseCves_(cveList);
  return ids.filter(function (c) { return kevMap && kevMap[c]; });
}

function macosParseCves_(value) {
  return macosUnique_((String(value || '').match(/CVE-\d{4}-\d{4,7}/gi) || [])
    .map(function (x) { return x.toUpperCase(); }));
}

/**
 * 配布判断。**この順番を変えないこと。**
 *
 * v3.2 の判定順序をそのまま引き継いでいる（引き継ぎ資料 §8.2）。
 * AI はここに一切関与しない。
 */
function macosEvaluateDecision_(rec, kevAvailable) {
  const managed = macosNormBool_(rec.managedOs);
  const sec = String(rec.securityStatus || 'PENDING_INDEX').toUpperCase();
  const exploited = macosNormBool_(rec.appleExploited);
  const kev = macosParseCves_(rec.kevList);
  const cve = macosParseCves_(rec.cveList);
  const prev = String(rec.decision || 'PENDING').toUpperCase();

  // ① 新メジャー OS は月次パッチではなくアップグレード計画の話。
  if (macosIsMajorUpgrade_(rec.version)) return { decision: 'SEPARATE_PLAN', reason: 'MAJOR_RELEASE' };

  // ② / ③ 自社が持っているかどうか。未設定は決めない。
  if (managed === 'FALSE') return { decision: 'NOT_APPLICABLE', reason: 'MANAGED_FALSE' };
  if (managed !== 'TRUE') return { decision: 'PENDING', reason: 'MANAGED_UNKNOWN' };

  // ④ 一度緊急にしたものは、外部情報の揺れで自動的に下げない。人が「適用済」にするまで維持。
  if (prev === 'EMERGENCY') return { decision: 'EMERGENCY', reason: 'EMERGENCY_STICKY' };

  // ⑤ / ⑥ 実悪用の確認は他のすべてに優先する。
  if (exploited === 'TRUE') return { decision: 'EMERGENCY', reason: 'APPLE_EXPLOITED' };
  if (kev.length > 0) return { decision: 'EMERGENCY', reason: 'CISA_KEV' };

  // ⑦ Apple の情報が確認できないうちは「定期更新まで待てる」と言わない。
  if (sec === 'PENDING_INDEX' || sec === 'PENDING_DETAIL' || sec === 'UNKNOWN') {
    return { decision: 'PENDING', reason: 'SECURITY_PENDING' };
  }

  // ⑧ Apple が「公開 CVE エントリなし」と明記した場合。安全という意味ではない。
  if (sec === 'NO_PUBLISHED_CVE') return { decision: 'NEXT_CYCLE', reason: 'NO_EMERGENCY_EVIDENCE' };

  if (sec === 'FOUND') {
    // ⑨ 昨日照合できたことは、今日の KEV が変わっていない証明にならない。
    if (cve.length > 0 && !kevAvailable) return { decision: 'PENDING', reason: 'CISA_UNAVAILABLE' };
    // ⑩
    return { decision: 'NEXT_CYCLE', reason: 'NO_EMERGENCY_EVIDENCE' };
  }

  return { decision: 'PENDING', reason: 'INFORMATION_INCOMPLETE' };
}

/** 27.0 のような x.0（および数字だけ）は新メジャー OS。26.6.2 は月次パッチ系。 */
function macosIsMajorUpgrade_(version) {
  const parts = String(version || '').trim().split('.');
  if (!/^\d+$/.test(parts[0] || '')) return false;
  if (parts.length === 1) return true;
  return parts.slice(1).every(function (p) { return /^0+$/.test(p); });
}

// ============================================================
// Phase 3: AI（Apple の修正内容を短くするだけ）
// ============================================================

/**
 * AI に投げてよいか。
 *
 * 無料枠は 1 日 20 回程度でモデル別。NW と合算した当日消費で見る。
 * 上限に達したら AI を呼ばずに送る。**配布判断は AI に依存しないので止まらない。**
 */
function macosAiAllowed_() {
  if (macosAiDownThisRun_) return false;
  if (macosRunStartedAt_ && (Date.now() - macosRunStartedAt_) > MACOS_AI_TIME_GUARD_MS) return false;
  return macosAiCountToday_() < MACOS_AI_DAILY_BUDGET;
}

function macosAiCountToday_() {
  return (typeof sharedAiCountToday_ === 'function') ? sharedAiCountToday_() : 0;
}

function macosPrepareAiSummary_(rec) {
  const facts = rec.__facts || [];
  if (!facts.length) {
    rec.aiStatus = 'SKIPPED_NO_FACTS';
    return { ok: false };
  }

  const selected = macosSelectFacts_(facts, rec);
  const fingerprint = macosFingerprint_(selected);
  const internal = macosParseJson_(rec.internalJson, {});

  // 入力が同じなら前回の要約を使い回す。無料枠を無駄に減らさないため。
  if (String(rec.aiStatus) === 'SUCCESS' && internal.aiFp === fingerprint && String(rec.aiSummary || '')) {
    return { ok: true, summary: String(rec.aiSummary), changes: macosParseJson_(rec.aiChanges, []) };
  }

  if (!macosAiAllowed_()) {
    rec.aiStatus = macosAiDownThisRun_ ? 'SKIPPED_AI_DOWN' : 'SKIPPED_BUDGET';
    return { ok: false };
  }

  try {
    const raw = callGemini_(macosBuildAiPrompt_(selected, rec), macosAiSchema_());
    const out = macosParseJson_(macosStripCodeFence_(raw), null);
    if (!out) throw new Error('AI 応答を JSON として読めない');
    macosValidateAiOutput_(out, selected);

    rec.aiStatus = 'SUCCESS';
    rec.aiSummary = macosClip_(String(out.summary.text), 500);
    rec.aiChanges = JSON.stringify(out.notable_changes || []);
    internal.aiFp = fingerprint;
    internal.aiPromptVersion = MACOS_AI_PROMPT_VERSION;
    internal.aiSourceIds = macosCollectSourceIds_(out).join(',');
    internal.aiLastRun = macosNow_();
    rec.internalJson = JSON.stringify(internal);

    return { ok: true, summary: rec.aiSummary, changes: out.notable_changes || [] };
  } catch (e) {
    rec.aiStatus = 'FAILED';
    internal.aiFp = fingerprint;
    rec.internalJson = JSON.stringify(internal);
    rec.lastError = 'AI: ' + String(e && e.message ? e.message : e);
    // ここで諦める。理由は macosAiDownThisRun_ の宣言部に書いてある。
    macosAiDownThisRun_ = true;
    Logger.log('macOS AI 失敗 (' + rec.version + '): ' + rec.lastError);
    Logger.log('この実行では以降 AI を呼びません。配布判断の通知は AI なしで送ります。');
    return { ok: false };
  }
}

/**
 * 既存の callGeminiModel_ は responseSchema を渡さないと形を保証しない。
 * プロンプト側も入れ子構造（summary.text）を書いていないので、
 * スキーマ無しで投げると検証で必ず落ちる（設計確定書 §2.9）。
 */
function macosAiSchema_() {
  return {
    type: 'OBJECT',
    properties: {
      summary: {
        type: 'OBJECT',
        properties: { text: { type: 'STRING' }, source_ids: { type: 'ARRAY', items: { type: 'STRING' } } },
        required: ['text', 'source_ids']
      },
      notable_changes: {
        type: 'ARRAY',
        items: {
          type: 'OBJECT',
          properties: { text: { type: 'STRING' }, source_ids: { type: 'ARRAY', items: { type: 'STRING' } } },
          required: ['text', 'source_ids']
        }
      }
    },
    required: ['summary', 'notable_changes']
  };
}

function macosBuildAiPrompt_(facts, rec) {
  const compact = facts.map(function (f) {
    return { id: f.id, component: f.component, impact: f.impact, description: f.description, cves: f.cves };
  });
  return [
    'あなたは企業の macOS 脆弱性管理担当者向けの編集者です。',
    '役割は、下記の Apple 公式情報だけを、短く分かりやすい日本語へ言い換えることです。',
    '',
    '禁止事項:',
    '- 緊急度や配布時期を判断しない',
    '- CVE 番号を回答文へ書かない',
    '- URL を生成しない',
    '- 次の対応を決めない',
    '- 入力にない事実を追加しない / 推測しない',
    '- 「早めの適用」「急ぎの対応」「臨時更新」「定期更新」「判断保留」「対象外」など配布判断の表現を書かない',
    '',
    'JSON で返してください。形は次のとおりです。',
    '{"summary":{"text":"1〜2文","source_ids":["F1"]},"notable_changes":[{"text":"...","source_ids":["F2"]}]}',
    'notable_changes は最大 3 件。summary と各 notable_changes には必ず根拠の source_ids を付けてください。',
    '根拠が不足する場合は無理に補完しないでください。',
    '',
    '対象 macOS: ' + String(rec.version || ''),
    'Apple 公式から抽出した事実:',
    JSON.stringify(compact)
  ].join('\n');
}

/** KEV 一致・権限昇格系を優先して、上位だけ AI に渡す。 */
function macosSelectFacts_(facts, rec) {
  const kev = {};
  macosParseCves_(rec.kevList).forEach(function (c) { kev[c] = true; });
  const re = /(kernel|root|arbitrary code|execute code|remote attacker|remote user|sandbox|gatekeeper|authentication|privilege|memory corruption)/i;

  function score(f) {
    if ((f.cves || []).some(function (c) { return kev[String(c).toUpperCase()]; })) return 100;
    return re.test([f.component, f.impact, f.description].join(' ')) ? 50 : 1;
  }
  function num(id) { const m = String(id || '').match(/^F(\d+)$/); return m ? Number(m[1]) : 999999; }

  return facts.slice().sort(function (a, b) {
    const d = score(b) - score(a);
    return d !== 0 ? d : num(a.id) - num(b.id);
  }).slice(0, MACOS_AI_MAX_FACTS);
}

function macosFingerprint_(facts) {
  const canonical = JSON.stringify((facts || []).map(function (f) {
    return { id: f.id, component: f.component || '', impact: f.impact || '',
             description: f.description || '', cves: (f.cves || []).slice().sort() };
  }));
  const bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, canonical, Utilities.Charset.UTF_8);
  return bytes.map(function (b) { return ('0' + ((b < 0 ? b + 256 : b).toString(16))).slice(-2); }).join('');
}

/**
 * AI 出力の検証。**入力に無いものを 1 つでも含んでいたら丸ごと捨てる。**
 * 捨てても配布判断の通知は送る。AI は補助機能であって、脆弱性管理の停止要因ではない。
 */
function macosValidateAiOutput_(out, facts) {
  if (!out || typeof out !== 'object') throw new Error('AI 出力の形が不正（root）');
  if (!out.summary || typeof out.summary.text !== 'string' || !Array.isArray(out.summary.source_ids)) {
    throw new Error('AI 出力の形が不正（summary）');
  }
  if (!Array.isArray(out.notable_changes) || out.notable_changes.length > 3) {
    throw new Error('AI 出力の形が不正（notable_changes）');
  }

  const valid = {};
  (facts || []).forEach(function (f) { valid[String(f.id)] = true; });

  [out.summary].concat(out.notable_changes).forEach(function (b) {
    const text = String(b.text || '').trim();
    if (!text) throw new Error('AI 出力に空の本文がある');
    if (!Array.isArray(b.source_ids) || !b.source_ids.length) throw new Error('AI 出力に根拠 ID が無い');
    b.source_ids.forEach(function (id) {
      if (!valid[String(id)]) throw new Error('入力に無い根拠 ID を返した: ' + id);
    });
    if (/https?:\/\//i.test(text)) throw new Error('AI が URL を生成した');
    if (/CVE-\d{4}-\d{4,7}/i.test(text)) throw new Error('AI が CVE 番号を書いた');
    if (/\b(URGENT|EMERGENCY|REVIEW|NEXT_CYCLE|PENDING|NOT_APPLICABLE|SEPARATE_PLAN)\b/i.test(text) ||
        /(緊急適用|臨時更新|定期更新|次回定例|早めの適用|急ぎの対応|判断保留|自社対象外|対象外|別途計画|推奨[：:])/.test(text)) {
      throw new Error('AI が配布判断の表現を書いた');
    }
  });
  return true;
}

function macosCollectSourceIds_(out) {
  const ids = [];
  [out.summary].concat(out.notable_changes || []).forEach(function (b) {
    (b.source_ids || []).forEach(function (id) { if (ids.indexOf(id) < 0) ids.push(id); });
  });
  return ids;
}

function macosStripCodeFence_(s) {
  return String(s || '').replace(/^\s*```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
}

// ============================================================
// Slack
// ============================================================

/**
 * Slack へ送る。**既存の postSlack_ をそのまま使わずここでラップする。**
 *
 * 既存 postSlack_ は非 200 でもログに書いて応答コードを返すだけで、例外を投げない。
 * 投げる前提で書くと、Webhook 失効も Block Kit 不正も「送信成功」として台帳に残り、
 * 再送条件に永久に該当しなくなる（設計確定書 §2.7）。
 */
function macosPostSlack_(payload) {
  const url = String(PropertiesService.getScriptProperties().getProperty(SLACK_WEBHOOK_PROP) || '').trim();
  if (!url) throw new Error(SLACK_WEBHOOK_PROP + ' が未設定です。');
  const code = postSlack_(url, payload);
  if (code !== 200) throw new Error('Slack 送信失敗 HTTP ' + code);
  return true;
}

/**
 * 配布判断の通知。**1 リリース 1 通。**
 *
 * 1 行目だけで「何が出たか」と「いつ当てるか」が分かることを最優先にしている。
 * 公開の事実・バージョン・結論を全部タイトルへ寄せてあるのはそのため
 * （Slack の通知プレビューにも 1 行目が出る）。
 *
 * 同じ結論を言い換えて繰り返さない。2026-09-10 のレビューで、🟢 のとき
 * 見出し・理由・結論・注意書きの 4 か所が同じことを言っていたのを削った。
 */
function macosSendDecisionNotice_(rec, kev) {
  const decision = String(rec.decision || 'PENDING').toUpperCase();
  const isFirst = !String(rec.noticedAt || '');
  const ai = macosUseAi_(rec) ? macosPrepareAiSummary_(rec) : { ok: false };
  const payload = macosBuildDecisionPayload_(rec, decision, isFirst, ai, kev);

  try {
    macosPostSlack_(payload);
    rec.noticeState = MACOS_N_SUCCESS;
    rec.noticedAt = macosNow_();
    if (ai.ok || !macosUseAi_(rec)) rec.lastError = '';
  } catch (e) {
    rec.noticeState = MACOS_N_FAILED;
    rec.lastError = 'SLACK: ' + String(e && e.message ? e.message : e);
    throw e;
  }
}

/** 送信するペイロードを組み立てる。送信はしないので、テストからも呼べる。 */
function macosBuildDecisionPayload_(rec, decision, isFirst, ai, kev) {
  const title = macosNoticeTitle_(rec, decision, isFirst);
  const blocks = [{ type: 'header', text: { type: 'plain_text', text: title, emoji: true } }];

  blocks.push({ type: 'section', text: { type: 'mrkdwn', text: macosLeadText_(rec, decision) } });

  // 2 通目以降は「なぜまた来たか」を必ず書く。書かないと 1 通目と見分けが付かない。
  const prev = String(rec.prevDecision || '').toUpperCase();
  if (!isFirst && prev && prev !== decision) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn',
      text: '前回は「' + macosShortVerdict_(prev) + '」でした' }] });
  }

  // 🔴 の根拠。Apple が実悪用を書いた原文をそのまま引く。
  //
  // 訳さずに原文を出す。ここは「なぜ緊急なのか」を上へ説明するときに引用される文で、
  // 判断の根拠そのもの。要約や翻訳を挟むと、根拠が加工された状態で伝わる
  // （README §1.5「判断ではなく判断の根拠を残す」）。スコープの日本語は事実行の
  // 「Apple実悪用 あり（Mac に関する記載）」が担う。
  const evidence = String(rec.exploitContext || '').trim();
  if (evidence) {
    const quoted = evidence.split(' | ').slice(0, 2)
      .map(function (t) { return '> ' + macosClip_(t.trim(), 600); }).join('\n');
    blocks.push({ type: 'section', text: { type: 'mrkdwn',
      text: quoted + '\n_Apple 公式ページの記載（原文）_' } });
  }

  if (ai.ok) {
    const lines = ['*更新内容*', ai.summary];
    (ai.changes || []).slice(0, 3).forEach(function (c) { lines.push('・' + String(c.text || '')); });
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: macosClip_(lines.join('\n'), 2800) } });
  } else if (macosUseAi_(rec)) {
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: '更新内容の要約なし（配布判断には影響しません）' }] });
  }

  // 事実は 2 行にまとめる。判断の根拠を残すために出すので、確認できていない項目は
  // 「なし」ではなく「未確認」と書く（README §1.5「なしに丸めない」）。
  const managed = macosNormBool_(rec.managedOs);
  // 公開日は 1 行目にあるので、ここでは繰り返さない。
  // ただし日が経っているときだけ経過を出す。検知の遅れや積み残しがここで見える。
  const facts = [];
  const age = macosDaysSince_(rec.postingDate);
  if (age !== null && age >= 7) facts.push('公開から ' + age + ' 日');
  facts.push('管理OS ' + (managed === 'TRUE' ? '対象' : managed === 'FALSE' ? '対象外' : '未確認'));
  facts.push('公開CVE ' + macosCveCountText_(rec));

  // 実悪用と KEV は独立した 2 つの確認なので、値は必ずどこかに出す。
  // ただし NO_EMERGENCY_EVIDENCE のときは理由行が同じ 2 つを既に書いているので、
  // ここで繰り返さず、理由行に無い「いつ照合したか」だけを足す。
  const lines = [];
  if (String(rec.reasonCode) === 'NO_EMERGENCY_EVIDENCE') {
    facts.push('実悪用・KEV 照合 ' + (rec.kevCheckedAt ? String(rec.kevCheckedAt).slice(5, 16) : '未実施'));
    lines.push(facts.join(' ／ '));
  } else {
    lines.push(facts.join(' ／ '));
    lines.push('Apple実悪用 ' + macosExploitLabel_(rec) + ' ／ CISA KEV ' + macosKevText_(rec, kev));
  }

  blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: lines.join('\n') }] });

  const links = [];
  if (rec.securityUrl) links.push('<' + rec.securityUrl + '|Apple公式の詳細>');
  const ssUrl = macosSpreadsheetUrl_();
  if (ssUrl) links.push('<' + ssUrl + '|macOS台帳>');

  // 注意書きは 1 行に畳む。毎日同じ文が 3 行続くと 3 回目から読まれない。
  const notes = [];
  if (decision === 'NEXT_CYCLE') notes.push('「急ぎの対応は不要」は安全の保証ではなく、現時点で臨時更新の条件に当たらないという判定です。');
  if (managed === 'TRUE') notes.push('端末モデル / CPU 個別の条件は対象外。');
  if (ai.ok) notes.push('要約のみ AI で、判断・CVE・KEV はコードです。');

  const foot = [];
  if (links.length) foot.push(links.join(' ／ '));
  if (notes.length) foot.push('※ ' + notes.join(' '));
  if (foot.length) {
    blocks.push({ type: 'divider' });
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: macosClip_(foot.join('\n'), 2800) }] });
  }

  return { text: title, blocks: blocks };
}

/**
 * 1 行目。**ここだけで「何が出たか」と「いつ当てるか」が分かるようにする。**
 * Slack の通知プレビューにもこの文字列が出る。
 */
function macosNoticeTitle_(rec, decision, isFirst) {
  // ビルド番号は 1 行目に入れない。**読み手がそれを見て何かをすることが無い**ため
  // （2026-09-10 の確認）。記録として事実行には残す。
  //
  // **公開日は 1 行目に入れる。**これは参考情報ではなく「いつから晒されているか」の答えで、
  // 判断材料そのもの。とくに、1 か月前のリリースが KEV 掲載で今日 🔴 に変わった、という
  // ケースでは、日付が無いと新しく出たものだと誤読する。
  const pub = rec.postingDate ? '（' + rec.postingDate + ' 公開）' : ' ';
  return macosHeadline_(decision) + ' macOS ' + rec.version + pub +
         '— ' + macosShortVerdict_(decision);
}

/**
 * 1 行目に置く結論。**読んだ人が次に何をするかが分かる言葉にする。**
 *
 * 「次回定例アップデートで可」という言い方はやめた。社内でその呼び方をしていないうえ、
 * 「定例」から月次を連想させるが、実際のベースラインは **年1回の定期 OS 更新**
 * （社内ルール案_OS更新基準.md）。
 *
 * さらに社内ルールは「次回定期」という値を一度使って**廃止している**
 * （設定を見ていないのに待てると断定していたため）。同じ語をここで復活させない。
 *
 * 社内語彙の「定期更新 / 臨時更新」は本文側で使い、1 行目は行動が分かる平易な言葉にする。
 */
function macosShortVerdict_(d) {
  if (d === 'EMERGENCY') return '早めの適用を検討';
  if (d === 'NEXT_CYCLE') return '急ぎの対応は不要';
  if (d === 'SEPARATE_PLAN') return '別途アップグレード計画';
  if (d === 'NOT_APPLICABLE') return '対象外';
  return '判断保留';
}

/**
 * 判定の根拠と、必要なら次の行動。
 *
 * 🟢 のときは行動を書かない。1 行目の言い換えにしかならず、
 * タイトル・理由・結論・注意書きで同じことを 4 回言う原因になっていた。
 */
function macosLeadText_(rec, decision) {
  const reason = macosReasonText_(rec.reasonCode, rec);
  // 🟢 は行動を書かない。1 行目の言い換えにしかならないので、
  // 代わりに社内語彙（定期更新）で位置づけを 1 文だけ添える。
  if (decision === 'NEXT_CYCLE') return reason + '定期更新まで待てる状態です。';
  return reason + '\n' + macosActionText_(decision);
}

/** 公開日からの経過日数。日付が読めなければ null。 */
function macosDaysSince_(yyyyMmDd) {
  const m = String(yyyyMmDd || '').match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return null;
  const then = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  const t = Utilities.formatDate(new Date(), MACOS_TZ, 'yyyy-MM-dd').match(/^(\d{4})-(\d{2})-(\d{2})/);
  const today = Date.UTC(Number(t[1]), Number(t[2]) - 1, Number(t[3]));
  return Math.max(0, Math.floor((today - then) / 86400000));
}

/** Apple のセキュリティ情報を実際に読めているか。読めていないなら「なし」と言わない。 */
function macosSecurityVerified_(rec) {
  const s = String(rec.securityStatus || '').toUpperCase();
  return s === 'FOUND' || s === 'NO_PUBLISHED_CVE';
}

function macosCveCountText_(rec) {
  if (!macosSecurityVerified_(rec)) return '未確認';
  if (String(rec.securityStatus).toUpperCase() === 'NO_PUBLISHED_CVE') return 'Apple 公開エントリなし';
  const n = macosParseCves_(rec.cveList).length;
  return n ? (n + ' 件') : '0 件';
}

/** AI を使うのは、判定が出ていて Apple の修正内容も読めている場合だけ。 */
function macosUseAi_(rec) {
  const d = String(rec.decision || '').toUpperCase();
  if (d !== 'EMERGENCY' && d !== 'NEXT_CYCLE') return false;
  return String(rec.securityStatus || '').toUpperCase() === 'FOUND' && !!(rec.__facts && rec.__facts.length);
}

function macosHeadline_(d) {
  if (d === 'EMERGENCY') return ':red_circle:';
  if (d === 'NEXT_CYCLE') return ':large_green_circle:';
  if (d === 'SEPARATE_PLAN') return ':large_purple_circle:';
  if (d === 'NOT_APPLICABLE') return ':black_circle:';
  return ':white_circle:';
}

function macosReasonText_(code, rec) {
  const map = {
    MAJOR_RELEASE: '新しいメジャー OS のため、月次パッチとは別に計画します。',
    MANAGED_FALSE: 'macOS管理OS シートで管理対象外に設定されています。',
    MANAGED_UNKNOWN: '自社の管理対象 OS か確認できません。',
    APPLE_EXPLOITED: 'Apple が実悪用の可能性を明記しています。',
    CISA_KEV: '対象 CVE が CISA KEV に掲載されています。',
    SECURITY_PENDING: 'Apple のセキュリティ情報がまだ確認できていません。',
    CISA_UNAVAILABLE: 'CISA KEV の最新状態を確認できないため、配布時期を保留します。',
    EMERGENCY_STICKY: '一度緊急適用と判定したため、適用完了まで自動では解除しません。',
    NO_EMERGENCY_EVIDENCE: 'Apple の実悪用記載なし、CISA KEV 一致なし。',
    INFORMATION_INCOMPLETE: '判断に必要な情報が不足しています。'
  };
  let text = map[String(code || '')] || String(code || '');
  // 「設定してください」だけでは何を足すか分からない。対象のメジャーまで書く。
  if (String(code) === 'MANAGED_UNKNOWN' && rec && rec.version) {
    const major = String(rec.version).split('.')[0];
    text += 'macOS管理OS シートの「' + major + '」に TRUE / FALSE を入れてください。';
  }
  return text;
}

/** 次にやること。社内ルールの語彙（定期更新 / 臨時更新）に合わせる。 */
function macosActionText_(d) {
  // 「臨時更新」は社内ルールの用語。即日更新という意味ではない、と同ルールに明記がある。
  if (d === 'EMERGENCY') return '*臨時更新の要否を判断してください。*';
  if (d === 'SEPARATE_PLAN') return '*通常の更新とは分けて、メジャー OS のアップグレードとして計画してください。*';
  if (d === 'NOT_APPLICABLE') return '*現在の管理対象 OS の設定では、対応は発生しません。*';
  return '*いまは配布時期を決めません。情報が更新されてから再判定します。*';
}

function macosExploitLabel_(rec) {
  if (!macosSecurityVerified_(rec)) return '未確認';
  const v = macosNormBool_(rec.appleExploited);
  if (v !== 'TRUE') return v === 'FALSE' ? 'なし' : '未確認';
  const c = String(rec.exploitContext || '');
  if (/Intel-based Mac|Mac systems|macOS/i.test(c)) return 'あり（Mac に関する記載）';
  if (/\biOS\b|iPhone|iPad/i.test(c)) return 'あり（他 Apple OS での記載。該当 CVE は macOS でも修正対象）';
  return 'あり';
}

function macosKevText_(rec, kev) {
  const hits = macosParseCves_(rec.kevList);
  if (hits.length) return '掲載あり：' + hits.join(', ');
  if (kev && !kev.ok) return '照合不可（CISA 未取得）';
  if (!macosSecurityVerified_(rec)) return '未確認';
  if (rec.kevCheckedAt) return '一致なし（' + String(rec.kevCheckedAt).slice(5, 16) + ' 照合）';
  return '未確認';
}

// ============================================================
// 実行履歴・死活
// ============================================================

function macosWriteRunLog_(stats, errorText, startedAt, aiCalls) {
  try {
    const sh = macosSheet_(MACOS_SHEET_RUNLOG);
    const result = errorText ? '失敗' : (stats.failed || stats.notes.length ? '要確認' : '正常');
    const row = sh.getLastRow() + 1;
    sh.getRange(row, 1, 1, MACOS_RUNLOG_HEADERS.length).setValues([[
      new Date(), result, stats.detected, stats.added, stats.changed, stats.emergency,
      stats.notified, stats.failed,
      Math.round((Date.now() - startedAt) / 1000),
      Math.max(0, aiCalls || 0),
      [errorText ? 'エラー: ' + errorText : ''].concat(stats.notes)
        .filter(function (t) { return t; }).join('  /  ')
    ]]);
    sh.getRange(row, 1).setNumberFormat('yyyy/mm/dd hh:mm');
  } catch (e) {
    Logger.log('macOS 実行履歴の記録に失敗: ' + e);
  }
}

/**
 * NW の実行履歴の備考に出す死活。**平常時は空文字を返す。**
 *
 * macOS の Slack は Apple がリリースしない限り数週間鳴らないのが正常なので、
 * 専用シートを作っても誰も開かず、トリガーが消えたことに数週間気づけない。
 * NW は毎日動くので、見る場所を実行履歴 1 か所に寄せる（設計確定書 §2.14）。
 */
function macosHealthNote_() {
  try {
    const last = String(PropertiesService.getScriptProperties().getProperty(MACOS_LAST_RUN_PROP) || '');
    if (!last) return 'macOS監視：未実行（トリガー未設定の可能性）';
    const t = new Date(last.replace(/-/g, '/')).getTime();
    if (isNaN(t)) return '';
    const days = Math.floor((Date.now() - t) / 86400000);
    return days >= 2 ? ('macOS監視：最終実行から ' + days + ' 日（トリガー要確認）') : '';
  } catch (e) { return ''; }
}

// ============================================================
// セットアップ・点検
// ============================================================

/**
 * シートを作る。**日次トリガーはここでは作らない。**
 *
 * トリガーをコードから作ると script.scriptapp スコープが要り、既存 GAS の再認可が発生する。
 * NW も画面から手で張る運用なので合わせる。手順は readme.gs 側に書く。
 */
function macosSetup() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) throw new Error('対象のスプレッドシートを開いて、そのスクリプトから実行してください。');

  const ledger = macosEnsureSheet_(ss, MACOS_SHEET_LEDGER, macosHeaders_());
  if (ledger.getMaxRows() < 200) ledger.insertRowsAfter(ledger.getMaxRows(), 200 - ledger.getMaxRows());
  // 値の型を Sheets に解釈させない。'TRUE' が真偽値に、'15.10' が 15.1 になるのを防ぐ。
  ledger.getRange(2, 1, ledger.getMaxRows() - 1, MACOS_LEDGER_COLS.length).setNumberFormat('@');
  ledger.setColumnWidth(1, 140);
  ledger.setColumnWidth(MACOS_LEDGER_COLS.length, 60);

  const managed = macosEnsureSheet_(ss, MACOS_SHEET_MANAGED, MACOS_MANAGED_HEADERS);
  if (managed.getLastRow() < 2) {
    // **管理対象を自動で TRUE にしない。**空欄は UNKNOWN として判断を保留する。
    managed.getRange(2, 1, 4, 3).setValues([
      ['26', '', '運用前に TRUE / FALSE を入れてください'],
      ['15', '', '運用前に TRUE / FALSE を入れてください'],
      ['14', '', '運用前に TRUE / FALSE を入れてください'],
      ['13', '', '運用前に TRUE / FALSE を入れてください']
    ]);
  }

  macosEnsureSheet_(ss, MACOS_SHEET_RUNLOG, MACOS_RUNLOG_HEADERS);

  const props = PropertiesService.getScriptProperties();
  if (!props.getProperty(MACOS_INITIALIZED_PROP)) props.setProperty(MACOS_INITIALIZED_PROP, 'FALSE');

  Logger.log('macOS 用の 3 シートを用意しました。');
  Logger.log('次にやること: ①「macOS管理OS」に TRUE / FALSE を入れる ' +
             '② macosRunReadinessCheck() を実行して PASS を確認 ' +
             '③ 画面のトリガー設定で ' + MACOS_TRIGGER_FN + ' を毎日 ' + MACOS_DAILY_HOUR + ' 時台に張る');
  return macosRunReadinessCheck();
}

function macosEnsureSheet_(ss, name, headers) {
  let sh = ss.getSheetByName(name);
  if (!sh) sh = ss.insertSheet(name);
  if (sh.getLastRow() === 0) {
    sh.getRange(1, 1, 1, headers.length).setValues([headers]);
    sh.setFrozenRows(1);
    return sh;
  }
  const cur = sh.getRange(1, 1, 1, Math.max(sh.getLastColumn(), 1)).getDisplayValues()[0];
  const same = cur.length === headers.length && headers.every(function (h, i) { return cur[i] === h; });
  if (!same) {
    if (sh.getLastRow() > 1) {
      throw new Error('「' + name + '」の見出しが想定と違います。データが入っているので自動では直しません。手で直してください。');
    }
    if (sh.getLastColumn() > headers.length) sh.deleteColumns(headers.length + 1, sh.getLastColumn() - headers.length);
    sh.getRange(1, 1, 1, headers.length).setValues([headers]);
  }
  sh.setFrozenRows(1);
  return sh;
}

/**
 * 運用開始前の点検。
 *
 * **管理対象 OS が 1 つも TRUE でないと、配布判断が永久にすべて「判断保留」になる。**
 * Slack は毎回届くので「動いている」ように見えてしまう（設計確定書 §2.15）。
 */
function macosCheckReadiness_() {
  const errors = [];
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  const sh = ss ? ss.getSheetByName(MACOS_SHEET_MANAGED) : null;
  if (!sh || sh.getLastRow() < 2) {
    errors.push('「' + MACOS_SHEET_MANAGED + '」が空です。macosSetup() を実行してください。');
  } else {
    const rows = sh.getRange(2, 1, sh.getLastRow() - 1, 2).getValues()
      .filter(function (r) { return String(r[0] || '').trim(); });
    const unset = rows.filter(function (r) {
      return !(r[1] === true || r[1] === false || /^(TRUE|FALSE)$/i.test(String(r[1] || '').trim()));
    });
    if (unset.length) errors.push('管理対象が未設定の系統があります: ' + unset.map(function (r) { return r[0]; }).join(','));
    const anyTrue = rows.some(function (r) { return r[1] === true || /^TRUE$/i.test(String(r[1] || '').trim()); });
    if (!anyTrue) errors.push('管理対象が 1 つも TRUE ではありません。このままだと配布判断が常に「判断保留」になります。');
  }

  const slack = String(PropertiesService.getScriptProperties().getProperty(SLACK_WEBHOOK_PROP) || '');
  if (!/^https:\/\/hooks\.slack\.com\//.test(slack)) errors.push(SLACK_WEBHOOK_PROP + ' が未設定です。');

  return { ok: errors.length === 0, errors: errors };
}

/**
 * 初回取込をやり直す。
 *
 * 1 回目の実行で情報源の一部が取れていなかった場合に使う。
 * このあと macosDaily() を 1 回実行すると、いま公開されているものを取り直して
 * すべて「初期取込」として記録し、**Slack は送らない。**
 * 台帳は消さない（消す必要が無い。同じ版は上書きされる）。
 */
function macosReinitialize() {
  PropertiesService.getScriptProperties().setProperty(MACOS_INITIALIZED_PROP, 'FALSE');
  Logger.log('初回取込をやり直す状態にしました。次に macosDaily() を 1 回実行してください（通知は飛びません）。');
}

function macosRunReadinessCheck() {
  const r = macosCheckReadiness_();
  if (r.ok) Logger.log('macOS 点検: PASS');
  else Logger.log('macOS 点検: 要対応\n - ' + r.errors.join('\n - '));
  return r;
}

// ============================================================
// 汎用
// ============================================================

function macosSheet_(name) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) throw new Error('スプレッドシートを取得できません。');
  const sh = ss.getSheetByName(name);
  if (!sh) throw new Error('「' + name + '」シートがありません。macosSetup() を実行してください。');
  return sh;
}

function macosSpreadsheetUrl_() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    return ss ? ss.getUrl() : '';
  } catch (e) { return ''; }
}

function macosFetchText_(url, label) {
  const res = UrlFetchApp.fetch(url, {
    method: 'get',
    followRedirects: true,
    muteHttpExceptions: true,
    headers: { 'User-Agent': 'macos-release-monitor/1.0' }
  });
  const code = res.getResponseCode();
  if (code < 200 || code >= 300) throw new Error(label + ' HTTP ' + code);
  const text = res.getContentText();
  if (!text) throw new Error(label + ' 応答が空');
  return text;
}

function macosNow_() {
  return Utilities.formatDate(new Date(), MACOS_TZ, 'yyyy-MM-dd HH:mm:ss');
}

/** 真偽値でも文字列でも 'TRUE' / 'FALSE' / 'UNKNOWN' に寄せる。型のずれで比較が外れないように。 */
function macosNormBool_(v) {
  const s = String(v === undefined || v === null ? '' : v).trim().toUpperCase();
  if (s === 'TRUE') return 'TRUE';
  if (s === 'FALSE') return 'FALSE';
  return 'UNKNOWN';
}

function macosUnique_(items) {
  const seen = {};
  return (items || []).filter(function (x) {
    const k = String(x || '').trim();
    if (!k || seen[k]) return false;
    seen[k] = true;
    return true;
  });
}

function macosClip_(s, max) {
  const t = String(s || '');
  return t.length > max ? t.slice(0, max - 1) + '…' : t;
}

function macosParseJson_(v, fallback) {
  if (!v) return fallback;
  try {
    const p = JSON.parse(String(v));
    return p === null ? fallback : p;
  } catch (e) { return fallback; }
}

function macosChildText_(el, name) {
  const direct = el.getChild(name);
  if (direct) return direct.getText().trim();
  const children = el.getChildren();
  for (let i = 0; i < children.length; i++) {
    if (children[i].getName() === name) return children[i].getText().trim();
  }
  return '';
}

function macosStripTags_(html) {
  return String(html || '')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ');
}

function macosDecodeHtml_(t) {
  return String(t || '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

// ============================================================
// 診断
// ============================================================

/**
 * 台帳に書けない・入らないときに実行する。**シートには一切書き込まない。**
 * どこで詰まっているかをログに出すだけ。
 */
function macosDiagnose() {
  const out = [];
  function line(k, v) { out.push('  ' + k + ': ' + v); }

  out.push('=== macOS 診断 ===');
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    line('スプレッドシート', ss ? ss.getName() : '取得できない');
    line('タイムゾーン', ss ? ss.getSpreadsheetTimeZone() : '不明');
  } catch (e) { line('スプレッドシート', 'エラー ' + e.message); }

  const props = PropertiesService.getScriptProperties();
  line('MACOS_INITIALIZED', props.getProperty(MACOS_INITIALIZED_PROP) || '(未設定)');
  line('MACOS_LAST_RUN_AT', props.getProperty(MACOS_LAST_RUN_PROP) || '(未設定)');
  line('SLACK_WEBHOOK_URL', props.getProperty(SLACK_WEBHOOK_PROP) ? '設定あり' : '(未設定)');

  [MACOS_SHEET_LEDGER, MACOS_SHEET_MANAGED, MACOS_SHEET_RUNLOG].forEach(function (name) {
    try {
      const sh = macosSheet_(name);
      line('シート「' + name + '」',
           '最終行 ' + sh.getLastRow() + ' / 最大行 ' + sh.getMaxRows() +
           ' / 最終列 ' + sh.getLastColumn() + ' / 最大列 ' + sh.getMaxColumns());
      if (name === MACOS_SHEET_LEDGER) {
        const led = macosLoadLedger_();
        line('  台帳の中身', '有効 ' + led.recs.length + ' 版 / 空行 ' + led.blank + ' / 重複 ' + led.dup);
        if (led.dup || led.blank) line('  → 要整理', 'macosDaily() を 1 回実行すると自動で畳まれます');
        const need = 82;
        if (sh.getMaxRows() < need) {
          line('  → 問題', '行数が ' + sh.getMaxRows() + ' しかない。81 行を書くには ' + need + ' 行必要。これが原因');
        }
        if (sh.getMaxColumns() < MACOS_LEDGER_COLS.length) {
          line('  → 問題', '列数が ' + sh.getMaxColumns() + ' しかない。' + MACOS_LEDGER_COLS.length + ' 列必要');
        }
      }
    } catch (e) { line('シート「' + name + '」', 'エラー ' + e.message); }
  });

  try {
    const src = macosSafeSource_('Security Index', macosFetchSecurityIndex_);
    line('Security Index', src.ok ? (src.data.length + ' 件') : src.error);
    if (src.ok) {
      const rel = macosCollectReleases_(src.data);
      const recent = rel.filter(function (r) {
        const a = macosDaysSince_(r.postingDate);
        return a === null || a <= MACOS_HISTORY_DAYS;
      });
      line('版で畳んだ後', rel.length + ' 件（うち ' + MACOS_HISTORY_DAYS + ' 日以内 ' + recent.length + ' 件）');
    }
  } catch (e) { line('情報源', 'エラー ' + e.message); }

  // 追跡対象の行を並べる。通知が来ないときは、まずここに行が出ているかを見る。
  try {
    const led = macosLoadLedger_();
    const active = led.recs.filter(function (r) { return String(r.tracking).trim() !== MACOS_TRACK_BACKFILL; });
    out.push('  追跡対象の行: ' + active.length + ' 件（初期取込を除く）');
    if (!active.length) {
      out.push('    → 0 件なので通知は出ません。通知を試すには台帳の I 列を「追跡中」、T 列を「PENDING」にします');
    }
    active.slice(0, 10).forEach(function (r) {
      out.push('    macOS ' + r.version +
               ' | 追跡=' + JSON.stringify(String(r.tracking)) +
               ' | 通知=' + JSON.stringify(String(r.noticeState)) +
               ' | 管理=' + JSON.stringify(String(r.managedOs)) +
               ' | 判断=' + String(r.decision || '') +
               ' | Security=' + String(r.securityStatus || ''));
      if (String(r.lastError || '')) out.push('      最終エラー: ' + String(r.lastError));
      if (String(r.tracking).trim() !== MACOS_TRACK_ACTIVE && String(r.tracking).trim() !== MACOS_TRACK_DONE) {
        out.push('      → 追跡状態の値が想定と違います。ちょうど「' + MACOS_TRACK_ACTIVE + '」と入れてください');
      }
      if (String(r.tracking).trim() === MACOS_TRACK_ACTIVE && !macosNeedsNotice_(String(r.noticeState).trim())) {
        out.push('      → 通知状態が ' + JSON.stringify(String(r.noticeState)) +
                 ' なので送信対象外です。送るには「PENDING」にします');
      }
    });
  } catch (e) { line('追跡対象の行', 'エラー ' + e.message); }

  try {
    const rd = macosCheckReadiness_();
    line('点検', rd.ok ? 'PASS' : rd.errors.join(' / '));
  } catch (e) { line('点検', 'エラー ' + e.message); }

  Logger.log(out.join('\n'));
  return out.join('\n');
}

/**
 * **いま台帳にある最新の正式版で、本番と同じ配布判断の通知を 1 通送る。**
 *
 * Apple の次のリリースを待たずに、判定・KEV 照合・AI 要約・Slack の形まで通しで確かめるための関数。
 * 台帳を手で書き換える必要はない。
 *
 * 送信後、追跡状態と通知状態は**元に戻す**（テストの痕跡を残さないため）。
 * Apple から取り直した CVE・実悪用・配布判断はそのまま台帳に残す。情報が増えるだけなので。
 */
function macosNotifyLatest() {
  macosRunStartedAt_ = Date.now();
  macosAiDownThisRun_ = false;

  const led = macosLoadLedger_();
  if (!led.recs.length) throw new Error('台帳が空です。先に macosDaily() を実行してください。');

  // 管理対象の系統を優先する。そのほうが本番に近い通知になる。
  const managed = led.recs.filter(function (r) { return macosNormBool_(r.managedOs) === 'TRUE'; });
  const pool = managed.length ? managed : led.recs;
  pool.sort(function (a, b) { return String(b.postingDate).localeCompare(String(a.postingDate)); });
  const rec = pool[0];

  if (!managed.length) {
    Logger.log('注意: 管理対象が TRUE の行がありません。「⚫ 対象外」の通知になります。');
    Logger.log('本番に近い形で見たい場合は「macOS管理OS」シートで該当のメジャーを TRUE にしてください。');
  }
  Logger.log('対象: macOS ' + rec.version + '（公開日 ' + rec.postingDate + '）');

  const prev = { tracking: rec.tracking, noticeState: rec.noticeState, noticedAt: rec.noticedAt };
  rec.tracking = MACOS_TRACK_ACTIVE;
  rec.noticeState = MACOS_N_PENDING;
  rec.noticedAt = '';

  const kev = kevCatalogWithStatus_();
  if (!kev.ok) Logger.log('注意: CISA KEV を取得できません（' + kev.error + '）。判定は保留側に倒れます。');

  macosUpdateSecurity_(rec);
  if (String(rec.lastError || '')) Logger.log('Apple 詳細の取得: ' + rec.lastError);
  Logger.log('Security 状態: ' + rec.securityStatus + ' / 公開CVE ' + macosParseCves_(rec.cveList).length + ' 件');

  if (kev.ok && macosShouldCheckKev_(rec)) {
    rec.kevList = macosMatchKev_(rec.cveList, kev.map).join(',');
    rec.kevCheckedAt = macosNow_();
  }

  const ev = macosEvaluateDecision_(rec, kev.ok);
  rec.reasonCode = ev.reason;
  if (String(rec.decision || '') !== ev.decision) rec.prevDecision = String(rec.decision || '');
  rec.decision = ev.decision;
  Logger.log('配布判断: ' + macosShortVerdict_(ev.decision) + '（' + ev.reason + '）');

  let sent = false;
  try {
    macosSendDecisionNotice_(rec, kev);
    sent = true;
    Logger.log('OK: Slack へ送信しました。チャンネルを確認してください。');
  } catch (e) {
    Logger.log('NG: Slack 送信に失敗しました: ' + (e && e.message ? e.message : e));
    Logger.log('※ 404 は Webhook の失効、403 はチャンネル権限、400 は本文の形式です。');
  }

  rec.tracking = prev.tracking;
  rec.noticeState = prev.noticeState;
  rec.noticedAt = prev.noticedAt;
  macosSaveLedger_(led);
  Logger.log('追跡状態は「' + prev.tracking + '」に戻しました。日次の動きには影響しません。');
  return sent;
}

// ============================================================
// 自己確認
// ============================================================

/**
 * **GAS へ貼ったら、まずこれを実行する。**
 *
 * ローカルの node で 2 ファイルを連結して検証しても、Apps Script のファイル分離は
 * 再現できない（README §5）。ここで見たいのは主に次の 2 つ。
 *   1. v7.gs 側の関数と var がこのファイルから見えているか
 *   2. 判定の順序と AI 出力の検証が、貼った実物で動くか
 *
 * ネットワークにもシートにも触らない。実行しても Slack は飛ばない。
 */
function macosSelfTest() {
  const results = [];
  function check(name, fn) {
    try {
      const r = fn();
      results.push((r === true ? 'PASS  ' : 'FAIL  ') + name + (r === true ? '' : '  → ' + r));
    } catch (e) {
      results.push('FAIL  ' + name + '  → ' + (e && e.message ? e.message : e));
    }
  }

  // --- ファイルをまたいだ参照（ここが落ちるなら本体を貼り忘れている） ---
  check('v7 の postSlack_ が見える', function () { return typeof postSlack_ === 'function' || 'postSlack_ が未定義'; });
  check('v7 の kevCatalogWithStatus_ が見える', function () { return typeof kevCatalogWithStatus_ === 'function' || 'kevCatalogWithStatus_ が未定義。v7 を貼り替えていない可能性'; });
  check('v7 の callGemini_ が見える', function () { return typeof callGemini_ === 'function' || 'callGemini_ が未定義'; });
  check('v7 の sharedAiCountToday_ が見える', function () { return typeof sharedAiCountToday_ === 'function' || 'sharedAiCountToday_ が未定義。v7 を貼り替えていない可能性'; });
  check('v7 の SLACK_WEBHOOK_PROP が見える', function () { return typeof SLACK_WEBHOOK_PROP === 'string' || 'SLACK_WEBHOOK_PROP が見えない（v7 側で var 宣言か確認）'; });

  // --- 配布判定の順序 ---
  function d(rec, kev) { return macosEvaluateDecision_(rec, kev === undefined ? true : kev); }
  check('① 新メジャーOS → SEPARATE_PLAN', function () { return d({ version: '27.0', managedOs: 'TRUE' }).decision === 'SEPARATE_PLAN' || 'NG'; });
  check('② 管理対象外 → NOT_APPLICABLE', function () { return d({ version: '26.6.2', managedOs: 'FALSE' }).decision === 'NOT_APPLICABLE' || 'NG'; });
  check('③ 管理未設定 → PENDING', function () { return d({ version: '26.6.2', managedOs: '' }).reason === 'MANAGED_UNKNOWN' || 'NG'; });
  check('④ EMERGENCY は自動で下げない', function () { return d({ version: '26.6.2', managedOs: 'TRUE', decision: 'EMERGENCY', securityStatus: 'FOUND' }).reason === 'EMERGENCY_STICKY' || 'NG'; });
  check('⑤ Apple実悪用 → EMERGENCY', function () { return d({ version: '26.6.2', managedOs: 'TRUE', appleExploited: 'TRUE', securityStatus: 'FOUND' }).reason === 'APPLE_EXPLOITED' || 'NG'; });
  check('⑥ KEV一致 → EMERGENCY', function () { return d({ version: '26.6.2', managedOs: 'TRUE', securityStatus: 'FOUND', kevList: 'CVE-2026-1234' }).reason === 'CISA_KEV' || 'NG'; });
  check('⑦ Security未確認 → PENDING', function () { return d({ version: '26.6.2', managedOs: 'TRUE', securityStatus: 'PENDING_DETAIL' }).reason === 'SECURITY_PENDING' || 'NG'; });
  check('⑨ CISA不通なら緑にしない', function () { return d({ version: '26.6.2', managedOs: 'TRUE', securityStatus: 'FOUND', cveList: 'CVE-2026-1234' }, false).reason === 'CISA_UNAVAILABLE' || 'NG'; });
  check('⑩ 緊急根拠なし → NEXT_CYCLE', function () { return d({ version: '26.6.2', managedOs: 'TRUE', securityStatus: 'FOUND', cveList: 'CVE-2026-1234' }).decision === 'NEXT_CYCLE' || 'NG'; });

  // --- シートの型ぶれに耐えるか（'TRUE' が真偽値になっても比較が成立するか） ---
  check('真偽値でも管理対象を判定できる', function () {
    return (macosNormBool_(false) === 'FALSE' && macosNormBool_(true) === 'TRUE' && macosNormBool_('') === 'UNKNOWN') || 'NG';
  });

  // --- 列マップの往復（見出しを日本語にしても壊れないこと） ---
  check('台帳の列が往復で保たれる', function () {
    const rec = {};
    MACOS_LEDGER_COLS.forEach(function (c, i) { rec[c.key] = 'v' + i; });
    const back = macosRowToRec_(macosRecToRow_(rec));
    const bad = MACOS_LEDGER_COLS.filter(function (c) { return back[c.key] !== rec[c.key]; });
    return bad.length === 0 || ('欠落: ' + bad.map(function (c) { return c.key; }).join(','));
  });
  check('見出しと列数', function () {
    return (macosHeaders_().length === MACOS_LEDGER_COLS.length && macosHeaders_()[0] === 'バージョン') || 'NG';
  });

  // --- Slack が長すぎて 400 にならないか ---
  check('CVE が多くても Slack の 3,000 字上限に収まる', function () {
    const many = [];
    for (let i = 0; i < 90; i++) many.push('CVE-2026-' + (10000 + i));
    const rec = { version: '26.6.2', build: '25G83', postingDate: '2026-08-17', managedOs: 'TRUE',
                  securityStatus: 'FOUND', cveList: many.join(','), appleExploited: 'FALSE',
                  securityUrl: 'https://support.apple.com/en-us/1', decision: 'NEXT_CYCLE',
                  reasonCode: 'NO_EMERGENCY_EVIDENCE' };
    const p = macosBuildDecisionPayload_(rec, 'NEXT_CYCLE', true, { ok: false }, { ok: true });
    const over = (p.blocks || []).filter(function (b) { return b.text && String(b.text.text).length >= 3000; });
    return over.length === 0 || (over.length + ' ブロックが上限超過');
  });

  // --- AI の捏造を拒否するか ---
  const facts = [{ id: 'F1', component: 'Kernel', impact: 'x', description: 'y', cves: ['CVE-2026-1234'] }];
  function rejects(out) {
    try { macosValidateAiOutput_(out, facts); return false; } catch (e) { return true; }
  }
  check('正常な AI 出力は通る', function () { return !rejects({ summary: { text: '権限制御の問題が修正されています。', source_ids: ['F1'] }, notable_changes: [] }) || 'NG'; });
  check('存在しない根拠IDを拒否', function () { return rejects({ summary: { text: 'a', source_ids: ['F99'] }, notable_changes: [] }) || 'NG'; });
  check('URL 捏造を拒否', function () { return rejects({ summary: { text: '詳細は https://example.com', source_ids: ['F1'] }, notable_changes: [] }) || 'NG'; });
  check('CVE 捏造を拒否', function () { return rejects({ summary: { text: 'CVE-2026-9999 を修正', source_ids: ['F1'] }, notable_changes: [] }) || 'NG'; });
  check('配布判断の表現を拒否', function () { return rejects({ summary: { text: '緊急適用が必要です', source_ids: ['F1'] }, notable_changes: [] }) || 'NG'; });

  const failed = results.filter(function (r) { return r.indexOf('FAIL') === 0; });
  Logger.log(results.join('\n'));
  Logger.log('\n==== macOS 自己確認: ' + (failed.length ? '要対応 ' + failed.length + ' 件 / 全 ' + results.length + ' 件' : 'PASS（全 ' + results.length + ' 件）') + ' ====');
  if (failed.length) Logger.log('※ 「v7 の ... が見える」が落ちている場合は、v7.gs の貼り替えが済んでいません。');
  return { ok: failed.length === 0, results: results };
}
