/**
 * NW機器 脆弱性ウォッチャー for Google Apps Script  (v7 / マルチベンダー MVP)
 * ==================================================================
 * v6 からの変更点（詳細は 設計書_MVP_8h.md）:
 *
 *   1. 資産シートを拡張（ベンダー・種別・機種・ツール対象）。
 *   2. 台帳 12 列（自社影響→製品→CVE→…→アドバイザリ）。固定5列。
 *   3. Cisco PSIRT RSS → CSAF 版比較（資産シートの IOS-XE / 17.15.5 等で決め打ち判定）。
 *   4. main() = runFortinet_() + runCisco_()。Slack は対応推奨+要調査のみ。
 *   5. 自社影響3値（対応推奨/次回定期/要調査）、KEV連携、Fortinetコード判定表。
 *
 * 移行: migrateLedgerHeaders() → clearRunData() → main()
 *
 * ------------------------------------------------------------------
 * v5 からの変更点（v6、すべて実データ50件の検証にもとづく。詳細は設計書v3）:
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

/** Gemini API のモデル ID。3.7 Flash は AI Studio 無料枠対象（2026-08 時点） */
const GEMINI_MODEL = 'gemini-3.7-flash';
const CLAUDE_MODEL = 'claude-sonnet-5';

const RSS_URL = 'https://filestore.fortinet.com/fortiguard/rss/ir.xml';
const CISCO_RSS_URL = 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml';
const CSAF_BASE = 'https://filestore.fortinet.com/fortiguard/psirt/csaf_';

const VENDOR_FORTINET = 'Fortinet';
const VENDOR_CISCO = 'Cisco';

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

/**
 * 1回の main() 内で処理するアドバイザリのチャンクサイズ。
 * 日次運用では通常 数件。6 分制限への保険として残す。
 */
const MAX_ADVISORIES_PER_RUN = 50;

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
 * 自社影響の3値。ベースラインは年1回の定期FW更新。
 * ツールの役割は「次回定期を待てない例外」の検出。
 */
const V_URGENT = '対応推奨';
const V_ROUTINE = '次回定期';
const V_UNKNOWN = '要調査';

/** @deprecated 互換用エイリアス（内部参照の移行中） */
const V_TARGET = V_URGENT;
const V_OUT = V_ROUTINE;

/** SSL-VPN を外面から除外する（無効化済みの場合は false） */
const SSL_VPN_ENABLED = false;

const KEV_FEED_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** Fortinet AI が選ぶ影響機能（外面判定の統制語彙） */
const FORTINET_AI_FEATURES = [
  'IPsec VPN', 'SSL-VPN', '管理GUI', 'SSH',
  'アンチウイルスエンジン', 'IPSエンジン', 'Webフィルタ', 'SSLインスペクション',
  'データプレーン', 'その他', '不明'
];

/** CISA KEV 掲載の有無（台帳表示用） */
const KEV_YES = 'あり';
const KEV_NO = 'なし';

/**
 * 台帳 12 列。
 *
 * A 固定5列: 自社影響 → 製品 → CVE → CVSS → 最終更新日
 * B 判定表示: 公式推奨対応 → KEV → 影響機能 → 判定根拠
 * C 人の確認: 確認方法 → ユーザ影響（AI）
 * D 参照: アドバイザリ
 *
 * OS該当は列に出さず、判定根拠の「OS=…」に含める。
 * 外面・掌握・停止は判定の内部入力のみ。
 */
const LEDGER_HEADERS = [
  '自社影響',     // 1  対応推奨 / 次回定期 / 要調査
  '製品',         // 2
  'CVE',          // 3
  'CVSS',         // 4
  '最終更新日',   // 5
  '公式推奨対応', // 6  ベンダー公式（日本語）
  'KEV',          // 7  あり / なし
  '影響機能',     // 8
  '判定根拠',     // 9  OS=… | KEV=… | ◯◯のため「結論」
  '確認方法',     // 10 確認ポイント／コマンド／判断
  'ユーザ影響',   // 11 最悪ケース50字以内
  'アドバイザリ'  // 12
];

/**
 * 機能別の確認手順（行動可能）。AI 出力が不合格のときこれで差し替える。
 * 書式: 確認ポイント / コマンド / 判断 の3行。
 */
const CHECK_STEPS_FORTINET = {
  '管理GUI': [
    '確認ポイント：管理用インターフェースで HTTP/HTTPS 管理が許可されているか',
    'コマンド：show system interface',
    '判断：allowaccess に http または https があれば対応が必要。無ければ次回定期で可'
  ].join('\n'),
  'SSH': [
    '確認ポイント：SSH 管理アクセスと管理者 trusthost の制限有無',
    'コマンド：show system interface\nshow system admin',
    '判断：allowaccess に ssh があり trusthost が未設定なら対応が必要。SSH無効なら次回定期で可'
  ].join('\n'),
  'SSL-VPN': [
    '確認ポイント：SSL-VPN が有効か',
    'コマンド：show vpn ssl settings',
    '判断：status が enable なら対応が必要。disable なら次回定期で可'
  ].join('\n'),
  'IPsec VPN': [
    '確認ポイント：IPsec phase1 が設定されているか',
    'コマンド：show vpn ipsec phase1-interface',
    '判断：phase1 が1件以上あれば対応が必要。無ければ次回定期で可'
  ].join('\n'),
  'Webフィルタ': [
    '確認ポイント：Webフィルタプロファイルがポリシーに紐づいているか',
    'コマンド：show webfilter profile\nshow firewall policy',
    '判断：プロファイルが有効なポリシーがあれば対応が必要。未使用なら次回定期で可'
  ].join('\n'),
  'SSLインスペクション': [
    '確認ポイント：SSL/SSH 検査プロファイルが使われているか',
    'コマンド：show firewall ssl-ssh-profile',
    '判断：検査が有効なプロファイルがあれば対応が必要。未使用なら次回定期で可'
  ].join('\n'),
  'IPSエンジン': [
    '確認ポイント：IPS センサがポリシーに適用されているか',
    'コマンド：show ips sensor',
    '判断：センサが有効なら対応が必要。未使用なら次回定期で可'
  ].join('\n'),
  'アンチウイルスエンジン': [
    '確認ポイント：アンチウイルスプロファイルが使われているか',
    'コマンド：show antivirus profile',
    '判断：プロファイルが有効なら対応が必要。未使用なら次回定期で可'
  ].join('\n'),
  'データプレーン': [
    '確認ポイント：版が影響範囲内か（機能設定に依存しない）',
    'コマンド：get system status',
    '判断：自社版が影響範囲内なら定期更新で対応。範囲外なら対応不要'
  ].join('\n'),
  'その他': [
    '確認ポイント：版が影響範囲内か（機能設定に依存しない）',
    'コマンド：get system status',
    '判断：自社版が影響範囲内なら定期更新で対応。範囲外なら対応不要'
  ].join('\n'),
  '不明': [
    '確認ポイント：版が影響範囲内か（機能設定に依存しない）',
    'コマンド：get system status',
    '判断：自社版が影響範囲内なら定期更新で対応。範囲外なら対応不要'
  ].join('\n')
};

const CHECK_STEPS_CISCO = [
  {
    re: /http|webui|web-based|web based|management/i,
    text: [
      '確認ポイント：HTTP/HTTPS 管理サーバが有効か',
      'コマンド：show running-config | include ip http server|ip http secure-server',
      '判断：ip http server / secure-server が出れば対応が必要。無ければ次回定期で可'
    ].join('\n')
  },
  {
    re: /beep/i,
    text: [
      '確認ポイント：BEEP リスナーが有効か',
      'コマンド：show running-config | include beep',
      '判断：beep 設定が出れば対応が必要。無ければ次回定期で可'
    ].join('\n')
  },
  {
    re: /xmcp/i,
    text: [
      '確認ポイント：XMCP Server が有効か',
      'コマンド：show running-config | include service-routing xmcp',
      '判断：xmcp listen が出れば対応が必要。無ければ次回定期で可'
    ].join('\n')
  },
  {
    re: /snmp/i,
    text: [
      '確認ポイント：SNMP サーバが有効か',
      'コマンド：show running-config | include snmp-server',
      '判断：snmp-server 設定が出れば対応が必要。無ければ次回定期で可'
    ].join('\n')
  },
  {
    re: /\bssh\b|vty/i,
    text: [
      '確認ポイント：SSH / VTY アクセスが有効か',
      'コマンド：show running-config | include ip ssh|line vty',
      '判断：SSH または VTY が有効なら対応が必要。無効なら次回定期で可'
    ].join('\n')
  },
  {
    re: /sd-?wan/i,
    text: [
      '確認ポイント：SD-WAN 機能が設定されているか',
      'コマンド：show running-config | include sdwan|sd-wan',
      '判断：SD-WAN 設定が出れば対応が必要。無ければ次回定期で可'
    ].join('\n')
  }
];

const CHECK_STEPS_CISCO_DEFAULT = [
  '確認ポイント：稼働バージョンが影響範囲内か',
  'コマンド：show version',
  '判断：自社版が影響範囲内なら定期更新で対応。範囲外なら対応不要'
].join('\n');

/** 資産シート v7。「製品」はベンダー公式表記（FortiOS / IOS-XE）。ツール対象=いいえ は台帳に出さない */
const ASSET_HEADERS = ['ベンダー', '種別', '製品', '機種', 'バージョン', '台数', 'ツール対象', '備考'];

const DEFAULT_ASSET_ROWS = [
  [VENDOR_FORTINET, 'UTM', 'FortiOS', 'FortiGate 120G', '7.4.11', 1, 'はい', ''],
  [VENDOR_CISCO, 'Switch', 'IOS-XE', 'C9200-24PXG-E', '17.15.5', 1, 'はい', ''],
  [VENDOR_CISCO, 'Switch', 'IOS-XE', 'C9200L-24PXG-4X', '17.15.5', 1, 'はい', ''],
  [VENDOR_CISCO, 'WLC', 'IOS-XE', 'Catalyst 9800-L', '17.15.5', 1, 'はい', '版は実機確認推奨'],
  [VENDOR_CISCO, 'AP', '—', 'CW9166I-Q', '', 1, 'はい', 'WLC管理下'],
  [VENDOR_FORTINET, '—', '—', 'FortiClient EMS', '', 1, 'いいえ', 'クライアント・対象外'],
  ['Netgear', 'Switch', '—', 'MS510TXM', '', 1, 'いいえ', '別ベンダー'],
  ['Netgear', 'Switch', '—', 'GS108Tv3', '', 1, 'いいえ', '別ベンダー'],
  ['Soliton', 'RADIUS', '—', 'NetAttest EPS-edge SX06', '', 1, 'いいえ', '別ベンダー']
];

/** 処理済みシート。分母（今月の公表件数）はここから数える。 */
const STATE_HEADERS = ['ベンダー', '最終更新日', '初回公表日', 'アドバイザリID', 'タイトル', '台帳の行数', '対象製品', 'CSAF版'];

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

function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu('脆弱性ウォッチャー')
    .addItem('データ削除（台帳・処理済み）', 'clearRunData')
    .addToUi();
}

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
    DEFAULT_ASSET_ROWS.forEach(function (r) { asset.appendRow(r); });
    asset.setFrozenRows(1);
    Logger.log('「資産」シートを作成しました。');
  } else {
    Logger.log('「資産」シートは既にあります。migrateAssetHeaders() で列を更新できます。');
  }

  let state = ss.getSheetByName(SHEET_STATE);
  if (!state) {
    state = ss.insertSheet(SHEET_STATE);
    state.appendRow(STATE_HEADERS);
    state.setFrozenRows(1);
    state.setColumnWidth(1, 80);
    state.setColumnWidth(2, 100);
    state.setColumnWidth(3, 100);
    state.setColumnWidth(4, 180);
    state.setColumnWidth(5, 400);
    state.setColumnWidth(6, 90);
    state.setColumnWidth(7, 280);
    state.setColumnWidth(8, 70);
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
  Logger.log('  → clearRunData() で削除できます（確認ダイアログあり）。');
}

/**
 * 「台帳」と「処理済み」の 2 行目以降を削除する（見出し行は残す）。
 * main() の再取得前や列構成変更後に使う。資産シートは触らない。
 * 誤実行防止のため確認ダイアログを出す。
 */
function clearRunData() {
  let ui;
  try {
    ui = SpreadsheetApp.getUi();
  } catch (e) {
    throw new Error('clearRunData() はスプレッドシートを開いた状態で、メニュー「脆弱性ウォッチャー → データ削除」から実行してください。');
  }
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  const ledger = ss.getSheetByName(SHEET_LEDGER);
  const state = ss.getSheetByName(SHEET_STATE);
  if (!ledger && !state) {
    ui.alert('削除対象なし', '「台帳」「処理済み」シートが見つかりません。setup() を先に実行してください。', ui.ButtonSet.OK);
    return;
  }

  const ledgerRows = ledger && ledger.getLastRow() > 1 ? ledger.getLastRow() - 1 : 0;
  const stateRows = state && state.getLastRow() > 1 ? state.getLastRow() - 1 : 0;
  if (!ledgerRows && !stateRows) {
    ui.alert('削除対象なし', '「台帳」「処理済み」に削除するデータ行がありません。', ui.ButtonSet.OK);
    Logger.log('clearRunData: 削除対象のデータ行なし');
    return;
  }

  const lines = [];
  if (ledgerRows) lines.push('・台帳: ' + ledgerRows + ' 行');
  if (stateRows) lines.push('・処理済み: ' + stateRows + ' 行');
  const answer = ui.alert(
    'データ削除の確認',
    '次のデータ行をすべて削除します（見出しの 1 行目は残します）。\n\n' +
    lines.join('\n') +
    '\n\n資産シートは削除しません。\nこの操作は元に戻せません。削除しますか？',
    ui.ButtonSet.YES_NO
  );
  if (answer !== ui.Button.YES) {
    ui.alert('キャンセルしました。データは削除していません。');
    Logger.log('clearRunData: ユーザーがキャンセル');
    return;
  }

  const removedLedger = deleteSheetDataRows_(SHEET_LEDGER);
  const removedState = deleteSheetDataRows_(SHEET_STATE);
  const summary = [];
  if (removedLedger) summary.push('台帳 ' + removedLedger + ' 行');
  if (removedState) summary.push('処理済み ' + removedState + ' 行');
  const msg = summary.length ? summary.join(' / ') + ' を削除しました。' : '削除する行はありませんでした。';
  ui.alert('削除完了', msg + '\n\nmain() を実行して再取得できます。', ui.ButtonSet.OK);
  Logger.log('clearRunData: ' + msg);
}

/** 指定シートの 2 行目以降を削除する。削除した行数を返す。 */
function deleteSheetDataRows_(sheetName) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(sheetName);
  if (!sh || sh.getLastRow() < 2) return 0;
  const count = sh.getLastRow() - 1;
  sh.deleteRows(2, count);
  return count;
}

/** 資産シートを v7 列構成に更新する（既存データは消える）。 */
function migrateAssetHeaders() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(SHEET_ASSET);
  if (!sh) {
    setup();
    return;
  }
  if (sh.getLastRow() > 1) sh.deleteRows(2, sh.getLastRow() - 1);
  sh.getRange(1, 1, 1, ASSET_HEADERS.length).setValues([ASSET_HEADERS]);
  DEFAULT_ASSET_ROWS.forEach(function (r) { sh.appendRow(r); });
  sh.setFrozenRows(1);
  Logger.log('資産シートを v7 構成（' + ASSET_HEADERS.length + ' 列）に更新しました。');
}

function createDailyTrigger() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (t.getHandlerFunction() === 'main') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('main').timeBased().atHour(9).everyDays(1).create();
  Logger.log('毎日 9 時台に main() を実行するトリガーを作成しました。');
}

function main() {
  const fortinetRows = runFortinet_();
  const ciscoRows = runCisco_();
  const notifyRows = fortinetRows.concat(ciscoRows);
  if (notifyRows.length) notifySlack_(notifyRows);
  else backfillAiColumns_();
  Logger.log('main() 完了（Fortinet 台帳 ' + fortinetRows.length + ' 行 / Cisco 台帳 ' + ciscoRows.length + ' 行）');
}

function runFortinet_() {
  const assets = fortinetAssets_(readAssets_());
  if (!assets.length) {
    Logger.log('警告: Fortinet 対象の資産がありません。');
  }

  const allItems = fetchRssItems_();
  const known0 = getKnownState_(VENDOR_FORTINET);
  warnIfFeedOverflowed_(allItems, known0.dates, function (it) { return it.ir; });

  const candidates = selectRssCsafCandidates_(allItems, known0, function (it) { return it.ir; },
    function (it) { return it.pubDate; });
  Logger.log('Fortinet RSS: 全 ' + allItems.length + ' 件 → CSAF 候補 ' + candidates.length + ' 件');

  const fetched = fetchAllCsaf_(candidates);

  let allLedgerRows = [];
  let batchNum = 0;

  // 未処理がなくなるまで同一実行内で繰り返す（日次1回で全件処理）
  while (true) {
    const known = getKnownState_(VENDOR_FORTINET);
    const pending = fetched.filter(function (f) {
      return needsAdvisoryProcessing_(f.item.ir, f.updatedAt, f.version, known);
    });

    if (!pending.length) {
      if (!batchNum) Logger.log('Fortinet: 新着・改訂ともになし。');
      break;
    }

    const todo = pending.slice(0, MAX_ADVISORIES_PER_RUN);
    batchNum++;
    if (pending.length > todo.length) {
      Logger.log('Fortinet: 未処理 ' + pending.length + ' 件 → このバッチ ' + todo.length +
                 ' 件（残りは同一実行内で続行）');
    } else {
      Logger.log('Fortinet: 処理対象 ' + todo.length + ' 件');
    }

    const revised = todo.filter(function (f) { return known.dates[f.item.ir]; });
    if (revised.length) {
      Logger.log('改訂を検知: ' + revised.map(function (f) {
        return f.item.ir + '（' + known.dates[f.item.ir] + ' → ' + ymd_(f.updatedAt) + '）';
      }).join(', '));
      removeRowsFor_(VENDOR_FORTINET, revised.map(function (f) { return f.item.ir; }));
    }

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

    rows.forEach(function (r) { decideNotification_(r, assets); });

    const counts = countVerdicts_(rows);
    Logger.log('全 ' + rows.length + ' 行: 対応推奨 ' + counts[V_URGENT] +
               ' / 要調査 ' + counts[V_UNKNOWN] + ' / 次回定期 ' + counts[V_ROUTINE]);
    if (batchNum === 1) logUnownedProducts_(rows);

    writeState_(VENDOR_FORTINET, todo, rows);

    const ledgerRows = rows.filter(function (r) { return isLedgerRow_(r, assets); });
    Logger.log('Fortinet 台帳: ' + ledgerRows.length + ' / ' + rows.length + ' 行');

    const needAi = ledgerRows.filter(function (r) {
      return r.needsFortinetAi || r.needsDisplayAi;
    });
    if (needAi.length) {
      try {
        enrichWithAI_(needAi);
      } catch (e) {
        Logger.log('AI 生成に失敗しました。フォールバックで表示列を埋めます: ' + e);
      }
      needAi.forEach(function (r) {
        applyFallbackDisplayFields_(r);
        if (r.needsFortinetAi && !r._lockedVerdict) finalizeFortinetVerdict_(r);
        else if (r.feature && r.feature !== '—') r.reason = buildDecisionReason_(r);
        // finalize で機能が変わった場合に確認方法を合わせ直す
        r.howToCheck = normalizeHowToCheck_(r);
        r.impactJa = truncateJa_(r.impactJa || fallbackImpactJa_(r), 50);
      });
    }

    writeLedger_(ledgerRows);
    allLedgerRows = allLedgerRows.concat(ledgerRows);

    if (todo.length >= pending.length) break;
  }

  if (allLedgerRows.length) sortLedger_();
  return allLedgerRows;
}

/**
 * 台帳に載せる行かどうか。
 *
 * 載せるのは、自社が保有している製品で OS 該当が「対象」または「不明」の行。
 * 製品不明・非保有・OS対象外は台帳に出さない（処理済みシートには残る）。
 */
function isLedgerRow_(row, assets) {
  if (!row.product) return false;
  if (!assetsForProduct_(assets, row.product).length) return false;
  if (row.osStatus === '対象外') return false;
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
// 0b. Cisco PSIRT RSS → CSAF 版比較
// ============================================================

const CISCO_CSAF_BASE = 'https://tools.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/';

function runCisco_() {
  const assets = ciscoAssets_(readAssets_());
  if (!assets.length) {
    Logger.log('Cisco: ツール対象の資産がありません。スキップします。');
    return [];
  }

  const allItems = fetchCiscoRssItems_();
  const known0 = getKnownState_(VENDOR_CISCO);
  warnIfFeedOverflowed_(allItems, known0.dates, function (it) { return it.id; });

  const candidates = selectRssCsafCandidates_(allItems, known0, function (it) { return it.id; },
    function (it) { return it.pubDate; });
  Logger.log('Cisco RSS: 全 ' + allItems.length + ' 件 → CSAF 候補 ' + candidates.length +
             ' 件（資産シートの製品で判定）');

  const fetched = fetchCiscoCsafBatch_(candidates);

  let allLedgerRows = [];
  let batchNum = 0;

  while (true) {
    const known = getKnownState_(VENDOR_CISCO);
    const pending = fetched.filter(function (f) {
      return needsAdvisoryProcessing_(f.item.id, f.updatedAt, f.version, known);
    });

    if (!pending.length) {
      if (!batchNum) Logger.log('Cisco: 新着・改訂ともになし。');
      break;
    }

    const todo = pending.slice(0, MAX_ADVISORIES_PER_RUN);
    batchNum++;
    Logger.log('Cisco 処理対象 ' + todo.length + ' 件' +
               (pending.length > todo.length ? '（未処理 ' + pending.length + ' 件・続きあり）' : ''));

    const revised = todo.filter(function (f) { return known.dates[f.item.id]; });
    if (revised.length) {
      removeRowsFor_(VENDOR_CISCO, revised.map(function (f) { return f.item.id; }));
    }

    let rows = [];
    todo.forEach(function (f) {
      if (f.error) {
        Logger.log('Cisco CSAF 取得失敗: ' + f.item.id + ' / ' + f.error);
        rows.push(extractCiscoRowFallback_(f.item));
        return;
      }
      const extracted = extractCiscoRowsFromCsaf_(f.csaf, f.item, assets);
      if (!extracted.length) {
        Logger.log('Cisco 資産対象外: ' + f.item.id);
      }
      rows = rows.concat(extracted);
    });

    rows.forEach(function (r) { decideNotification_(r, assets); });

    const counts = countVerdicts_(rows);
    Logger.log('Cisco 全 ' + rows.length + ' 行: 対応推奨 ' + counts[V_URGENT] +
               ' / 要調査 ' + counts[V_UNKNOWN] + ' / 次回定期 ' + counts[V_ROUTINE]);

    writeState_(VENDOR_CISCO, todo, rows);

    const ledgerRows = rows.filter(function (r) { return isLedgerRow_(r, assets); });
    Logger.log('Cisco 台帳: ' + ledgerRows.length + ' / ' + rows.length + ' 行');

    const needAi = ledgerRows.filter(function (r) { return r.needsDisplayAi; });
    if (needAi.length) {
      try {
        enrichWithAI_(needAi);
      } catch (e) {
        Logger.log('Cisco AI 生成に失敗しました。フォールバックで表示列を埋めます: ' + e);
      }
      needAi.forEach(function (r) {
        applyFallbackDisplayFields_(r);
        r.reason = buildDecisionReason_(r);
      });
    }

    writeLedger_(ledgerRows);
    allLedgerRows = allLedgerRows.concat(ledgerRows);

    if (todo.length >= pending.length) break;
  }

  if (allLedgerRows.length) sortLedger_();
  return allLedgerRows;
}

function fetchCiscoCsaf_(advisoryId) {
  const id = String(advisoryId || '').trim();
  const url = CISCO_CSAF_BASE + id + '/csaf/' + id + '_csaf.json';
  const res = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('HTTP ' + res.getResponseCode());
  }
  return JSON.parse(res.getContentText());
}

/** CSAF product_tree の product_id → 版番号（17.15.5 等） */
function ciscoProductMap_(csaf) {
  const map = {};
  function walk(branch) {
    if (!branch) return;
    if (branch.product && branch.product.product_id) {
      map[branch.product.product_id] = branch.product.name || '';
    }
    (branch.branches || []).forEach(walk);
  }
  ((csaf.product_tree || {}).branches || []).forEach(walk);
  return map;
}

function ciscoAffectedVersions_(vuln, idMap) {
  const versions = [];
  ((vuln.product_status || {}).known_affected || []).forEach(function (id) {
    const v = idMap[id];
    if (v && /^\d+\.\d+/.test(v)) pushUnique_(versions, v);
  });
  return versions;
}

/** CSAF の fixed / first_fixed から版番号を抜き出す */
function ciscoFixedVersions_(vuln, idMap) {
  const versions = [];
  const status = vuln.product_status || {};
  ['fixed', 'first_fixed'].forEach(function (key) {
    (status[key] || []).forEach(function (id) {
      const name = idMap[id] || String(id);
      const m = /(\d+\.\d+(?:\.\d+)?)/.exec(name);
      if (m) pushUnique_(versions, m[1]);
    });
  });
  (vuln.remediations || []).forEach(function (r) {
    if (r.category !== 'vendor_fix') return;
    const m = /(\d+\.\d+(?:\.\d+)?)/.exec(String(r.details || ''));
    if (m && !/has released software updates/i.test(r.details || '')) {
      pushUnique_(versions, m[1]);
    }
  });
  return versions.sort(function (a, b) {
    return compareVersion_(parseVersion_(a) || [0], parseVersion_(b) || [0]);
  });
}

function ciscoConfigHints_(csaf) {
  const hints = [];
  (((csaf.document || {}).notes) || []).forEach(function (n) {
    const t = String(n.title || '').toLowerCase();
    if (t.indexOf('vulnerable products') !== -1 || t.indexOf('determine') !== -1) {
      hints.push(String(n.text || '').slice(0, 2500));
    }
  });
  return hints.join('\n\n');
}

function ciscoProductTreeNames_(csaf) {
  const names = [];
  function walk(branch) {
    if (!branch) return;
    if (branch.product && branch.product.name) pushUnique_(names, branch.product.name);
    (branch.branches || []).forEach(walk);
  }
  ((csaf.product_tree || {}).branches || []).forEach(walk);
  return names;
}

/** 製品名の突合（IOS-XE ↔ Cisco IOS XE Software 等）。 */
function productNamesMatch_(assetProduct, csafName) {
  const a = normProduct_(assetProduct);
  const b = normProduct_(csafName);
  if (!a || !b) return false;
  if (a === b) return true;
  if (a.indexOf(b) !== -1 || b.indexOf(a) !== -1) return true;
  if (a === 'iosxe' && b.indexOf('iosxe') !== -1) return true;
  return false;
}

/**
 * 資産シート基準で、この Cisco アドバイザリを処理するか（決め打ち条件）。
 * 次のいずれかを満たすときだけ true:
 *   1. CSAF の product_tree に、資産シートの製品名（例: IOS-XE）が含まれる
 *   2. CSAF の known_affected 版番号が、資産シートのいずれかの版と完全一致する
 */
function ciscoAdvisoryTargetsAssets_(csaf, assets) {
  const assetProducts = [];
  const assetVersions = [];
  assets.forEach(function (a) {
    if (a.product && a.product !== '—') pushUnique_(assetProducts, a.product);
    if (a.version) pushUnique_(assetVersions, String(a.version).trim());
  });
  if (!assetProducts.length && !assetVersions.length) return false;

  const treeNames = ciscoProductTreeNames_(csaf);
  for (let i = 0; i < assetProducts.length; i++) {
    for (let j = 0; j < treeNames.length; j++) {
      if (productNamesMatch_(assetProducts[i], treeNames[j])) return true;
    }
  }

  if (!assetVersions.length) return false;
  const idMap = ciscoProductMap_(csaf);
  const aff = {};
  (csaf.vulnerabilities || []).forEach(function (v) {
    ciscoAffectedVersions_(v, idMap).forEach(function (ver) {
      aff[String(ver).trim().toLowerCase()] = true;
    });
  });
  return assetVersions.some(function (v) { return aff[v.toLowerCase()]; });
}

/** 資産シートの製品のうち、このアドバイザリが実際に言及しているもの。 */
function ciscoTargetProducts_(csaf, assets) {
  const candidates = [];
  assets.forEach(function (a) {
    if (a.product && a.product !== '—') pushUnique_(candidates, a.product);
  });
  if (!candidates.length) return [];

  const treeNames = ciscoProductTreeNames_(csaf);
  const idMap = ciscoProductMap_(csaf);
  const allAff = [];
  (csaf.vulnerabilities || []).forEach(function (v) {
    ciscoAffectedVersions_(v, idMap).forEach(function (ver) { pushUnique_(allAff, ver); });
  });

  return candidates.filter(function (p) {
    const np = normProduct_(p);
    if (treeNames.some(function (t) { return productNamesMatch_(p, t); })) return true;
    const vers = assets.filter(function (a) { return normProduct_(a.product) === np; })
      .map(function (a) { return a.version; }).filter(Boolean);
    return vers.some(function (av) {
      return allAff.some(function (aff) { return aff.toLowerCase() === av.toLowerCase(); });
    });
  });
}

/**
 * Cisco CSAF → 台帳行（CVE × 資産製品）。
 * 資産シートの製品・版に関係ないアドバイザリは行を作らない。
 */
function extractCiscoRowsFromCsaf_(csaf, item, assets) {
  assets = assets || [];
  if (!ciscoAdvisoryTargetsAssets_(csaf, assets)) {
    return [];
  }
  const targetProducts = ciscoTargetProducts_(csaf, assets);
  if (!targetProducts.length) return [];

  const doc = csaf.document || {};
  const tracking = doc.tracking || {};
  const advisoryId = tracking.id || item.id;
  const updatedAt = tracking.current_release_date
    ? new Date(tracking.current_release_date)
    : (tracking.initial_release_date ? new Date(tracking.initial_release_date) : item.pubDate);
  const initialAt = tracking.initial_release_date
    ? new Date(tracking.initial_release_date)
    : updatedAt;
  const vulnName = String(doc.title || item.title || '').trim();
  const idMap = ciscoProductMap_(csaf);
  const configHints = ciscoConfigHints_(csaf);
  const vulns = csaf.vulnerabilities || [];
  const product = targetProducts[0];

  if (!vulns.length) {
    Logger.log('Cisco vulnerabilities なし: ' + advisoryId);
    return [extractCiscoRowFallback_(item)];
  }

  return vulns.map(function (v) {
    let score = '', severity = '', vector = '';
    (v.scores || []).forEach(function (s) {
      const c = s.cvss_v4 || s.cvss_v3 || {};
      if (c.vectorString && !vector) vector = c.vectorString;
      if (c.baseScore !== undefined && (score === '' || c.baseScore > score)) {
        score = c.baseScore;
        severity = c.baseSeverity || '';
      }
    });

    const affectedVersions = ciscoAffectedVersions_(v, idMap);
    const fixedVersions = ciscoFixedVersions_(v, idMap);
    const fixes = [];
    (v.remediations || []).forEach(function (r) {
      if (r.category === 'vendor_fix' && r.details) pushUnique_(fixes, r.details);
    });

    const summary = [
      noteText_(v, function (n) { return n.category === 'summary'; }),
      configHints
    ].filter(function (s) { return s; }).join('\n\n');

    return {
      vendor: VENDOR_CISCO,
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
      affected: affectedVersions,
      fixedVersions: fixedVersions,
      summary: summary,
      impact: (v.threats || [])
        .filter(function (t) { return t.category === 'impact'; })
        .map(function (t) { return t.details; })
        .join(', '),
      fixesRaw: fixes.join('\n'),
      workaround: '',
      verdict: '', reason: '', selfVersion: '', fixVersion: '',
      feature: '', impactJa: '', howToCheck: '', plan: ''
    };
  });
}

/** CSAF が取れないときの保険（RSS だけ）。 */
function extractCiscoRowFallback_(item) {
  const meta = parseCiscoRssMeta_(item.description);
  return {
    vendor: VENDOR_CISCO,
    advisoryId: item.id,
    advisoryUrl: item.link,
    pubDate: item.pubDate,
    initialDate: item.pubDate,
    title: item.title,
    cve: meta.cves[0] || extractCveFromText_(item.title + ' ' + item.description),
    product: 'IOS-XE',
    cvss: meta.cvss,
    severity: meta.severity,
    vector: '', unauthRemote: '',
    affected: [],
    summary: decodeCiscoHtml_(item.description || ''),
    impact: '',
    fixesRaw: '',
    workaround: '',
    verdict: V_UNKNOWN,
    reason: 'CSAF を取得できず版比較できないため',
    selfVersion: '', fixVersion: '',
    feature: '', impactJa: '', howToCheck: '', plan: ''
  };
}

function parseCiscoRssMeta_(description) {
  const html = decodeCiscoHtml_(description);
  const sir = /Security Impact Rating:\s*(\w+)/i.exec(html);
  const cvss = /CVSS Base Score:\s*([\d.]+)/i.exec(html);
  const cves = html.match(/CVE-\d{4}-\d{4,}/gi) || [];
  return {
    severity: sir ? sir[1].toUpperCase() : '',
    cvss: cvss ? cvss[1] : '',
    cves: cves.map(function (c) { return c.toUpperCase(); })
  };
}

function decodeCiscoHtml_(s) {
  return String(s || '')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
    .replace(/&#039;/g, "'").replace(/&quot;/g, '"').replace(/<[^>]+>/g, ' ');
}

function fetchCiscoRssItems_() {
  const res = UrlFetchApp.fetch(CISCO_RSS_URL, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('Cisco RSS 取得失敗 HTTP ' + res.getResponseCode());
  }

  const root = XmlService.parse(res.getContentText()).getRootElement();
  const items = root.getChild('channel').getChildren('item');

  return items.map(function (item) {
    const link = item.getChildText('link') || '';
    return {
      id: parseCiscoAdvisoryId_(link),
      title: item.getChildText('title') || '',
      link: link,
      description: item.getChildText('description') || '',
      pubDate: parsePubDate_(item.getChildText('pubDate'))
    };
  });
}

function parseCiscoAdvisoryId_(link) {
  const m = /cisco-sa-[a-z0-9-]+/i.exec(link || '');
  return m ? m[0] : String(link || '').trim();
}

function extractCveFromText_(text) {
  const m = /CVE-\d{4}-\d{4,}/gi.exec(String(text || ''));
  return m ? m[0].toUpperCase() : '';
}

/**
 * Cisco 版番号の完全一致判定。
 * CSAF の known_affected を 17.15.5 等の版番号に展開した配列と突き合わせる。
 */
function judgeCiscoVersions_(assetVersions, affectedVersions) {
  if (!affectedVersions.length) return { hit: false, unknown: true, matched: '' };

  const aff = {};
  affectedVersions.forEach(function (v) {
    aff[String(v).trim().toLowerCase()] = true;
  });

  let unknown = false;
  for (let i = 0; i < assetVersions.length; i++) {
    const av = String(assetVersions[i]).trim();
    if (!av) { unknown = true; continue; }
    if (aff[av.toLowerCase()]) return { hit: true, unknown: false, matched: av };
  }
  return { hit: false, unknown: unknown, matched: '' };
}

function testCiscoRss() {
  const items = fetchCiscoRssItems_();
  const assets = ciscoAssets_(readAssets_());
  const known = getKnownState_(VENDOR_CISCO);
  Logger.log('Cisco RSS 件数: ' + items.length + ' / 資産: ' + assets.length + ' 件');
  const candidates = selectRssCsafCandidates_(items, known, function (it) { return it.id; },
    function (it) { return it.pubDate; });
  Logger.log('CSAF 候補: ' + candidates.length + ' 件');
  let hit = 0;
  fetchCiscoCsafBatch_(candidates.slice(0, 10)).forEach(function (f) {
    if (f.error) {
      Logger.log('  CSAF 失敗 ' + f.item.id + ': ' + f.error);
      return;
    }
    try {
      if (!ciscoAdvisoryTargetsAssets_(f.csaf, assets)) return;
      hit++;
      const rows = extractCiscoRowsFromCsaf_(f.csaf, f.item, assets);
      rows.forEach(function (r) { decideNotification_(r, assets); });
      Logger.log([f.item.id, ymd_(f.updatedAt), rows.length + ' CVE'].join(' | '));
      rows.slice(0, 2).forEach(function (r) {
        Logger.log('  ' + [r.verdict, r.cve, r.cvss, r.reason].join(' | '));
      });
    } catch (e) {
      Logger.log('  処理失敗 ' + f.item.id + ': ' + e);
    }
  });
  Logger.log('資産対象アドバイザリ（候補先頭10件中）: ' + hit + ' 件');
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
function warnIfFeedOverflowed_(items, knownDates, getId) {
  getId = getId || function (it) { return it.ir; };
  if (!Object.keys(knownDates).length) return;

  const overlap = items.filter(function (it) { return knownDates[getId(it)]; }).length;

  if (overlap === 0) {
    Logger.log('警告: RSS 50 件のいずれも記録にありません。');
    Logger.log('  前回の実行から 50 件以上が入れ替わり、枠から押し出されたものがある可能性があります。');
    Logger.log('  ベンダーの PSIRT ページを人が確認し、抜けが無いか突き合わせてください。');
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
 * RSS 50 件のうち CSAF を取りに行く候補を選ぶ（日次運用向け）。
 *
 * 取得する:
 *   - 処理済みに無い ID（初出。RSS に載っている限り古くても取得）
 *   - RSS 日付が処理済みの CSAF 最終更新日より新しい（改訂の可能性）
 *   - CSAF 版が未記録の既存行（移行後の1回だけ再確認）
 *
 * スキップする:
 *   - 処理済みがあり、RSS 日付が CSAF 最終更新日以下（日次では変更なし）
 */
function selectRssCsafCandidates_(items, known, getId, getRssDate) {
  let skip = 0;
  const out = items.filter(function (it) {
    const id = getId(it);
    const prev = known.dates[id];
    if (!prev) return true;
    if (!known.versions[id]) return true;
    const rssY = ymd_(getRssDate(it));
    if (rssY && rssY > prev) return true;
    skip++;
    return false;
  });
  if (skip) Logger.log('  変更なしと判断し CSAF スキップ: ' + skip + ' 件');
  return out;
}

/** CSAF 取得後、台帳へ反映するか（最終更新日・版で判定）。 */
function needsAdvisoryProcessing_(id, csafDate, csafVersion, known) {
  if (!known.dates[id]) return true;
  if (ymd_(csafDate) !== known.dates[id]) return true;
  if (String(csafVersion || '') !== String(known.versions[id] || '')) return true;
  return false;
}

function csafTrackingVersion_(csaf) {
  const v = (((csaf || {}).document || {}).tracking || {}).version;
  return v === undefined || v === null ? '' : String(v);
}

function fetchCiscoCsafBatch_(items) {
  return items.map(function (it, i) {
    if (i > 0) Utilities.sleep(300);
    try {
      const csaf = fetchCiscoCsaf_(it.id);
      return {
        item: it,
        csaf: csaf,
        updatedAt: csafUpdatedAt_(csaf, it),
        version: csafTrackingVersion_(csaf),
        error: ''
      };
    } catch (e) {
      return { item: it, csaf: null, updatedAt: it.pubDate, version: '', error: String(e) };
    }
  });
}

/**
 * 指定 item の CSAF をまとめて取得する（items は呼び出し側で期間絞り込み済み）。
 *
 * UrlFetchApp.fetchAll() は複数リクエストを並行して投げるため、
 * 1 件ずつ fetch するより大幅に速い。
 *
 * 戻り値: [{ item, csaf, updatedAt, version, error }]
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
        return { item: it, csaf: csaf, updatedAt: csafUpdatedAt_(csaf, it),
          version: csafTrackingVersion_(csaf), error: '' };
      }
      const csaf = JSON.parse(r.getContentText());
      ok++;
      return { item: it, csaf: csaf, updatedAt: csafUpdatedAt_(csaf, it),
        version: csafTrackingVersion_(csaf), error: '' };
    } catch (e) {
      return { item: it, csaf: null, updatedAt: it.pubDate, version: '', error: String(e) };
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
      vendor: VENDOR_FORTINET,
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
    vendor: VENDOR_FORTINET,
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
    vendor: VENDOR_FORTINET, advisoryId: item.ir, advisoryUrl: item.link,
    pubDate: item.pubDate, initialDate: item.pubDate,
    title: item.title, cve: '', product: '', cvss: '', severity: '', vector: '',
    unauthRemote: '', affected: [], summary: '', impact: '', fixesRaw: '',
    workaround: '',     verdict: V_UNKNOWN,
    reason: 'アドバイザリ情報を取得できませんでした（' + msg + '）。手動で確認してください。',
    osStatus: '不明', kev: '', externalSurface: '—', takeover: '—', serviceStop: '—',
    _lockedVerdict: true,
    selfVersion: '', fixVersion: '', feature: '', impactJa: '', howToCheck: '', plan: ''
  };
}

function pushUnique_(arr, val) {
  if (val && arr.indexOf(val) === -1) arr.push(val);
}

function uniqueStrings_(arr) {
  const seen = {};
  const out = [];
  (arr || []).forEach(function (v) {
    const s = String(v || '').trim();
    if (s && !seen[s]) { seen[s] = true; out.push(s); }
  });
  return out;
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

  const headers = sh.getRange(1, 1, 1, sh.getLastColumn()).getValues()[0];
  const isV7 = headers.indexOf('ベンダー') !== -1;

  if (isV7) {
    const values = sh.getRange(2, 1, sh.getLastRow() - 1, ASSET_HEADERS.length).getValues();
    return values.filter(function (r) { return r[2] || r[3]; }).map(function (r) {
      return {
        vendor: String(r[0] || '').trim(),
        category: String(r[1] || '').trim(),
        product: String(r[2] || '').trim(),
        model: String(r[3] || '').trim(),
        version: String(r[4] || '').trim(),
        count: r[5],
        toolTarget: String(r[6] || 'はい').trim(),
        note: String(r[7] || '').trim()
      };
    });
  }

  // v6 互換
  const values = sh.getRange(2, 1, sh.getLastRow() - 1, 5).getValues();
  return values.filter(function (r) { return r[0]; }).map(function (r) {
    return {
      vendor: VENDOR_FORTINET,
      category: '',
      product: String(r[0]).trim(),
      model: '',
      version: String(r[1]).trim(),
      count: r[2],
      toolTarget: 'はい',
      note: String(r[4] || '').trim()
    };
  });
}

function fortinetAssets_(assets) {
  return assets.filter(function (a) {
    if (a.toolTarget === 'いいえ') return false;
    const v = a.vendor || VENDOR_FORTINET;
    return v === VENDOR_FORTINET && a.product && a.product !== '—';
  });
}

function ciscoAssets_(assets) {
  return assets.filter(function (a) {
    if (a.toolTarget === 'いいえ') return false;
    return a.vendor === VENDOR_CISCO;
  });
}

function assetsForProduct_(assets, product) {
  const p = normProduct_(product);
  if (!p) return [];
  return assets.filter(function (a) { return normProduct_(a.product) === p; });
}

function initDecisionFields_(row) {
  row.osStatus = row.osStatus || '';
  row.kev = row.kev || '';
  row.externalSurface = row.externalSurface || '';
  row.takeover = row.takeover || '';
  row.serviceStop = row.serviceStop || '';
  row.vendorPath = row.vendorPath || '';
  row.aiTechImpact = row.aiTechImpact || '';
  row.aiServiceStop = row.aiServiceStop || '';
  row.aiConfidence = row.aiConfidence || '';
  row.needsFortinetAi = false;
  row.needsDisplayAi = false;
}

function kevLabel_(cve) {
  return isKevListed_(cve) ? KEV_YES : KEV_NO;
}

/** AI 失敗時でも影響機能・確認方法・ユーザ影響を空にしない */
function isFortinetFeatureVocab_(feature) {
  return FORTINET_AI_FEATURES.indexOf(String(feature || '').trim()) !== -1;
}

/**
 * タイトル・要約・impact から Fortinet 統制語彙へ寄せる。
 * 当てはまらなければ「その他」（外面なし → 判定表では次回定期）。
 */
function guessFortinetFeature_(row) {
  const text = [row.feature, row.title, row.summary, row.impact].join(' ').toLowerCase();
  if (isFortinetFeatureVocab_(row.feature)) return row.feature;
  const rules = [
    [/ssl[- ]?vpn|sslvpn/, 'SSL-VPN'],
    [/ipsec/, 'IPsec VPN'],
    [/web\s*filter|webfilter/, 'Webフィルタ'],
    [/ssl\s*inspect|deep\s*inspect/, 'SSLインスペクション'],
    [/\bips\b|intrusion\s*prevention/, 'IPSエンジン'],
    [/anti[- ]?virus|\bav\b|fortiguard/, 'アンチウイルスエンジン'],
    [/\bssh\b/, 'SSH'],
    [/\bgui\b|management\s*(interface|console)|admin\s*portal/, '管理GUI'],
    [/data\s*plane|dataplane|\bwad\b|kernel|buffer\s*over/, 'データプレーン'],
    [/captive\s*portal/, 'その他']
  ];
  for (let i = 0; i < rules.length; i++) {
    if (rules[i][0].test(text)) return rules[i][1];
  }
  return 'その他';
}

function applyFallbackDisplayFields_(row) {
  if (row.vendor === VENDOR_FORTINET) {
    if (!isFortinetFeatureVocab_(row.feature)) {
      row.feature = guessFortinetFeature_(row);
    }
  } else {
    row.feature = normalizeCiscoFeature_(row.feature || row.title || '');
  }

  row.howToCheck = normalizeHowToCheck_(row);
  row.impactJa = truncateJa_(row.impactJa || fallbackImpactJa_(row), 50);
}

function truncateJa_(s, max) {
  const t = String(s || '').trim().replace(/\s+/g, ' ');
  if (!t) return '';
  return t.length > max ? t.slice(0, max) : t;
}

/** 英語タイトルコピーをやめ、impact から日本語の最悪ケースを引く */
function fallbackImpactJa_(row) {
  const text = [row.impact, row.title, row.summary].join(' ').toLowerCase();
  if (/denial of service|\bdos\b|service stop|hang|crash|reboot/.test(text)) {
    return '機器が停止し拠点の社内通信が全断する恐れ';
  }
  if (/remote code|code execution|rce|arbitrary code|command injection/.test(text)) {
    return '機器を乗っ取られ設定改ざんや通信傍受をされる恐れ';
  }
  if (/information disclosure|sensitive|leak|exfiltrat/.test(text)) {
    return '管理情報や認証情報が外部に漏れる恐れ';
  }
  if (/privilege|escalat|unauthorized.*admin/.test(text)) {
    return '一般利用者が管理者権限を奪い設定を変更する恐れ';
  }
  if (/xss|cross.?site|injection|script/.test(text)) {
    return '利用者ブラウザで不正操作され認証情報を盗まれる恐れ';
  }
  if (/auth.?bypass|authentication/.test(text)) {
    return '認証を迂回され不正アクセスされる恐れ';
  }
  return '機器や接続端末が侵害され業務通信に支障が出る恐れ';
}

function normalizeCiscoFeature_(raw) {
  let s = String(raw || '').trim().replace(/\s+/g, ' ');
  if (!s) return 'IOS XE 基盤';
  s = s.replace(/^Cisco\s+IOS\s*XE\s+Software\s*/i, '');
  s = s.replace(/^Cisco\s+IOS\s*XE\s*/i, '');
  s = s.replace(/^IOS\s*XE\s+Software\s*/i, '');
  if (/security hardening/i.test(s) || !s) return 'IOS XE 基盤';
  if (/web-based|webui|http server|web.?ui/i.test(s)) return 'WebUI';
  if (/beep/i.test(s)) return 'BEEP';
  if (/xmcp/i.test(s)) return 'XMCP Server';
  if (/sd-?wan/i.test(s)) return 'SD-WAN';
  if (/snmp/i.test(s)) return 'SNMP';
  if (/\bssh\b/i.test(s)) return 'SSH';
  if (/core/i.test(s)) return 'IOS XE 基盤';
  if (s.length > 20) s = s.slice(0, 20);
  return s || 'IOS XE 基盤';
}

function lookupCheckSteps_(row) {
  if (row.vendor === VENDOR_FORTINET) {
    const f = row.feature || 'その他';
    return CHECK_STEPS_FORTINET[f] || CHECK_STEPS_FORTINET['その他'];
  }
  const text = [row.feature, row.title].join(' ');
  for (let i = 0; i < CHECK_STEPS_CISCO.length; i++) {
    if (CHECK_STEPS_CISCO[i].re.test(text)) return CHECK_STEPS_CISCO[i].text;
  }
  return CHECK_STEPS_CISCO_DEFAULT;
}

/** 確認方法が行動可能か検証し、不合格なら機能別テーブルで差し替える */
function normalizeHowToCheck_(row) {
  const raw = String(row.howToCheck || '').trim();
  const hasCmd = /コマンド[：:]/.test(raw) && /(show|get|diagnose)\b/i.test(raw);
  const hasJudge = /判断[：:]/.test(raw);
  const useless = /アドバイザリの\s*(Affected|Fixed|Solution)|個別アドバイザリ|公開情報と対象バージョン/i.test(raw);
  if (raw && hasCmd && hasJudge && !useless) return raw;
  return lookupCheckSteps_(row);
}

// ============================================================
// 3b. KEV カタログ
// ============================================================

function fetchKevCatalog_() {
  const cache = CacheService.getScriptCache();
  const cached = cache.get('kev_catalog');
  if (cached) {
    try { return JSON.parse(cached); } catch (e) { /* 再取得 */ }
  }
  const res = UrlFetchApp.fetch(KEV_FEED_URL, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('KEV 取得失敗 HTTP ' + res.getResponseCode());
  }
  const body = JSON.parse(res.getContentText());
  const set = {};
  (body.vulnerabilities || []).forEach(function (v) {
    if (v.cveID) set[String(v.cveID).toUpperCase()] = true;
  });
  cache.put('kev_catalog', JSON.stringify(set), 21600);
  return set;
}

function isKevListed_(cve) {
  if (!cve) return false;
  try {
    const set = fetchKevCatalog_();
    return !!set[String(cve).toUpperCase()];
  } catch (e) {
    Logger.log('KEV 照合失敗: ' + e);
    return false;
  }
}

// ============================================================
// 3c. OS 該当・ベンダー別判定
// ============================================================

function judgeOsApplicability_(row, assets) {
  if (!row.product) {
    return { os: 'unknown', label: '不明', detail: '製品不明' };
  }
  const mine = assetsForProduct_(assets, row.product);
  if (!mine.length) {
    return { os: 'out', label: '対象外', detail: '非保有製品' };
  }
  const versions = mine.map(function (a) { return a.version; }).filter(function (v) { return v; });
  row.selfVersion = mine.map(function (a) {
    return row.product + ' ' + (a.version || '（バージョン未記入）');
  }).join('\n');
  if (!versions.length) {
    return { os: 'unknown', label: '不明', detail: '版未記入' };
  }
  const res = (row.vendor === VENDOR_CISCO)
    ? judgeCiscoVersions_(versions, row.affected)
    : judgeVersions_(versions, row.affected, row.product);
  if (res.hit) {
    if (row.vendor !== VENDOR_CISCO) narrowFixVersion_(row, assets);
    return { os: 'hit', label: '対象', detail: '' };
  }
  if (res.unknown) {
    return { os: 'unknown', label: '不明', detail: '版解釈不能' };
  }
  if (row.vendor === VENDOR_CISCO) {
    const uniq = uniqueStrings_(versions);
    return { os: 'out', label: '対象外', detail: '自社版 ' + uniq.join(', ') + ' は影響対象外' };
  }
  const b = branchRange_(row, versions);
  const detail = b
    ? b.branch + ' 系の影響は ' + b.range + ' まで'
    : '利用中の系列が影響対象外';
  return { os: 'out', label: '対象外', detail: detail };
}

function isOnExternalSurface_(feature) {
  const f = String(feature || '').trim();
  if (!f || f === '不明' || f === 'その他') return false;
  if (f === 'データプレーン') return true;
  if (f === 'SSL-VPN' && !SSL_VPN_ENABLED) return false;
  const surface = {
    'IPsec VPN': true, 'SSL-VPN': true, '管理GUI': true, 'SSH': true,
    'アンチウイルスエンジン': true, 'IPSエンジン': true,
    'Webフィルタ': true, 'SSLインスペクション': true
  };
  return !!surface[f];
}

function normalizeServiceStop_(v) {
  if (v === true || v === 'true' || v === 'はい') return 'はい';
  if (v === false || v === 'false' || v === 'いいえ') return 'いいえ';
  return '不明';
}

function buildDecisionReason_(row) {
  const os = row.osStatus || '不明';
  const kev = row.kev || KEV_NO;
  const phrase = row.reasonPhrase || '判定材料が不足しているため';
  const verdict = row.verdict || V_UNKNOWN;
  return 'OS=' + os + ' | KEV=' + kev + ' | ' + phrase + '「' + verdict + '」';
}

function applyCiscoVerdict_(row) {
  row.vendorPath = 'Cisco固定';
  row.osStatus = row.osStatus || '対象';
  row.kev = kevLabel_(row.cve);
  row.verdict = (row.kev === KEV_YES) ? V_URGENT : V_ROUTINE;
  row.reasonPhrase = (row.kev === KEV_YES)
    ? '悪用が確認されているため'
    : '定期更新で解消見込みのため';
  row.needsDisplayAi = true;
  row.reason = buildDecisionReason_(row);
}

function finalizeFortinetVerdict_(row, opts) {
  row.vendorPath = 'Fortinet';
  if (!opts || !opts.skipKev) {
    row.kev = kevLabel_(row.cve);
  }
  row.osStatus = row.osStatus || '対象';

  if (row.kev === KEV_YES) {
    row.verdict = V_URGENT;
    row.reasonPhrase = '悪用が確認されているため';
    row.reason = buildDecisionReason_(row);
    return;
  }

  // AI 失敗・低confidence・統制外語彙でも、OS=対象なら要調査に倒さない。
  if (!row.aiOk || !isFortinetFeatureVocab_(row.feature) || row.aiConfidence === 'low') {
    row.feature = guessFortinetFeature_(row);
    if (!row.aiTechImpact) row.aiTechImpact = '不明';
  }

  row.externalSurface = isOnExternalSurface_(row.feature) ? 'はい' : 'いいえ';
  row.takeover = row.aiTechImpact || '不明';
  row.serviceStop = normalizeServiceStop_(row.aiServiceStop);

  if (row.externalSurface === 'いいえ') {
    row.verdict = V_ROUTINE;
    row.reasonPhrase = '影響機能が外部から到達しないため';
  } else if (row.takeover === 'total' || row.serviceStop === 'はい') {
    row.verdict = V_URGENT;
    row.reasonPhrase = '外部到達面の' + row.feature + 'を悪用され重大な影響が出るため';
  } else {
    row.verdict = V_ROUTINE;
    row.reasonPhrase = '外部到達面だが影響が部分的で定期更新で解消できるため';
  }
  row.reason = buildDecisionReason_(row);
}

/**
 * 通知判定（第0段階 OS + ベンダー別）。
 * Fortinet 版該当行は AI 後に finalizeFortinetVerdict_ で確定する。
 */
function decideNotification_(row, assets) {
  if (row._lockedVerdict) return;

  initDecisionFields_(row);
  row.fixVersion = pickFixVersion_(row);

  if (!row.product) {
    row.verdict = V_UNKNOWN;
    row.osStatus = '不明';
    row.kev = kevLabel_(row.cve);
    row.reasonPhrase = '製品を特定できないため';
    row.needsDisplayAi = true;
    row.reason = buildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  const mine = assetsForProduct_(assets, row.product);
  if (!mine.length) {
    row.verdict = V_ROUTINE;
    row.osStatus = '対象外';
    row.kev = kevLabel_(row.cve);
    row.reasonPhrase = row.product + ' を自社で使用していないため';
    row.reason = buildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  const os = judgeOsApplicability_(row, assets);
  row.osStatus = os.label;

  if (os.os === 'out') {
    row.verdict = V_ROUTINE;
    row.kev = kevLabel_(row.cve);
    row.vendorPath = (row.vendor === VENDOR_CISCO) ? 'Cisco固定' : 'Fortinet';
    if (os.detail && /ため$/.test(os.detail)) {
      row.reasonPhrase = os.detail;
    } else {
      row.reasonPhrase = (os.detail || '影響対象外') + 'のため';
    }
    row.reason = buildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  if (os.os === 'unknown') {
    row.verdict = V_UNKNOWN;
    row.kev = kevLabel_(row.cve);
    row.vendorPath = (row.vendor === VENDOR_CISCO) ? 'Cisco固定' : 'Fortinet';
    row.reasonPhrase = '自社利用バージョンを判定できないため';
    row.needsDisplayAi = true;
    row.reason = buildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  if (row.vendor === VENDOR_CISCO) {
    applyCiscoVerdict_(row);
    row._lockedVerdict = true;
    return;
  }

  row.needsFortinetAi = true;
  row.needsDisplayAi = true;
  row.kev = kevLabel_(row.cve);
  if (row.kev === KEV_YES) {
    row.vendorPath = 'Fortinet';
    row.verdict = V_URGENT;
    row.reasonPhrase = '悪用が確認されているため';
    row.reason = buildDecisionReason_(row);
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
    if (r.verdict === V_ROUTINE && r.reason.indexOf('使用していない') !== -1) {
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

/** 台帳の公式推奨対応列用。英語を残さない。 */
function formatOfficialAction_(row) {
  if (row.vendor === VENDOR_CISCO) {
    const vers = row.fixedVersions || [];
    if (vers.length) return vers[0] + ' 以上に更新が必要';
    const raw = String(row.fixesRaw || '');
    if (/has released software updates/i.test(raw)) {
      return '修正済みソフトウェアが公開済み。アドバイザリの Fixed Software を確認して更新';
    }
    if (/no workarounds/i.test(raw)) return '回避策なし。修正版へ更新';
    return '修正版はアドバイザリの Fixed Software を参照';
  }
  const fix = jpFix_(row);
  if (!fix) return '';
  return jpFixEnglishFallback_(fix);
}

/** 残った英語の修正指示を日本語の定型へ */
function jpFixEnglishFallback_(text) {
  return String(text || '').split('\n').map(function (line) {
    const t = line.trim();
    if (!t) return '';
    if (/has released software updates/i.test(t)) {
      return '修正済みソフトウェアが公開済み。アドバイザリを確認して更新';
    }
    if (/Upgrade to\s+([\d.]+)/i.test(t) && !/[\u3040-\u30ff\u4e00-\u9faf]/.test(t)) {
      const m = /Upgrade to\s+([\d.]+)/i.exec(t);
      return m[1] + ' 以上に更新が必要';
    }
    return t;
  }).filter(Boolean).join('\n');
}

function countVerdicts_(rows) {
  const c = {};
  c[V_URGENT] = 0; c[V_ROUTINE] = 0; c[V_UNKNOWN] = 0;
  rows.forEach(function (r) { if (c[r.verdict] !== undefined) c[r.verdict]++; });
  return c;
}

// ============================================================
// 5. AI による機能分類・確認方法（台帳表示列）
// ============================================================

function enrichWithAI_(rows) {
  const targets = rows.filter(function (r) {
    return r.needsFortinetAi || r.needsDisplayAi;
  });
  if (!targets.length) {
    Logger.log('AI 対象の行がありません。');
    return;
  }

  let ok = 0;

  for (let i = 0; i < targets.length; i += AI_CHUNK_SIZE) {
    const chunk = targets.slice(i, i + AI_CHUNK_SIZE);
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
        if (!v) {
          r.aiOk = false;
          return;
        }
        r.feature = v.affected_feature || '不明';
        r.aiTechImpact = v.technical_impact || '不明';
        r.aiServiceStop = v.service_stop;
        r.aiConfidence = v.confidence || '';
        r.impactJa = truncateJa_(v['ユーザ影響'] || '', 50);
        r.howToCheck = v['確認方法'] || '';
        if (r.vendor === VENDOR_CISCO) {
          r.feature = normalizeCiscoFeature_(r.feature);
          r.aiOk = true;
        } else if (!isFortinetFeatureVocab_(r.feature)) {
          r.aiOk = false;
        } else {
          r.aiOk = !!(r.feature && r.feature !== '不明' && r.aiConfidence !== 'low');
        }
        ok++;
      });
      Logger.log('AI 生成 ' + label + ' 成功');
    } catch (err) {
      Logger.log('AI 生成 ' + label + ' 失敗: ' + err);
      chunk.forEach(function (r) { r.aiOk = false; });
    }
    Utilities.sleep(1000);
  }

  Logger.log('AI 生成: ' + AI_PROVIDER + ' / 成功 ' + ok + ' / 対象 ' + targets.length + ' 行');
}

function rowKey_(r) {
  return r.advisoryId + '|' + r.cve + '|' + r.product;
}

function buildEnrichPrompt_(rows) {
  const payload = rows.map(function (r) {
    return {
      key: rowKey_(r),
      ベンダー: r.vendor || VENDOR_FORTINET,
      対象製品: r.product,
      CVE: r.cve,
      脆弱性名: r.title,
      アドバイザリの記述: r.summary,
      影響の種類: r.impact,
      CVSSベクター: r.vector || '',
      自社利用バージョン: r.selfVersion,
      脆弱性の影響バージョン: (r.affected || []).join(' / '),
      ベンダー提示の緩和策: r.workaround || 'なし'
    };
  });

  return [
    'あなたは社内の情報システム担当者です。脆弱性について、',
    '人が読んで行動できる確認方法・最悪ケースの影響・機能分類を JSON で返してください。',
    '',
    '【禁止】',
    '- 最終判定（対応推奨 / 次回定期 / 要調査）を書かない',
    '- 自然文の判定根拠を書かない',
    '- set / execute / configure など変更系 CLI',
    '- 「アドバイザリを確認」だけなど、操作しても判断できない文言',
    '- アドバイザリに無い推測',
    '',
    '【入力】',
    JSON.stringify(payload, null, 1),
    '',
    '【出力フィールド】',
    'affected_feature:',
    '  Fortinet: 次のいずれか1つ → ' + FORTINET_AI_FEATURES.join(' / '),
    '  Cisco: 短い機能名（例: WebUI / BEEP / XMCP Server / SNMP）。製品名の長いタイトルは不可',
    'technical_impact: total / partial / 不明',
    'service_stop: true / false / null',
    'attack_position: network / adjacent / local / physical / 不明',
    'auth_required: none / low / high / 不明',
    'evidence: アドバイザリの根拠を20字以内',
    'confidence: high / medium / low',
    '確認方法: 必ず次の3行。読んだ人がその通り操作して対応要否を判断できること',
    '  確認ポイント：〈何が有効なら影響を受けるか〉',
    '  コマンド：〈読み取り専用。Fortinet は show/get/diagnose。Cisco は show 系〉',
    '  判断：〈この出力なら対応が必要／この出力なら次回定期で可〉',
    'ユーザ影響: 悪用された場合の最悪ケースを、業務影響が想像できる日本語で50字以内。抽象語のみ禁止',
    '',
    '出力は次の JSON 配列のみ。前置き・コードフェンスを含めないこと。',
    '[{"key":"FG-IR-26-154|CVE-2025-43892|FortiOS","affected_feature":"Webフィルタ",',
    '  "technical_impact":"partial","service_stop":false,"attack_position":"network",',
    '  "auth_required":"none","evidence":"CSAF記載","confidence":"high",',
    '  "確認方法":"確認ポイント：Webフィルタプロファイルがポリシーに紐づいているか\\nコマンド：show webfilter profile\\n判断：有効なポリシーがあれば対応が必要。未使用なら次回定期で可",',
    '  "ユーザ影響":"警告画面経由で端末が操作され社内認証情報が盗まれる恐れ"}]'
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
function getKnownState_(vendor) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_STATE);
  const dates = {};
  const versions = {};
  if (!sh || sh.getLastRow() < 2) return { dates: dates, versions: versions };

  const values = sh.getRange(2, 1, sh.getLastRow() - 1, STATE_HEADERS.length).getValues();
  const cVendor = STATE_HEADERS.indexOf('ベンダー');
  const cUpd = STATE_HEADERS.indexOf('最終更新日');
  const cId = STATE_HEADERS.indexOf('アドバイザリID');
  const cIrLegacy = STATE_HEADERS.indexOf('FG-IR');
  const cVer = STATE_HEADERS.indexOf('CSAF版');

  values.forEach(function (r) {
    const rowVendor = cVendor >= 0 ? String(r[cVendor]).trim() : VENDOR_FORTINET;
    if (vendor && rowVendor !== vendor) return;
    const id = String(cId >= 0 ? r[cId] : r[cIrLegacy]).trim();
    if (!id) return;
    dates[id] = ymd_(r[cUpd]);
    versions[id] = cVer >= 0 ? String(r[cVer] || '').trim() : '';
  });
  return { dates: dates, versions: versions };
}

/** 既読アドバイザリの最終更新日（yyyy-mm-dd）のみ。後方互換用。 */
function getKnownAdvisories_(vendor) {
  return getKnownState_(vendor).dates;
}

function vendorFromAdvisoryId_(advisoryId) {
  const id = String(advisoryId || '').trim();
  if (/^cisco-sa-/i.test(id)) return VENDOR_CISCO;
  if (/^FG-IR-/i.test(id)) return VENDOR_FORTINET;
  return '';
}

/**
 * 指定したアドバイザリの行を、台帳と処理済みシートから消す。
 * 改訂されたアドバイザリを入れ直す前に呼ぶ。
 */
function removeRowsFor_(vendor, advisoryIds) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const targets = {};
  advisoryIds.forEach(function (id) { targets[id] = true; });

  const specs = [
    { sh: ss.getSheetByName(SHEET_LEDGER), col: COL['アドバイザリ'], width: LEDGER_HEADERS.length, inferVendor: true },
    { sh: ss.getSheetByName(SHEET_STATE), colVendor: STATE_HEADERS.indexOf('ベンダー') + 1, col: STATE_HEADERS.indexOf('アドバイザリID') + 1, width: STATE_HEADERS.length }
  ];

  specs.forEach(function (spec) {
    const sh = spec.sh;
    if (!sh || sh.getLastRow() < 2) return;
    const n = sh.getLastRow() - 1;
    const ids = sh.getRange(2, spec.col, n, 1).getDisplayValues();
    const vendors = spec.inferVendor ? null : sh.getRange(2, spec.colVendor, n, 1).getDisplayValues();

    let removed = 0;
    for (let i = ids.length - 1; i >= 0; i--) {
      if (spec.inferVendor) {
        if (vendorFromAdvisoryId_(ids[i][0]) !== vendor) continue;
      } else {
        const rowVendor = String(vendors[i][0] || VENDOR_FORTINET).trim();
        if (rowVendor !== vendor) continue;
      }
      if (targets[String(ids[i][0]).trim()]) { sh.deleteRow(i + 2); removed++; }
    }
    if (removed) Logger.log(sh.getName() + ' から古い ' + removed + ' 行を削除しました（改訂のため入れ直します）。');
  });
}

/**
 * 処理したアドバイザリを 1 件 1 行で記録する。
 * 「今月 Fortinet から公表：N 件」の分母はこのシートを数えて出す。
 */
function writeState_(vendor, todo, rows) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(SHEET_STATE);
  if (!sh) {
    sh = ss.insertSheet(SHEET_STATE);
    sh.appendRow(STATE_HEADERS);
    sh.setFrozenRows(1);
  }

  const assets = vendor === VENDOR_FORTINET ? fortinetAssets_(readAssets_()) : ciscoAssets_(readAssets_());
  const byAdvisory = {};
  rows.forEach(function (r) {
    const a = byAdvisory[r.advisoryId] ||
      (byAdvisory[r.advisoryId] = { products: [], ledger: 0, initial: r.initialDate });
    pushUnique_(a.products, r.product);
    if (isLedgerRow_(r, assets)) a.ledger++;
  });

  const values = todo.map(function (f) {
    const item = f.item || f;
    const id = item.ir || item.id;
    const a = byAdvisory[id] || { products: [], ledger: 0, initial: f.updatedAt || item.pubDate };
    return [
      vendor,
      f.updatedAt || item.pubDate || '',
      a.initial || f.updatedAt || item.pubDate || '',
      id,
      item.title,
      a.ledger,
      a.products.join(', '),
      f.version || ''
    ];
  });

  const startRow = sh.getLastRow() + 1;
  sh.getRange(startRow, 1, values.length, STATE_HEADERS.length).setValues(values);
  sh.getRange(startRow, 2, values.length, 2).setNumberFormat('yyyy/mm/dd');
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
    Logger.log(k + '  公表 ' + m[k].adv + ' 件 / 台帳に記録 ' + m[k].ledger + ' 行');
  });
}

function countByMonthVendor() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_STATE);
  if (!sh || sh.getLastRow() < 2) { Logger.log('処理済みシートが空です。'); return; }

  const values = sh.getRange(2, 1, sh.getLastRow() - 1, STATE_HEADERS.length).getValues();
  const cVendor = STATE_HEADERS.indexOf('ベンダー');
  const cLedger = STATE_HEADERS.indexOf('台帳の行数');
  const m = {};
  values.forEach(function (r) {
    const d = r[STATE_HEADERS.indexOf('最終更新日')];
    const key = (d instanceof Date)
      ? d.getFullYear() + '/' + ('0' + (d.getMonth() + 1)).slice(-2)
      : '(公開日不明)';
    const vendor = cVendor >= 0 ? String(r[cVendor]).trim() : VENDOR_FORTINET;
    const bucket = m[key] || (m[key] = {});
    const s = bucket[vendor] || (bucket[vendor] = { adv: 0, ledger: 0 });
    s.adv++;
    s.ledger += Number(r[cLedger]) || 0;
  });

  Logger.log('--- 月別・ベンダー別 ---');
  Object.keys(m).sort().reverse().forEach(function (month) {
    Object.keys(m[month]).sort().forEach(function (vendor) {
      const s = m[month][vendor];
      Logger.log(month + '  ' + vendor + ': 公表 ' + s.adv + ' 件 / 台帳 ' + s.ledger + ' 行');
    });
  });
}

function toRowArray_(r) {
  const advisoryCell = r.advisoryUrl
    ? '=HYPERLINK("' + r.advisoryUrl + '","' + r.advisoryId + '")'
    : r.advisoryId;

  const action = formatOfficialAction_(r);
  const cvss = (r.cvss === '' || r.cvss === undefined) ? '' : String(r.cvss);

  return [
    r.verdict || '',                  // 1  自社影響
    r.product || '不明',              // 2  製品
    r.cve || '',                      // 3  CVE
    cvss,                             // 4  CVSS
    r.pubDate || '',                  // 5  最終更新日
    action,                           // 6  公式推奨対応
    r.kev || '',                      // 7  KEV
    r.feature || '',                  // 8  影響機能
    r.reason || '',                   // 9  判定根拠
    r.howToCheck || '',               // 10 確認方法
    r.impactJa || '',                 // 11 ユーザ影響
    advisoryCell                      // 12 アドバイザリ
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

/** 対応推奨 → 要調査 → 次回定期 の順、同じ判定なら公開日の新しい順に並べ替える。 */
function sortLedger_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 3) return;

  const n = sh.getLastRow() - 1;
  const range = sh.getRange(2, 1, n, LEDGER_HEADERS.length);
  const rank = {};
  rank[V_URGENT] = 0; rank[V_UNKNOWN] = 1; rank[V_ROUTINE] = 2;

  const formulas = range.getFormulas();
  const values = range.getValues();
  for (let i = 0; i < values.length; i++) {
    const f = formulas[i][COL['アドバイザリ'] - 1];
    if (f) values[i][COL['アドバイザリ'] - 1] = f;
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

  const widths = [90, 100, 140, 70, 100, 220, 55, 120, 280, 320, 220, 150];
  widths.forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });

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

  const wanted = {};
  let count = 0;
  for (let i = 0; i < values.length; i++) {
    const verdict = values[i][COL['自社影響'] - 1];
    const advisoryId = display[i][COL['アドバイザリ'] - 1];
    const vendor = vendorFromAdvisoryId_(advisoryId) || VENDOR_FORTINET;
    if (verdict !== V_URGENT && verdict !== V_UNKNOWN && verdict !== V_ROUTINE) continue;
    if (String(values[i][COL['ユーザ影響'] - 1]).trim() &&
        String(values[i][COL['影響機能'] - 1]).trim() &&
        String(values[i][COL['確認方法'] - 1]).trim()) continue;

    const key = advisoryId + '|' +
                values[i][COL['CVE'] - 1] + '|' +
                values[i][COL['製品'] - 1];
    wanted[key] = {
      rowIndex: i + 2,
      advisoryId: advisoryId,
      vendor: vendor,
      title: ''
    };
    count++;
  }

  if (!count) { Logger.log('AI 補完が必要な行はありません。'); return; }
  Logger.log('AI 補完対象: ' + count + ' 行');

  const fortinetAssets = fortinetAssets_(readAssets_());
  const ciscoAssetList = ciscoAssets_(readAssets_());
  const byAdvisory = {};
  Object.keys(wanted).forEach(function (k) {
    const w = wanted[k];
    byAdvisory[w.vendor + '\t' + w.advisoryId] = w.vendor;
  });

  const targets = [];
  Object.keys(byAdvisory).forEach(function (vk) {
    const parts = vk.split('\t');
    const vendor = parts[0];
    const id = parts[1];
    try {
      let rows = [];
      if (vendor === VENDOR_CISCO) {
        const item = { id: id, link: '', title: '', description: '', pubDate: '' };
        rows = extractCiscoRowsFromCsaf_(fetchCiscoCsaf_(id), item, ciscoAssetList);
        rows.forEach(function (r) { decideNotification_(r, ciscoAssetList); });
      } else {
        const item = {
          ir: id,
          title: '',
          link: 'https://fortiguard.fortinet.com/psirt/' + id,
          pubDate: ''
        };
        rows = extractRows_(fetchCsaf_(item), item);
        rows.forEach(function (r) { decideNotification_(r, fortinetAssets); });
      }
      rows.forEach(function (r) {
        const w = wanted[rowKey_(r)];
        if (w && (r.needsFortinetAi || r.needsDisplayAi)) {
          r.rowIndex = w.rowIndex;
          targets.push(r);
        }
      });
    } catch (e) {
      Logger.log('AI 補完のための再取得に失敗: ' + id + ' / ' + e);
    }
    Utilities.sleep(300);
  });

  if (!targets.length) { Logger.log('再取得できた対象がありませんでした。'); return; }

  try {
    enrichWithAI_(targets);
  } catch (e) {
    Logger.log('AI 補完に失敗しました（フォールバック継続）: ' + e);
  }

  targets.forEach(function (r) {
    applyFallbackDisplayFields_(r);
    if (r.needsFortinetAi && !r._lockedVerdict) finalizeFortinetVerdict_(r);
    else r.reason = buildDecisionReason_(r);
    r.howToCheck = normalizeHowToCheck_(r);
    r.impactJa = truncateJa_(r.impactJa || fallbackImpactJa_(r), 50);
  });

  let written = 0;
  targets.forEach(function (t) {
    if (!t.feature && !t.impactJa && !t.howToCheck) return;
    sh.getRange(t.rowIndex, COL['影響機能']).setValue(t.feature || '');
    sh.getRange(t.rowIndex, COL['判定根拠']).setValue(t.reason || '');
    sh.getRange(t.rowIndex, COL['ユーザ影響']).setValue(t.impactJa || '');
    sh.getRange(t.rowIndex, COL['確認方法']).setValue(t.howToCheck || '');
    if (t.verdict) sh.getRange(t.rowIndex, COL['自社影響']).setValue(t.verdict);
    if (t.kev) sh.getRange(t.rowIndex, COL['KEV']).setValue(t.kev);
    written++;
  });
  Logger.log('AI 補完: ' + written + ' / ' + targets.length + ' 行を書き戻しました。');
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
    .filter(function (r) { return r.verdict === V_URGENT || r.verdict === V_UNKNOWN; })
    .sort(function (a, b) {
      if (a.verdict !== b.verdict) return a.verdict === V_URGENT ? -1 : 1;
      return (Number(b.cvss) || 0) - (Number(a.cvss) || 0);
    });

  if (!hits.length && !NOTIFY_WHEN_NO_HITS) {
    Logger.log('対応推奨・要調査の新着なし。Slack 通知はスキップします。');
    return;
  }

  const sheetUrl = SpreadsheetApp.getActiveSpreadsheet().getUrl();
  const worst = hits.length ? Math.max.apply(null, hits.map(function (r) { return Number(r.cvss) || 0; })) : 0;
  const icon = !hits.length ? ':white_check_mark:' : (worst >= 7 ? ':rotating_light:' : ':warning:');

  const headline = hits.length
    ? '対応推奨 ' + c[V_URGENT] + '件 ／ 要調査 ' + c[V_UNKNOWN] + '件'
    : '対応推奨なし（新着 ' + rows.length + ' 件）';

  const blocks = [{
    type: 'header',
    text: { type: 'plain_text', text: icon + ' NW機器 ' + headline, emoji: true }
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
      r.vendor || VENDOR_FORTINET,
      r.verdict,
      r.cve ? '<' + r.advisoryUrl + '|' + r.cve + '>' : r.advisoryId,
      r.cvss !== '' && r.cvss !== undefined ? 'CVSS ' + r.cvss : null,
      r.feature || null
    ].filter(function (x) { return x; }).join('  ·  ');
    blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: meta }] });

    // (3) どうするか。結論なので通常の太さで置く
    const action = formatOfficialAction_(r);
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
  if (c[V_ROUTINE]) footer.push('次回定期 ' + c[V_ROUTINE] + '件は台帳のみ');
  footer.push('<' + sheetUrl + '|台帳を開く>（確認方法・判定根拠はこちら）');

  blocks.push({ type: 'divider' });
  blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: footer.join('  ·  ') }] });

  UrlFetchApp.fetch(url, {
    method: 'post',
    contentType: 'application/json',
    muteHttpExceptions: true,
    payload: JSON.stringify({
      text: 'NW機器 ' + headline,   // 通知プレビューとモバイル用のフォールバック
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

/** Fortinet 判定表の単体テスト（ネットワーク不要） */
function testJudge() {
  let pass = 0;
  const cases = [
    { kev: KEV_YES, feature: 'Webフィルタ', aiOk: true, tech: 'partial', stop: 'いいえ', expect: V_URGENT },
    { kev: KEV_NO, feature: '不明', aiOk: false, tech: '不明', stop: '不明', expect: V_ROUTINE },
    { kev: KEV_NO, feature: 'その他', aiOk: true, tech: 'partial', stop: 'いいえ', expect: V_ROUTINE },
    { kev: KEV_NO, feature: 'Webフィルタ', aiOk: true, tech: 'partial', stop: 'いいえ', expect: V_ROUTINE },
    { kev: KEV_NO, feature: 'Webフィルタ', aiOk: true, tech: 'total', stop: 'いいえ', expect: V_URGENT },
    { kev: KEV_NO, feature: 'IPsec VPN', aiOk: true, tech: 'partial', stop: 'はい', expect: V_URGENT },
    { kev: KEV_NO, feature: 'データプレーン', aiOk: true, tech: 'partial', stop: 'いいえ', expect: V_ROUTINE },
    { kev: KEV_NO, feature: '', aiOk: false, tech: '', stop: '', title: 'SSL-VPN Reflected XSS', expect: V_ROUTINE }
  ];

  cases.forEach(function (c, i) {
    const row = {
      vendor: VENDOR_FORTINET, cve: 'CVE-TEST-' + i, osStatus: '対象',
      kev: c.kev, feature: c.feature, aiOk: c.aiOk, title: c.title || '',
      aiTechImpact: c.tech, aiServiceStop: c.stop, aiConfidence: c.aiOk ? 'high' : 'low'
    };
    finalizeFortinetVerdict_(row, { skipKev: true });
    const fmtOk = /^OS=対象 \| KEV=(あり|なし) \| .+「.+」$/.test(row.reason)
      && row.reason.indexOf('パス=') === -1;
    const ok = row.verdict === c.expect && fmtOk;
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + JSON.stringify(c) + ' → ' + row.verdict + ' / ' + row.reason);
  });
  Logger.log('Fortinet 判定表: ' + pass + ' / ' + cases.length + ' 件が期待どおり');
}

/** Cisco KEV 固定ルールの単体テスト */
function testCiscoKevJudge() {
  const urgent = {
    osStatus: '対象', kev: KEV_YES, reasonPhrase: '悪用が確認されているため',
    verdict: V_URGENT
  };
  urgent.reason = buildDecisionReason_(urgent);
  const routine = {
    osStatus: '対象', kev: KEV_NO, reasonPhrase: '定期更新で解消見込みのため',
    verdict: V_ROUTINE
  };
  routine.reason = buildDecisionReason_(routine);
  const ok = urgent.reason.indexOf('「対応推奨」') !== -1
    && routine.reason.indexOf('「次回定期」') !== -1
    && urgent.reason.indexOf('パス=') === -1;
  Logger.log('KEV=あり → ' + urgent.reason);
  Logger.log('KEV=なし → ' + routine.reason);
  Logger.log(ok ? 'Cisco 固定ルール: OK' : 'Cisco 固定ルール: NG');
}

/** 確認手順テーブルの単体テスト */
function testCheckSteps() {
  let pass = 0;
  let total = 0;
  Object.keys(CHECK_STEPS_FORTINET).forEach(function (f) {
    total++;
    const row = { vendor: VENDOR_FORTINET, feature: f, howToCheck: 'アドバイザリの Affected Products を確認' };
    const got = normalizeHowToCheck_(row);
    const ok = /コマンド[：:]/.test(got) && /(show|get|diagnose)\b/i.test(got) && /判断[：:]/.test(got);
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + 'Fortinet ' + f);
  });
  ['WebUI', 'BEEP', 'XMCP Server', 'IOS XE 基盤', 'SD-WAN'].forEach(function (f) {
    total++;
    const row = { vendor: VENDOR_CISCO, feature: f, title: f, howToCheck: '' };
    const got = normalizeHowToCheck_(row);
    const ok = /コマンド[：:]/.test(got) && /show\b/i.test(got) && /判断[：:]/.test(got);
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + 'Cisco ' + f + ' → ' + got.split('\n')[0]);
  });
  Logger.log('確認手順: ' + pass + ' / ' + total + ' 件が期待どおり');
}

/** Cisco 影響機能名の正規化テスト */
function testCiscoFeatureNormalize_() {
  const cases = [
    ['Cisco IOS XE Software Security Hardening', 'IOS XE 基盤'],
    ['Cisco IOS XE Software Web-Based Management', 'WebUI'],
    ['BEEP', 'BEEP'],
    ['XMCP Server', 'XMCP Server']
  ];
  cases.forEach(function (c) {
    const got = normalizeCiscoFeature_(c[0]);
    Logger.log((got === c[1] ? 'OK  ' : 'NG  ') + c[0] + ' → ' + got + '（期待 ' + c[1] + '）');
  });
}

/** 外面判定の単体テスト */
function testExternalSurface_() {
  const cases = [
    ['Webフィルタ', true],
    ['SSL-VPN', SSL_VPN_ENABLED],
    ['データプレーン', true],
    ['その他', false],
    ['不明', false]
  ];
  cases.forEach(function (c) {
    const got = isOnExternalSurface_(c[0]);
    Logger.log((got === c[1] ? 'OK  ' : 'NG  ') + c[0] + ' → ' + got + '（期待 ' + c[1] + '）');
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
    verdict: V_URGENT,
    needsFortinetAi: true,
    selfVersion: 'FortiOS 7.4.5',
    affected: ['FortiOS >=7.4.0|<=7.4.8', 'FortiOS 7.2 all versions'],
    fixesRaw: 'FortiOS 7.6: Upgrade to 7.6.4 or above\nFortiOS 7.4: Upgrade to 7.4.9 or above',
    workaround: '',
    feature: '', impactJa: '', howToCheck: '', plan: ''
  }];
  enrichWithAI_(dummy);
  Logger.log(JSON.stringify(dummy[0], null, 2));
}
