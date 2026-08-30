/**
 * NW機器 脆弱性ウォッチャー for Google Apps Script  (v7 / マルチベンダー MVP)
 * ==================================================================
 * v6 からの変更点（詳細は 設計書_MVP_8h.md）:
 *
 *   1. 資産シートを拡張（ベンダー・種別・機種・ツール対象）。
 *   2. 台帳 13 列（自社影響→製品→CVE→脆弱性名→…→アドバイザリ）。固定6列。
 *   3. Cisco PSIRT RSS → CSAF 版比較（資産シートの IOS-XE / 17.15.5 等で決め打ち判定）。
 *   4. main() = runFortinet_() + runCisco_()。Slack は「あり」2値のみ。
 *   5. 自社影響3値（あり（対応検討）/あり（影響調査）/なし）、社内ルールのゲート判定。
 *   6. Cisco 入口は CSAF RSS（csaf_20.xml）。通常 RSS は CSAF 失敗時の補助。
 *   7. Cisco 修正版の自動取得（openVuln）は GAS では使わない（id.cisco.com が UrlFetch を拒否）。
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

/** Gemini API のモデル ID。3.7 Flash は AI Studio 無料枠対象（2026-08 時点）。1日上限はモデル別に別枠 */
const GEMINI_MODEL = 'gemini-3.7-flash';
/** 3.7 の無料枠（1日20回程度）を使い切ったら、枠が残っているモデルへ順に退避する */
const GEMINI_MODEL_FALLBACKS = ['gemini-3.6-flash', 'gemini-2.5-flash', 'gemini-2.0-flash'];
/**
 * Claude のモデル ID。判定はコードが行い、AI は日本語生成だけなので Haiku で足りる。
 * 呼び出しには ANTHROPIC_API_KEY（スクリプト プロパティ）が要る。
 */
const CLAUDE_MODEL = 'claude-haiku-4-5-20251001';

/**
 * AI に投げた HTTP リクエストの回数。実行履歴に残して無料枠の消費を追えるようにする。
 *
 * 数えるのはプロンプトの数ではなく、実際に投げたリクエストの数。
 * リトライもモデルのフォールバックも 1 回ずつ数える。枠を減らすのはリクエストだから。
 * 呼び出しは AI 生成の内側 3 階層で起きるため、引数で持ち回らずここで数える。
 */
let aiRequestCount_ = 0;

function countAiRequest_() { aiRequestCount_++; }

const RSS_URL = 'https://filestore.fortinet.com/fortiguard/rss/ir.xml';
/** Cisco CSAF RSS（主経路）。link/guid に CSAF JSON の URL が直接入る */
const CISCO_CSAF_RSS_URL = 'https://sec.cloudapps.cisco.com/security/center/csaf_20.xml';
/** Cisco 通常 RSS（補助）。CSAF 失敗時のタイトル・概要・人向け URL */
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
 * 自社影響「なし」の行を台帳に残す期間（か月）。0 で無制限。
 *
 * 古い行が邪魔になるのは「なし」だけである。
 * 「あり」2値は、古くても自社がまだ判断していない事実を指しているので必ず残す。
 * 実データで一律カットを試したところ、まだ影響下にある対象 2 件
 * （CVE-2025-31514 / CVE-2025-54821）が消えた。年齢で切ってはいけない。
 *
 * 「なし」を落としても分母は壊れない。処理済みシートには全件残る。
 */
const KEEP_OUT_OF_SCOPE_MONTHS = 3;

/** Slack に個別表示する最大件数。超えた分は「ほか N 件」にまとめる */
const SLACK_MAX_ITEMS = 5;

/** Slack 末尾の外部一覧。URL は表示せずリンクテキストだけ出す */
const SECURITY_NEXT_VULN_URL = 'https://www.security-next.com/category/cat177';

/** 影響ありが 0 件のときも Slack に流すか。日次実行では false が静か */
const NOTIFY_WHEN_NO_HITS = false;

/** 1回の AI 呼び出しで処理する行数。無料枠は回数課金なので、通知対象はできるだけ1回にまとめる */
const AI_CHUNK_SIZE = 10;

/**
 * 自社影響の3値。社内ルール（社内ルール案_OS更新基準.md）の写し。
 *
 * ベースラインは年1回の定期OS更新。ツールの役割は次の切り分けだけ。
 *   V_ACT    臨時更新の条件を満たす。対応時期を検討する
 *   V_INVEST 設定次第で影響が変わる。確認方法を実行して判断する
 *   V_NONE   定期更新で足りる。臨時更新しない根拠がある
 *
 * 「影響が partial だから待てる」のような結論をツールが勝手に出さないこと。
 * 設定を見ていない以上、確認前の正しい状態は V_INVEST である。
 */
const V_ACT = 'あり（対応検討）';
const V_INVEST = 'あり（影響調査）';
const V_NONE = 'なし';

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
 * 台帳 13 列。
 *
 * A 固定6列: 自社影響 → 製品 → CVE → 脆弱性名 → CVSS → 最終更新日
 * B 判定表示: 公式推奨対応 → KEV → 影響機能 → 判定根拠
 * C 人の確認: 確認方法 → ユーザ影響（AI）
 * D 参照: アドバイザリ
 *
 * OS該当は列に出さず、判定根拠の「OS=…」に含める。
 * 外面・掌握・停止は判定の内部入力のみ。
 */
const LEDGER_HEADERS = [
  '自社影響',     // 1  あり（対応検討）/ あり（影響調査）/ なし
  '製品',         // 2
  'CVE',          // 3
  '脆弱性名',     // 4  CSAF / RSS の文書タイトル（短い表示）
  'CVSS',         // 5
  '最終更新日',   // 6
  '公式推奨対応', // 7  ベンダー公式（日本語）
  'KEV',          // 8  あり / なし
  '影響機能',     // 9
  '判定根拠',     // 10 OS=… | KEV=… | ◯◯のため「結論」
  '確認方法',     // 11 確認ポイント／コマンド／判断
  'ユーザ影響',   // 12 最悪ケース50字以内
  'アドバイザリ'  // 13
];

/**
 * 機能別の確認手順（行動可能）。AI 出力が不合格のときこれで差し替える。
 * 書式: 確認ポイント / コマンド / 判断 の3行。
 */
const CHECK_STEPS_FORTINET = {
  '管理GUI': [
    '確認ポイント：管理用インターフェースで HTTP/HTTPS 管理が許可されているか',
    'コマンド：show system interface',
    '判断：allowaccess に http または https があれば対応が必要。無ければ定期更新で可'
  ].join('\n'),
  'SSH': [
    '確認ポイント：SSH 管理アクセスと管理者 trusthost の制限有無',
    'コマンド：show system interface\nshow system admin',
    '判断：allowaccess に ssh があり trusthost が未設定なら対応が必要。SSH無効なら定期更新で可'
  ].join('\n'),
  'SSL-VPN': [
    '確認ポイント：SSL-VPN が有効か',
    'コマンド：show vpn ssl settings',
    '判断：status が enable なら対応が必要。disable なら定期更新で可'
  ].join('\n'),
  'IPsec VPN': [
    '確認ポイント：IPsec phase1 が設定されているか',
    'コマンド：show vpn ipsec phase1-interface',
    '判断：phase1 が1件以上あれば対応が必要。無ければ定期更新で可'
  ].join('\n'),
  'Webフィルタ': [
    '確認ポイント：Webフィルタプロファイルがポリシーに紐づいているか',
    'コマンド：show webfilter profile\nshow firewall policy',
    '判断：プロファイルが有効なポリシーがあれば対応が必要。未使用なら定期更新で可'
  ].join('\n'),
  'SSLインスペクション': [
    '確認ポイント：SSL/SSH 検査プロファイルが使われているか',
    'コマンド：show firewall ssl-ssh-profile',
    '判断：検査が有効なプロファイルがあれば対応が必要。未使用なら定期更新で可'
  ].join('\n'),
  'IPSエンジン': [
    '確認ポイント：IPS センサがポリシーに適用されているか',
    'コマンド：show ips sensor',
    '判断：センサが有効なら対応が必要。未使用なら定期更新で可'
  ].join('\n'),
  'アンチウイルスエンジン': [
    '確認ポイント：アンチウイルスプロファイルが使われているか',
    'コマンド：show antivirus profile',
    '判断：プロファイルが有効なら対応が必要。未使用なら定期更新で可'
  ].join('\n'),
  'データプレーン': [
    '確認ポイント：版は対象済み（追加の版確認は不要）',
    'アクション：アドバイザリの更新先を確認し、定期更新枠に載せる',
    '判断：臨時対応は不要。次回メンテで更新すれば足りる'
  ].join('\n'),
  'その他': [
    '確認ポイント：タイトルと Affected Products から影響機能を特定する',
    'アクション：該当機能の有効可否を実機で確認し、使っていなければなし／使っていれば対応検討へ振り分ける',
    '判断：機能が特定できたら設定確認コマンドを打つ。特定できなければ室で共有'
  ].join('\n'),
  '不明': [
    '確認ポイント：タイトルと Affected Products から影響機能を特定する',
    'アクション：該当機能の有効可否を実機で確認し、使っていなければなし／使っていれば対応検討へ振り分ける',
    '判断：機能が特定できたら設定確認コマンドを打つ。特定できなければ室で共有'
  ].join('\n')
};

/**
 * Cisco の確認手順。**フォールバック専用**。
 *
 * Cisco のアドバイザリは Vulnerable Products / Determine 節に
 * 正確な確認コマンドと、悪用不可になる除外条件（`ip http active-session-modules none` など）
 * まで書いている。手書きのこの表より必ず詳しいので、AI にはその節を優先させる
 * （ciscoConfigHints_ で渡し、buildEnrichPrompt_ で優先を指示）。
 *
 * ここを使うのは、AI が失敗したか、行動できない文言を返したときだけ。
 */
const CHECK_STEPS_CISCO = [
  {
    re: /http|webui|web-based|web based|management/i,
    text: [
      '確認ポイント：HTTP/HTTPS 管理サーバが有効か',
      'コマンド：show running-config | include ip http server|ip http secure-server',
      '判断：ip http server / secure-server が出れば対応が必要。無ければ定期更新で可'
    ].join('\n')
  },
  {
    re: /beep/i,
    text: [
      '確認ポイント：BEEP リスナーが有効か',
      'コマンド：show running-config | include beep',
      '判断：beep 設定が出れば対応が必要。無ければ定期更新で可'
    ].join('\n')
  },
  {
    re: /xmcp/i,
    text: [
      '確認ポイント：XMCP Server が有効か',
      'コマンド：show running-config | include service-routing xmcp',
      '判断：xmcp listen が出れば対応が必要。無ければ定期更新で可'
    ].join('\n')
  },
  {
    re: /snmp/i,
    text: [
      '確認ポイント：SNMP サーバが有効か',
      'コマンド：show running-config | include snmp-server',
      '判断：snmp-server 設定が出れば対応が必要。無ければ定期更新で可'
    ].join('\n')
  },
  {
    re: /\bssh\b|vty/i,
    text: [
      '確認ポイント：SSH / VTY アクセスが有効か',
      'コマンド：show running-config | include ip ssh|line vty',
      '判断：SSH または VTY が有効なら対応が必要。無効なら定期更新で可'
    ].join('\n')
  },
  {
    re: /sd-?wan/i,
    text: [
      '確認ポイント：SD-WAN 機能が設定されているか',
      'コマンド：show running-config | include sdwan|sd-wan',
      '判断：SD-WAN 設定が出れば対応が必要。無ければ定期更新で可'
    ].join('\n')
  }
];

const CHECK_STEPS_CISCO_DEFAULT = [
  '確認ポイント：版は対象済み（追加の版確認は不要）',
  'アクション：アドバイザリで更新先を確認し、定期更新枠に載せる',
  '判断：臨時対応は不要。次回メンテで更新すれば足りる'
].join('\n');

/** あり（影響調査）向け。定期更新定型は使わない */
const CHECK_STEPS_CISCO_INVEST = [
  '確認ポイント：アドバイザリの Affected Products / Determine 節で影響条件を特定する',
  'アクション：該当機能の有効可否を実機で確認し、使っていなければなし／使っていれば対応検討へ振り分ける',
  '判断：条件が分かれば設定確認コマンドを打つ。分からなければ室で共有して判断'
].join('\n');

/** 資産シート v7。「製品」はベンダー公式表記（FortiOS / IOS-XE）。ツール対象=いいえ は台帳に出さない */
/**
 * 資産シートの列。判定は「バージョン」を突き合わせて行うので、
 * この表がいつ時点のものかが分からないと、判定結果の根拠も定まらない。
 * 「更新日」は人が棚卸しした日を手で入れる欄。ツールは書き込まない。
 */
const ASSET_HEADERS = ['ベンダー', '種別', '製品', '機種', 'バージョン', '台数', 'ツール対象',
                       '備考', '更新日'];

const DEFAULT_ASSET_ROWS = [
  [VENDOR_FORTINET, 'UTM', 'FortiOS', 'FortiGate 120G', '7.4.11', 1, 'はい', '', ''],
  [VENDOR_CISCO, 'Switch', 'IOS-XE', 'C9200-24PXG-E', '17.15.5', 1, 'はい', '', ''],
  [VENDOR_CISCO, 'Switch', 'IOS-XE', 'C9200L-24PXG-4X', '17.15.5', 1, 'はい', '', ''],
  [VENDOR_CISCO, 'WLC', 'IOS-XE', 'Catalyst 9800-L', '17.15.5', 1, 'はい', '版は実機確認推奨', ''],
  [VENDOR_CISCO, 'AP', '—', 'CW9166I-Q', '', 1, 'はい', 'WLC管理下', ''],
  [VENDOR_FORTINET, '—', '—', 'FortiClient EMS', '', 1, 'いいえ', 'クライアント・対象外', ''],
  ['Netgear', 'Switch', '—', 'MS510TXM', '', 1, 'いいえ', '別ベンダー', ''],
  ['Netgear', 'Switch', '—', 'GS108Tv3', '', 1, 'いいえ', '別ベンダー', ''],
  ['Soliton', 'RADIUS', '—', 'NetAttest EPS-edge SX06', '', 1, 'いいえ', '別ベンダー', '']
];

/** 処理済みシート。分母（今月の公表件数）はここから数える。 */
const STATE_HEADERS = ['ベンダー', '最終更新日', '初回公表日', 'アドバイザリID', 'タイトル',
                       '対象製品', 'CSAF版', '自社判定'];

/** 過去の構成にあって今は使わない列。migrateLedgerHeaders() が名前で削除する。 */
const REMOVED_STATE_COLUMNS = ['台帳の行数'];

/**
 * 実行履歴。1 回の実行につき、ベンダーごとに 1 行。
 *
 * Slack は「判断が要る行があった日」だけ鳴る（NOTIFY_WHEN_NO_HITS = false）。
 * つまり「該当なしだった日」「取得に失敗した日」「トリガーが消えて実行されなかった日」が
 * すべて "Slack が静か" という同じ見え方になる。実行ログは保持期間が短く後から遡れない。
 * 動いた事実だけはここに残し、行が途切れていれば止まったと分かるようにする。
 */
const SHEET_RUNLOG = '実行履歴';
/*
 * 列は「確認 → 新規・改訂 → 台帳 → 失敗」の順に、上流から下流へ一直線に読めるようにする。
 * 取得件数（実際に CSAF を何本ダウンロードしたか）はここに置かない。
 * Fortinet は毎回全件、Cisco は差分のみという内部事情の数字で、合計すると
 * 「確認 100 なのに取得 50、残り 50 はどこへ？」という誤読を生むため、内訳へ回す。
 */
const RUNLOG_HEADERS = ['実行日時', '結果', '確認件数', '新規・改訂', '台帳へ追加',
                        '失敗', '所要秒', 'AI呼び出し', '内訳'];

/**
 * 1 回の実行（main）で集めた統計。
 *
 * 履歴は「1 日 1 実行 = 1 行」で読めるのが理想なので、ベンダーごとの処理は
 * ここへ足すだけにして、書き出しは main() が最後に 1 回だけ行う。
 * ベンダー別の数字は「内訳」列に残すので、異常時の切り分けはできる。
 */
let runStats_ = null;

function startRunStats_() {
  runStats_ = { startedAt: Date.now(), aiAtStart: aiRequestCount_, vendors: [] };
}

/** main() の外から呼ばれた場合（reprocessCisco など）は何もしない。 */
function addVendorStats_(vendor, s) {
  if (!runStats_) return;
  runStats_.vendors.push({
    vendor: vendor,
    rss: s.rss || 0, fetched: s.fetched || 0, ok: s.ok || 0,
    missing: s.missing || 0, failed: s.failed || 0,
    processed: s.processed || 0, ledger: s.ledger || 0,
    mode: s.mode || '', note: s.note || ''
  });
}

/**
 * CSAF を読めていない行の「CSAF版」に置く印。
 *
 * 空欄にしない。空欄は人から見て入力漏れと区別が付かず、埋められたり
 * 移行で正規化されたりすると、後日 CSAF が公開されたときに拾えなくなる
 * （Fortinet の版は常に "0" なので、日付が初回公表日のままだと版だけが手がかりになる）。
 * この列は "0" と空欄の取り違えで一度全件を誤検知した場所でもある。
 */
const STATE_VERSION_UNAVAILABLE = '未取得';

// ============================================================
// エントリポイント
// ============================================================

function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu('脆弱性ウォッチャー')
    .addItem('データ削除（台帳・処理済み）', 'clearRunData')
    .addItem('Ciscoだけ再取得', 'reprocessCisco')
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
    state.setColumnWidth(6, 280);
    state.setColumnWidth(7, 70);
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
      // 廃止した列は末尾からではなく名前で消す。末尾を落とすと右隣の列が
      // 1つずれて残り、既読判定が「CSAF版」の位置で対象製品を読むようになる。
      REMOVED_STATE_COLUMNS.forEach(function (name) {
        const at = cur.indexOf(name);
        if (at >= 0) {
          state.deleteColumn(at + 1);
          cur.splice(at, 1);
          Logger.log('処理済みシートから「' + name + '」列を削除しました。');
        }
      });
      if (state.getLastColumn() > STATE_HEADERS.length) {
        state.deleteColumns(STATE_HEADERS.length + 1, state.getLastColumn() - STATE_HEADERS.length);
      }
      state.getRange(1, 1, 1, STATE_HEADERS.length).setValues([STATE_HEADERS]);
      state.setFrozenRows(1);
      Logger.log('処理済みシートの見出しを ' + STATE_HEADERS.length + ' 列に更新しました。');
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

/**
 * Cisco の処理済み・台帳だけ消して再取得する。
 * 処理済みに残っていると main() は Cisco を再取得しない。
 */
/**
 * Fortinet の処理済みと台帳を消し、RSS 50 件を取り直す。
 * 列を増やしたときなど、既存行を新しい構成で埋め直したいときに手で実行する。
 *
 * 注意: 50 件を一度に再処理するため実行が長い。過去に同等の処理量で
 * 6 分の実行時間制限に到達している。制限に当たると、処理済みには記録されたが
 * 台帳には入らなかった件が残る（writeState_ が台帳書き込みより先に走るため）。
 * その場合はもう一度この関数を実行すれば、消してからやり直すので回復する。
 */
function reprocessFortinet() {
  const removedState = deleteVendorStateRows_(VENDOR_FORTINET);
  const removedLedger = deleteVendorLedgerRows_(VENDOR_FORTINET);
  Logger.log('Fortinet 再取得の準備: 処理済み ' + removedState + ' 行 / 台帳 ' +
             removedLedger + ' 行を削除');

  const rows = runFortinet_();
  Logger.log('reprocessFortinet 完了: 台帳へ ' + rows.length + ' 行');
  if (rows.length) notifySlack_(rows);
  else Logger.log('Fortinet 台帳 0 行。ログの「自社影響」「OS該当」を確認してください。');
  return rows;
}

function reprocessCisco() {
  clearCiscoEmptyRetryMark_();
  const removedState = deleteVendorStateRows_(VENDOR_CISCO);
  const removedLedger = deleteVendorLedgerRows_(VENDOR_CISCO);
  Logger.log('Cisco 再取得の準備: 処理済み ' + removedState + ' 行 / 台帳 ' + removedLedger + ' 行を削除');

  const rows = runCisco_();
  Logger.log('reprocessCisco 完了: 台帳へ ' + rows.length + ' 行');
  if (rows.length) notifySlack_(rows);
  else Logger.log('Cisco 台帳 0 行。ログの「資産対象外」「情報通知」を確認してください。');
  return rows;
}

function deleteVendorStateRows_(vendor) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_STATE);
  if (!sh || sh.getLastRow() < 2) return 0;
  const n = sh.getLastRow() - 1;
  const cVendor = STATE_HEADERS.indexOf('ベンダー') + 1;
  const cId = STATE_HEADERS.indexOf('アドバイザリID') + 1;
  const vendors = sh.getRange(2, cVendor, n, 1).getDisplayValues();
  const ids = sh.getRange(2, cId, n, 1).getDisplayValues();
  let removed = 0;
  for (let i = n - 1; i >= 0; i--) {
    const rowVendor = String(vendors[i][0] || '').trim();
    const id = String(ids[i][0] || '').trim();
    if (rowVendor !== vendor && vendorFromAdvisoryId_(id) !== vendor) continue;
    deleteSheetRowSafe_(sh, i + 2);
    removed++;
  }
  return removed;
}

function deleteVendorLedgerRows_(vendor) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 2) return 0;
  const n = sh.getLastRow() - 1;
  const col = COL['アドバイザリ'];
  const ids = sh.getRange(2, col, n, 1).getDisplayValues();
  let removed = 0;
  for (let i = n - 1; i >= 0; i--) {
    if (vendorFromAdvisoryId_(ids[i][0]) !== vendor) continue;
    deleteSheetRowSafe_(sh, i + 2);
    removed++;
  }
  return removed;
}

const PROP_CISCO_EMPTY_RETRY = 'ciscoEmptyLedgerRetryAt';

function clearCiscoEmptyRetryMark_() {
  PropertiesService.getScriptProperties().deleteProperty(PROP_CISCO_EMPTY_RETRY);
}

function countLedgerVendorRows_(vendor) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 2) return 0;
  const n = sh.getLastRow() - 1;
  const col = COL['アドバイザリ'];
  const ids = sh.getRange(2, col, n, 1).getDisplayValues();
  let count = 0;
  for (let i = 0; i < ids.length; i++) {
    if (vendorFromAdvisoryId_(ids[i][0]) === vendor) count++;
  }
  return count;
}

/**
 * 処理済みに Cisco があるのに台帳が空なら、処理済みを消して再取得する。
 * 突合を直したあとに、古い「対象外」記録で永久スキップされるのを防ぐ。
 * 再取得しても空なら、同じ実行を毎日繰り返さない。
 */
function recoverCiscoIfLedgerEmpty_() {
  const knownCount = Object.keys(getKnownState_(VENDOR_CISCO).dates).length;
  const ledgerCount = countLedgerVendorRows_(VENDOR_CISCO);
  const props = PropertiesService.getScriptProperties();

  if (ledgerCount > 0) {
    props.deleteProperty(PROP_CISCO_EMPTY_RETRY);
    return;
  }
  if (!knownCount) return;
  if (props.getProperty(PROP_CISCO_EMPTY_RETRY)) {
    Logger.log('Cisco: 処理済みはあるが台帳が空です。再取得は実施済みのためスキップ。必要なら reprocessCisco() を実行してください。');
    return;
  }

  props.setProperty(PROP_CISCO_EMPTY_RETRY, new Date().toISOString());
  const n = deleteVendorStateRows_(VENDOR_CISCO);
  Logger.log('Cisco: 処理済み ' + n + ' 行を消して再取得します（台帳が空のため）');
}

/** 指定シートの 2 行目以降を削除する。削除した行数を返す。 */
function deleteSheetDataRows_(sheetName) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(sheetName);
  if (!sh || sh.getLastRow() < 2) return 0;
  const count = sh.getLastRow() - 1;
  clearSheetDataRows_(sh);
  return count;
}

/**
 * 見出し固定のシートは、非固定行をすべて delete できない
 * （「固定されていない行をすべて削除することはできません」）。
 * 中身を消して、余った空行だけ詰める。2行目は必ず残す。
 */
function clearSheetDataRows_(sh) {
  const last = sh.getLastRow();
  if (last < 2) return;
  const cols = Math.max(sh.getLastColumn(), 1);
  sh.getRange(2, 1, last - 1, cols).clearContent();
  if (last > 2) sh.deleteRows(3, last - 2);
}

function deleteSheetRowSafe_(sh, row) {
  const frozen = sh.getFrozenRows() || 0;
  if (sh.getMaxRows() - 1 <= frozen) {
    sh.getRange(row, 1, 1, Math.max(sh.getLastColumn(), 1)).clearContent();
    return;
  }
  sh.deleteRow(row);
}

/** 資産シートを v7 列構成に更新する（既存データは消える）。 */
function migrateAssetHeaders() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sh = ss.getSheetByName(SHEET_ASSET);
  if (!sh) {
    setup();
    return;
  }

  if (sh.getMaxColumns() < ASSET_HEADERS.length) {
    sh.insertColumnsAfter(sh.getMaxColumns(), ASSET_HEADERS.length - sh.getMaxColumns());
  }

  const cur = sh.getRange(1, 1, 1, Math.max(sh.getLastColumn(), 1)).getDisplayValues()[0];
  const isV7 = cur.indexOf('ベンダー') !== -1;
  const dataRows = Math.max(sh.getLastRow() - 1, 0);

  // すでに v7 構成なら見出しを合わせるだけ。列を末尾に増やしたときはこちらを通る。
  // ここで入力済みの資産を消してはいけない。台帳や処理済みと違い、
  // 資産シートは人が手で維持している唯一の入力で、消すと復元できない。
  if (isV7) {
    sh.getRange(1, 1, 1, ASSET_HEADERS.length).setValues([ASSET_HEADERS]);
    sh.setFrozenRows(1);
    Logger.log('資産シートの見出しを ' + ASSET_HEADERS.length + ' 列に更新しました' +
               '（入力済みの ' + dataRows + ' 行はそのまま残しています）。');
    return;
  }

  // v6 構成（製品・バージョン・台数・—・備考の 5 列）からの移行。
  // 列の意味が違うので並べ替えが要るが、入力済みの資産は捨てずに移し替える。
  const old = dataRows ? sh.getRange(2, 1, dataRows, 5).getValues() : [];
  const moved = old.filter(function (r) { return r[0]; }).map(function (r) {
    return [VENDOR_FORTINET, '', String(r[0]).trim(), '', String(r[1] || '').trim(),
            r[2], 'はい', String(r[4] || '').trim(), ''];
  });

  if (dataRows) clearSheetDataRows_(sh);
  sh.getRange(1, 1, 1, ASSET_HEADERS.length).setValues([ASSET_HEADERS]);

  const rows = moved.length ? moved : DEFAULT_ASSET_ROWS;
  sh.getRange(2, 1, rows.length, ASSET_HEADERS.length).setValues(rows);
  sh.setFrozenRows(1);
  Logger.log('資産シートを v7 構成（' + ASSET_HEADERS.length + ' 列）に更新しました。' +
             (moved.length ? '既存 ' + moved.length + ' 行を移し替えました。'
                           : '空だったので初期値を入れました。'));
}

function createDailyTrigger() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (t.getHandlerFunction() === 'main') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('main').timeBased().atHour(9).everyDays(1).create();
  Logger.log('毎日 9 時台に main() を実行するトリガーを作成しました。');
}

function main() {
  startRunStats_();
  let runError = '';
  try {
    const fortinetRows = runFortinet_();
    const ciscoRows = runCisco_();
    const notifyRows = fortinetRows.concat(ciscoRows);
    if (notifyRows.length) notifySlack_(notifyRows);
    else backfillAiColumns_();
    Logger.log('main() 完了（Fortinet 台帳 ' + fortinetRows.length +
               ' 行 / Cisco 台帳 ' + ciscoRows.length + ' 行）');
  } catch (e) {
    Logger.log('main() 失敗: ' + e);
    notifyMainFailure_(e);
    runError = String(e);
    throw e;
  } finally {
    // 落ちた実行こそ履歴に残す。行が無い＝そもそも実行されなかった、と読めるようにする。
    writeRunLog_(runError);
  }
}

/**
 * 運用者（実行アカウント）へメールする。
 *
 * 日次トリガーの結果はログを見ないと分からず、実行ログの保持期間も短い。
 * 「人が見に行かなくても届く」経路はここだけなので、
 * 人の判断が要る事実に限ってここから送る。Slack と台帳は増やさない。
 * 送信に失敗しても処理は止めない（通知の失敗で本体を落とさない）。
 */
function sendOpsMail_(subject, bodyLines) {
  try {
    const to = Session.getActiveUser().getEmail() || Session.getEffectiveUser().getEmail();
    if (!to) {
      Logger.log('メール通知: 宛先メールが取得できませんでした（' + subject + '）');
      return;
    }
    MailApp.sendEmail({
      to: to,
      subject: subject,
      body: bodyLines.concat([
        '',
        'スプレッドシート: ' + SpreadsheetApp.getActiveSpreadsheet().getUrl()
      ]).join('\n')
    });
    Logger.log('メールを送信しました（' + subject + '） → ' + to);
  } catch (mailErr) {
    Logger.log('メール送信に失敗（' + subject + '）: ' + mailErr);
  }
}

/**
 * main() が落ちたとき、実行アカウントへメールする。
 * 日次トリガーはログを見ないと気づかないので、失敗だけは能動的に届ける。
 */
function notifyMainFailure_(err) {
  sendOpsMail_('[脆弱性ウォッチャー] main() 失敗', [
    '日次の脆弱性チェック（main）が失敗しました。',
    '',
    'エラー: ' + err,
    '',
    'Apps Script の実行ログを確認してください。'
  ]);
}

/**
 * 一度も処理できていないアドバイザリの CSAF を取得できなかったとき、運用者へメールする。
 *
 * 台帳にも Slack にも出さない。ログだけだと「Slack に何も出ない日」と
 * 「取りこぼした日」が同じ見え方になり、疑うきっかけが無いため、
 * 人が動く必要がある場合に限ってメールで知らせる。
 *
 * 送るのは「処理済みシートに記録が無い＝一度も台帳に反映できていない」件だけ。
 * 記録済みの件が一時的に取れなかった場合は、翌日の実行で取り直せば済むので送らない。
 */
function notifyFetchFailures_(vendor, failures) {
  const lines = [
    vendor + ' の新しいアドバイザリ ' + failures.length + ' 件で、CSAF を取得できませんでした。',
    'これらはまだ一度も台帳に反映できていません。',
    ''
  ];

  failures.forEach(function (f) {
    const item = f.item || f;
    lines.push('・' + (item.ir || item.id) + '  ' + (item.title || ''));
    lines.push('    ' + f.error);
    lines.push('    アドバイザリ: ' + (item.link || ''));
    lines.push('    CSAF: ' + (item.csafUrl || csafUrlFor_(item)));
    lines.push(f.missing
      ? '    → CSAF未作成として記録しました。以後この件を自動では取りに行きません。'
      : '    → 記録していません。翌日の実行で自動的に取り直します。');
    lines.push('');
  });

  lines.push('「CSAF未作成」と出ている件は、CSAF が実在するのに URL を外している可能性もあります。');
  lines.push('アドバイザリページを開いて中身を確認してください。');

  sendOpsMail_('[脆弱性ウォッチャー] CSAF 取得失敗 ' + failures.length + ' 件（' + vendor + '）', lines);
}

function runFortinet_() {
  const assets = fortinetAssets_(readAssets_());
  if (!assets.length) {
    Logger.log('警告: Fortinet 対象の資産がありません。');
  }

  const allItems = fetchRssItems_();
  const known0 = getKnownState_(VENDOR_FORTINET);
  warnIfFeedOverflowed_(allItems, known0.dates, function (it) { return it.ir; });

  // RSS の日付では CSAF の改訂を判断できないため、毎回すべて取得する。
  // 実測: RSS の pubDate / description の "Revised on" と CSAF の current_release_date は
  // 双方向にずれる。RSS だけ動いて CSAF が変わらない件（FG-IR-24-257: Revised on 2026-06-15、
  // CSAF は 2025-08-08 のまま）もあれば、RSS が一切動かないまま CSAF だけ改訂される件
  // （FG-IR-26-139: 2026-05-13 公表 → CSAF 2026-06-08 改訂）もある。後者は RSS の日付で
  // 候補を絞る限り永久に検知できない。よって RSS は ID とタイトルの目次としてだけ使い、
  // 既読判定は CSAF の実データ 1 本に寄せる。fetchAll のパラレル取得で 50 件およそ 5 秒。
  Logger.log('Fortinet RSS: 全 ' + allItems.length +
             ' 件の CSAF を取得します（RSS の日付は CSAF の改訂を表さないため毎回全件）');
  const fetched = fetchAllCsaf_(allItems);

  // 一度も処理できていない件の取得に失敗したときだけメールする。
  // 記録済みの件の一時的な失敗は、翌日取り直せば済むので通知しない。
  const unseenFailures = fetched.filter(function (f) {
    return f.error && !known0.dates[f.item.ir];
  });
  if (unseenFailures.length) notifyFetchFailures_(VENDOR_FORTINET, unseenFailures);

  let allLedgerRows = [];
  let batchNum = 0;
  let processedCount = 0;
  // このバッチで扱い終えた ID。取得に失敗した件は処理済みに記録しないため、
  // 記録の有無だけでループを回すと同じ件を選び続けてしまう。
  const handled = {};

  // 未処理がなくなるまで同一実行内で繰り返す（日次1回で全件処理）
  while (true) {
    const known = getKnownState_(VENDOR_FORTINET);
    const pending = fetched.filter(function (f) {
      if (handled[f.item.ir]) return false;
      return needsAdvisoryProcessing_(f.item.ir, f.updatedAt, f.version, known, !!f.error);
    });

    if (!pending.length) {
      if (!batchNum) Logger.log('Fortinet: 新着・改訂ともになし。');
      break;
    }

    const todo = pending.slice(0, MAX_ADVISORIES_PER_RUN);
    todo.forEach(function (f) { handled[f.item.ir] = true; });
    processedCount += todo.length;
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
        Logger.log((f.missing ? 'CSAF未作成: ' : 'CSAF 取得失敗（翌日再取得）: ') +
                   f.item.ir + ' / ' + f.error);
        rows.push(errorRow_(f.item, f.error));
        return;
      }
      rows = rows.concat(extractRows_(f.csaf, f.item));
    });
    Logger.log('展開後の行数: ' + rows.length);

    rows.forEach(function (r) { decideNotification_(r, assets); });

    const counts = countVerdicts_(rows);
    Logger.log('全 ' + rows.length + ' 行: ' + V_ACT + ' ' + counts[V_ACT] +
               ' / ' + V_INVEST + ' ' + counts[V_INVEST] + ' / ' + V_NONE + ' ' + counts[V_NONE]);
    if (batchNum === 1) logUnownedProducts_(rows);

    // 取得に失敗した件は処理済みに記録しない。記録すると「やれることは全部やった」印になり、
    // 翌日 CSAF が取れても、記録した日付（＝RSS の pubDate）と CSAF の日付が一致してしまって
    // 台帳に載らない。新着は両者が同じ日であることが多く、実際に踏み得る経路。
    // CSAF が存在しないと確定した 404 だけは記録し、毎日の再処理を止める。
    const recordable = todo.filter(function (f) { return !f.error || f.missing; })
      .map(function (f) {
        if (!f.error) return f;
        // CSAF を読めていないまま記録する行（＝未作成と確定した 404）。
        // 版の欄を空にせず印を置く。後日 CSAF が公開されれば "未取得" ≠ "0" で必ず拾える。
        return { item: f.item, csaf: f.csaf, updatedAt: f.updatedAt,
                 version: STATE_VERSION_UNAVAILABLE, error: f.error, missing: f.missing };
      });
    writeState_(VENDOR_FORTINET, recordable, rows, assets);

    const ledgerRows = rows.filter(function (r) { return isLedgerRow_(r, assets); });
    Logger.log('Fortinet 台帳: ' + ledgerRows.length + ' / ' + rows.length + ' 行');

    fillLedgerDisplay_(ledgerRows);

    writeLedger_(ledgerRows);
    allLedgerRows = allLedgerRows.concat(ledgerRows);

    if (todo.length >= pending.length) break;
  }

  if (allLedgerRows.length) sortLedger_();

  addVendorStats_(VENDOR_FORTINET, {
    rss: allItems.length,
    fetched: fetched.length,
    ok: fetched.filter(function (f) { return !f.error; }).length,
    missing: fetched.filter(function (f) { return f.missing; }).length,
    failed: fetched.filter(function (f) { return f.error && !f.missing; }).length,
    processed: processedCount,
    ledger: allLedgerRows.length,
    mode: 'all'
  });

  return allLedgerRows;
}

/**
 * 台帳に載せる行かどうか。
 *
 * 載せるのは、自社が保有している製品で OS 該当が「対象」または「不明」の行。
 * 製品不明・非保有・OS対象外は台帳に出さない（処理済みシートには残る）。
 *
 * 自社影響が「なし」でも、版が影響範囲内なら台帳に残す。
 * 社内ルールで臨時更新しないと判断した記録そのものが監査で必要になる。
 * 通知から外れるだけで、台帳から消えるわけではない。
 *
 * ただし古い「なし」は落とす。定期更新で解消済みの行が積み上がると、
 * 判断が必要な行が埋もれて台帳を開かなくなる（KEEP_OUT_OF_SCOPE_MONTHS）。
 * 落としても処理済みシートには全件残るので、取得した事実は消えない。
 */
function isLedgerRow_(row, assets) {
  if (!row.product) return false;
  if (!assetsForProduct_(assets, row.product).length) return false;
  if (row.osStatus === '対象外') return false;
  if (row.verdict === V_NONE && isStaleOutOfScope_(row.pubDate)) return false;
  return true;
}

/**
 * 台帳の表示列（影響機能・確認方法・ユーザ影響）を埋め、保留中の判定を確定させる。
 *
 * ルールゲートで「なし」に落ちた行は AI を呼ばず、コードのフォールバックだけで埋める。
 * 影響機能を分類しても結論が変わらない行に API を使う理由がない。
 * ただし列を空にはしない。空欄だと「AI が失敗した行」と区別できなくなる。
 */
function fillLedgerDisplay_(rows) {
  const needAi = rows.filter(function (r) { return r.needsVerdict || r.needsDisplayAi; });
  const codeOnly = rows.filter(function (r) { return r.needsCodeDisplay; });
  if (!needAi.length && !codeOnly.length) return;

  if (needAi.length) {
    try {
      enrichWithAI_(needAi);
    } catch (e) {
      Logger.log('AI 生成に失敗しました。フォールバックで表示列を埋めます: ' + e);
    }
  }
  if (codeOnly.length) {
    Logger.log('ルールゲートで「なし」に確定した ' + codeOnly.length + ' 行は AI を呼びません。');
  }

  needAi.concat(codeOnly).forEach(function (r) {
    applyFallbackDisplayFields_(r);
    if (r.needsVerdict && !r._lockedVerdict) finalizeVerdict_(r);
    else if (r.feature && r.feature !== '—') r.reason = buildDecisionReason_(r);
    // finalize で影響機能が変わった場合に確認方法を合わせ直す
    r.howToCheck = normalizeHowToCheck_(r);
    r.cveSummaryJa = slackContentsJa_(r);
    r.impactJa = preferImpactJa_(r);
  });
}

/**
 * AI のユーザ影響を採用しつつ、CVSS と明らかに矛盾する文はフォールバックへ戻す。
 */
function preferImpactJa_(row) {
  const ai = truncateJa_(row.impactJa || '', 50);
  const fb = truncateJa_(fallbackImpactJa_(row), 50);
  if (!ai) return fb;

  const parts = parseCvssCia_(row.vector);
  if (parts) {
    const takeoverWords = /掌握|乗っ取|改ざん|傍受/;
    const dosOnly = parts.C === 'N' && parts.I === 'N' && parts.A === 'H';
    if (dosOnly && takeoverWords.test(ai)) return fb;
    const fullCia = parts.C === 'H' && parts.I === 'H';
    if (fullCia && /停止|全断/.test(ai) && !takeoverWords.test(ai)) return fb;
    if (parts.A !== 'H' && /拠点の通信/.test(ai)) return fb;
  }
  if (isReloadDos_(row) && /応答停止/.test(ai) && !/再起動/.test(ai)) return fb;
  if (isMgmtPlaneDos_(row) && /拠点の通信/.test(ai)) return fb;
  return ai;
}

/** 「なし」を台帳から落としてよいほど古いか。 */
function isStaleOutOfScope_(pubDate) {
  if (!KEEP_OUT_OF_SCOPE_MONTHS) return false;
  if (!(pubDate instanceof Date) || isNaN(pubDate.getTime())) return false;

  const limit = new Date();
  limit.setMonth(limit.getMonth() - KEEP_OUT_OF_SCOPE_MONTHS);
  return pubDate < limit;
}

// ============================================================
// 0b. Cisco CSAF RSS（主）→ CSAF JSON / 通常RSS（補助）
// ============================================================

/** CSAF JSON の URL 組み立て保険。主経路は CSAF RSS の guid/link を使う */
const CISCO_CSAF_BASE = 'https://tools.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/';

function runCisco_() {
  const assets = ciscoAssets_(readAssets_());
  if (!assets.length) {
    Logger.log('Cisco: ツール対象の資産がありません。スキップします。');
    addVendorStats_(VENDOR_CISCO, { note: '資産に対象機器が無くスキップ' });
    return [];
  }

  recoverCiscoIfLedgerEmpty_();

  const allItems = fetchCiscoCsafRssItems_();
  const known0 = getKnownState_(VENDOR_CISCO);
  warnIfFeedOverflowed_(allItems, known0.dates, function (it) { return it.id; });

  const candidates = selectRssCsafCandidates_(allItems, known0, function (it) { return it.id; },
    function (it) { return it.pubDate; });
  Logger.log('Cisco CSAF RSS: 全 ' + allItems.length + ' 件 → CSAF 取得 ' + candidates.length +
             ' 件（残りは前回から更新なし。Cisco はフィードの日付が CSAF と一致するため差分のみ取得）');

  const fetched = fetchCiscoCsafBatch_(candidates);

  let allLedgerRows = [];
  let batchNum = 0;
  let processedCount = 0;

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
    processedCount += todo.length;
    batchNum++;
    Logger.log('Cisco 処理対象 ' + todo.length + ' 件' +
               (pending.length > todo.length ? '（未処理 ' + pending.length + ' 件・続きあり）' : ''));

    const revised = todo.filter(function (f) { return known.dates[f.item.id]; });
    if (revised.length) {
      removeRowsFor_(VENDOR_CISCO, revised.map(function (f) { return f.item.id; }));
    }

    let humanIndex = null;
    let rows = [];
    todo.forEach(function (f) {
      if (f.error) {
        Logger.log('Cisco CSAF 取得失敗: ' + f.item.id + ' / ' + f.error);
        if (!humanIndex) humanIndex = fetchCiscoHumanRssIndex_();
        const human = humanIndex[f.item.id] || {};
        const fallbackItem = {
          id: f.item.id,
          title: human.title || f.item.title,
          link: human.link || f.item.link || ciscoHumanAdvisoryUrl_(f.item.id),
          description: human.description || '',
          pubDate: human.pubDate || f.item.pubDate
        };
        const fb = extractCiscoRowFallback_(fallbackItem);
        if (fb) rows.push(fb);
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
    Logger.log('Cisco 全 ' + rows.length + ' 行: ' + V_ACT + ' ' + counts[V_ACT] +
               ' / ' + V_INVEST + ' ' + counts[V_INVEST] + ' / ' + V_NONE + ' ' + counts[V_NONE]);

    writeState_(VENDOR_CISCO, todo, rows, assets);

    const ledgerRows = rows.filter(function (r) { return isLedgerRow_(r, assets); });
    Logger.log('Cisco 台帳: ' + ledgerRows.length + ' / ' + rows.length + ' 行');

    fillLedgerDisplay_(ledgerRows);

    writeLedger_(ledgerRows);
    allLedgerRows = allLedgerRows.concat(ledgerRows);

    if (todo.length >= pending.length) break;
  }

  if (allLedgerRows.length) {
    sortLedger_();
    clearCiscoEmptyRetryMark_();
  }

  addVendorStats_(VENDOR_CISCO, {
    rss: allItems.length,
    fetched: fetched.length,
    ok: fetched.filter(function (f) { return !f.error; }).length,
    failed: fetched.filter(function (f) { return f.error; }).length,
    processed: processedCount,
    ledger: allLedgerRows.length
  });

  return allLedgerRows;
}

function fetchCiscoCsaf_(itemOrId) {
  // CSAF RSS の guid/link があればそれを使う。無ければ旧来の URL 組み立てに落とす。
  let url = '';
  let id = '';
  if (itemOrId && typeof itemOrId === 'object') {
    id = String(itemOrId.id || '').trim();
    url = String(itemOrId.csafUrl || '').trim();
  } else {
    id = String(itemOrId || '').trim();
  }
  if (!url && id) {
    url = CISCO_CSAF_BASE + id + '/csaf/' + id + '_csaf.json';
  }
  if (!url) throw new Error('CSAF URL が空です');

  const res = UrlFetchApp.fetch(url, { muteHttpExceptions: true, followRedirects: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('HTTP ' + res.getResponseCode() + ' / ' + url);
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
    const v = ciscoVersionFromName_(idMap[id]);
    if (v) pushUnique_(versions, v);
  });
  return versions;
}

/** "17.15.5" または "Cisco IOS XE Software 17.15.5" から版番号を取る。 */
function ciscoVersionFromName_(name) {
  const s = String(name || '').trim();
  if (!s) return '';
  if (/^\d+\.\d+/.test(s)) return s;
  const m = /(\d+\.\d+(?:\.\d+)?[a-z]?)\s*$/i.exec(s);
  return m ? m[1] : '';
}

/**
 * CSAF の product_status から修正版の版番号を抜き出す。
 *
 * Cisco の CSAF に修正版が入っていることは稀で、多くは空配列が返る。
 * remediations の details から数字を拾う実装にしていたが、あの文面は
 * "Cisco has released software updates that address this vulnerability"
 * のような定型文で、拾えた数字はたまたま含まれた別の値でしかなかった。
 * 更新先として読まれる列に推測値を出すのは誤誘導なので、そこは見ない。
 * 版番号は CSAF に稀に入っている場合だけ。通常は人が Software Checker で確認する。
 * （openVuln は Key 自体は有効だが、GAS の UrlFetch が id.cisco.com で Access Denied になるため使わない）
 */
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
  return sortVersionsAsc_(versions);
}

function sortVersionsAsc_(versions) {
  return versions.slice().sort(function (a, b) {
    return compareVersion_(parseVersion_(a) || [0], parseVersion_(b) || [0]);
  });
}

/**
 * Workarounds note を、設定コマンドと説明文に分けて取り出す。
 *
 * 「回避策あり」と書くだけでは何をすればよいか分からない。逆に note 全文を
 * 台帳に載せると英語の長文になって読まれない。そこで役割を分ける。
 *   コマンド行 … コードで抽出してそのまま台帳に載せる（訳す必要がない）
 *   説明文     … AI に渡して日本語の要点にする
 *
 * 免責文（"While this mitigation has been deployed..." 以降）は落とす。
 * あれは運用上の注意で、何をするかの情報を含まない。
 *
 * @return {{cmds: string[], text: string, none: boolean}}
 */
function ciscoWorkaround_(csaf) {
  const notes = ((csaf.document || {}).notes) || [];
  const raw = notes.filter(function (n) {
    return String(n.title || '').toLowerCase().indexOf('workaround') !== -1;
  }).map(function (n) { return String(n.text || ''); }).join('\n');

  if (!raw) return { cmds: [], text: '', none: false };

  // 「There are no workarounds」の直後に mitigation（緩和策コマンド）が続くことがある。
  // 先に none で return すると緩和策を落とすので、コマンド抽出を先に行う。
  const body = raw.split(/While this mitigation/i)[0];
  const cmds = [];
  const prose = [];
  body.split(/\r?\n/).forEach(function (line) {
    const t = line.trim();
    if (!t) return;
    if (t.length <= 80 && isCiscoConfigCommand_(t)) pushUnique_(cmds, t);
    else prose.push(t);
  });

  if (/there are no workarounds/i.test(raw) && !cmds.length) {
    return { cmds: [], text: '', none: true };
  }

  return {
    cmds: cmds.slice(0, 4),
    text: prose.join(' ').slice(0, 600),
    none: false
  };
}

/** 行頭が IOS の設定構文か。訳さずそのまま載せてよい行の判別に使う。 */
function isCiscoConfigCommand_(line) {
  return /^(no\s|ip\s|ipv6\s|interface\s|line\s|snmp-server\s|service\s|access-list\s|transport\s|shutdown\b|config-|router\s|control-plane\b|class-map\s|policy-map\s)/i
    .test(line);
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

/**
 * 処理済みシートの「対象製品」に書く製品名を CSAF から取り出す。
 *
 * 台帳用の ciscoTargetProducts_ とは目的が違う。あちらは「自社資産のどれに当たるか」を
 * 資産シート起点で絞り込むので、自社に関係ないアドバイザリでは空になる。
 * 処理済みシートはベンダーが公表した全件の記録（分母）なので、
 * 自社保有と無関係に「何の製品の脆弱性か」が読めないと、
 * 後から「なぜこれは台帳に無いのか」を説明できない。
 *
 * 版番号の葉には降りない（"17.2.10" だけ並んでも読めない）。
 * Cisco の CSAF は「Cisco Secure Endpoint が Apple macOS 上に入っている」形で
 * 同梱先の OS も持つため、Cisco 製品名があればそちらを優先する。
 * 実測: RSS 50 件すべてで製品名を取得できた。
 */
function ciscoCsafProductNames_(csaf) {
  const out = [];
  function walk(b) {
    if (!b) return;
    const cat = String(b.category || '');
    if ((cat === 'product_family' || cat === 'product_name') && b.name) {
      const n = String(b.name).trim();
      if (n) pushUnique_(out, n);
      return;
    }
    (b.branches || []).forEach(walk);
  }
  (((csaf || {}).product_tree || {}).branches || []).forEach(walk);

  const cisco = out.filter(function (n) { return /^cisco/i.test(n); });
  const names = cisco.length ? cisco : out;

  // 15 製品並ぶ例があり、そのままだとセルが読めなくなる。
  if (names.length > 5) {
    return names.slice(0, 5).concat(['他 ' + (names.length - 5) + ' 製品']);
  }
  return names;
}

function ciscoProductTreeNames_(csaf) {
  const names = [];
  function walk(branch) {
    if (!branch) return;
    // 葉の product.name は版番号が多い。親の Cisco IOS XE Software も拾う。
    if (branch.name) pushUnique_(names, branch.name);
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
 * 事前告知（notice / informational）は脆弱性ではないので行を作らない
 * （処理済みシートには書くので再取得しない）。
 */
function extractCiscoRowsFromCsaf_(csaf, item, assets) {
  if (isCiscoInformationalAdvisory_(csaf, item)) {
    Logger.log('Cisco 情報通知（脆弱性ではない）のため台帳対象外: ' +
               ((item && item.id) || ''));
    return [];
  }
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

  // 修正版の自動取得（openVuln）は GAS では使わない。CSAF に版があれば使い、無ければ空。
  // 回避策コマンドは CSAF Workarounds から取る。
  const workaround = ciscoWorkaround_(csaf);

  if (!vulns.length) {
    // informational 以外で vulns が空は稀。フォールバック行は誤検知を増やすので作らない。
    Logger.log('Cisco vulnerabilities なし（台帳行なし）: ' + advisoryId);
    return [];
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
    // CSAF に fixed が入っている稀な場合だけ拾う。
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
      workaroundCmds: workaround.cmds,
      workaroundNone: workaround.none,
      summary: summary,
      impact: (v.threats || [])
        .filter(function (t) { return t.category === 'impact'; })
        .map(function (t) { return t.details; })
        .join(', '),
      fixesRaw: fixes.join('\n'),
      workaround: workaround.text,
      verdict: '', reason: '', selfVersion: '', fixVersion: '',
      feature: '', impactJa: '', howToCheck: '', plan: ''
    };
  });
}

/** CSAF 失敗時の保険（通常 RSS）。情報通知 ID は行にしない。 */
function extractCiscoRowFallback_(item) {
  if (isCiscoInformationalAdvisory_(null, item)) {
    Logger.log('Cisco 情報通知のためフォールバック行も作らない: ' + (item && item.id));
    return null;
  }
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
    verdict: V_INVEST,
    reason: 'CSAF を取得できず版比較できないため',
    selfVersion: '', fixVersion: '',
    feature: '', impactJa: '', howToCheck: '', plan: ''
  };
}

/**
 * Cisco の事前告知・情報通知か。
 * 例: cisco-sa-notice-* / category=csaf_informational_advisory
 * 「8/5 に公開予定のアドバイザリ一覧」であり、CVE の脆弱性情報ではない。
 */
function isCiscoInformationalAdvisory_(csaf, item) {
  const id = String(
    (csaf && csaf.document && csaf.document.tracking && csaf.document.tracking.id) ||
    (item && item.id) || ''
  ).trim();
  if (/^cisco-sa-notice-/i.test(id)) return true;

  const cat = String((csaf && csaf.document && csaf.document.category) || '').toLowerCase();
  if (cat.indexOf('informational') !== -1) return true;

  const title = String(
    (csaf && csaf.document && csaf.document.title) ||
    (item && item.title) || ''
  );
  if (/advance\s+notification/i.test(title)) return true;
  return false;
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

/**
 * Cisco CSAF RSS（主経路）。
 *
 * 通常 RSS と違い、guid/link に CSAF JSON の URL が直接入っている。
 * ID 抽出 → URL 組み立てをやめて、取得先の推測ミスをなくす。
 *
 * 通常 RSS はタイトル・概要・人向けページ URL の保険として別関数で読む。
 */
function fetchCiscoCsafRssItems_() {
  const res = UrlFetchApp.fetch(CISCO_CSAF_RSS_URL, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('Cisco CSAF RSS 取得失敗 HTTP ' + res.getResponseCode());
  }

  const root = XmlService.parse(res.getContentText()).getRootElement();
  const items = root.getChild('channel').getChildren('item');

  return items.map(function (item) {
    const title = String(item.getChildText('title') || '').trim();
    const guid = String(item.getChildText('guid') || '').trim();
    const link = String(item.getChildText('link') || '').trim();
    const csafUrl = normalizeCiscoCsafUrl_(guid || link);
    const id = parseCiscoAdvisoryId_(title || csafUrl || link);
    return {
      id: id,
      title: title || id,
      link: ciscoHumanAdvisoryUrl_(id),
      csafUrl: csafUrl,
      description: '',
      pubDate: parsePubDate_(item.getChildText('pubDate'))
    };
  }).filter(function (it) { return it.id && it.csafUrl; });
}

/** guid/link からクエリを落とし、https にそろえる */
function normalizeCiscoCsafUrl_(raw) {
  let u = String(raw || '').trim();
  if (!u) return '';
  u = u.replace(/^http:\/\//i, 'https://').replace(/:80\//, '/');
  const q = u.indexOf('?');
  if (q !== -1) u = u.slice(0, q);
  return /\.json$/i.test(u) ? u : '';
}

/** 人向けアドバイザリページ。台帳のハイパーリンク用 */
function ciscoHumanAdvisoryUrl_(advisoryId) {
  const id = String(advisoryId || '').trim();
  if (!id) return '';
  return 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/' + id;
}

/**
 * 通常 RSS（補助）。CSAF 取得失敗時にタイトル・概要を補う。
 * 主経路ではないので失敗しても空オブジェクトを返す。
 */
function fetchCiscoHumanRssIndex_() {
  try {
    const res = UrlFetchApp.fetch(CISCO_RSS_URL, { muteHttpExceptions: true });
    if (res.getResponseCode() !== 200) return {};
    const root = XmlService.parse(res.getContentText()).getRootElement();
    const items = root.getChild('channel').getChildren('item');
    const map = {};
    items.forEach(function (item) {
      const link = item.getChildText('link') || '';
      const id = parseCiscoAdvisoryId_(link);
      if (!id) return;
      map[id] = {
        title: item.getChildText('title') || '',
        link: link,
        description: item.getChildText('description') || '',
        pubDate: parsePubDate_(item.getChildText('pubDate'))
      };
    });
    return map;
  } catch (e) {
    Logger.log('Cisco 通常 RSS（補助）取得失敗: ' + e);
    return {};
  }
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
  const items = fetchCiscoCsafRssItems_();
  const assets = ciscoAssets_(readAssets_());
  const known = getKnownState_(VENDOR_CISCO);
  Logger.log('Cisco CSAF RSS 件数: ' + items.length + ' / 資産: ' + assets.length + ' 件');
  if (items[0]) {
    Logger.log('先頭例: ' + items[0].id + ' / csafUrl=' + items[0].csafUrl);
  }
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
      Logger.log('  展開失敗 ' + f.item.id + ': ' + e);
    }
  });
  Logger.log('資産にヒットした候補（先頭10件中）: ' + hit + ' 件');
}

// ============================================================
// 1. RSS 取得と CSAF の URL 導出
// ============================================================

/**
 * "Tue, 14 Jul 2026 00:00:00 -0700" や CSAF RSS の "2026-08-21 16:54:40.0" を Date にする。
 * 失敗したら元の文字列を返す。
 */
function parsePubDate_(s) {
  if (!s) return '';
  const raw = String(s).trim();
  // CSAF RSS: "2026-08-21 16:54:40.0"
  const cisco = /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/.exec(raw);
  if (cisco) {
    const d = new Date(cisco[1] + 'T' + cisco[2] + 'Z');
    if (!isNaN(d.getTime())) return d;
  }
  const d = new Date(raw);
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
 * CSAF を 1 件取得する（単体確認用。日次実行は fetchAllCsaf_ を使う）。
 *
 * かつては失敗時にアドバイザリ HTML から csaf_url を拾う「保険」を持っていたが、
 * その経路は成立しないため削除した。fortiguard.fortinet.com のアドバイザリページは
 * JS で描画され、HTML 中に文字列 "csaf" は 1 度も現れない（altcha によるボット対策も入る）。
 * 残しておくと、失敗のたびに無駄なリクエストを 2 本増やしたうえ、
 * 「取りこぼしても回復手段がある」という誤解だけが残る。
 */
function fetchCsaf_(item) {
  const url = csafUrlFor_(item);
  const res = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('CSAF 取得失敗 HTTP ' + res.getResponseCode() + ': ' + url);
  }
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
 * RSS のうち CSAF を取りに行く候補を選ぶ（現在は Cisco 専用）。
 *
 * この絞り込みは「フィードの日付が CSAF の更新を反映している」ことが前提。
 * Cisco の csaf_20.xml は CSAF から生成されているため前提が成り立つ。
 * Fortinet の ir.xml は成り立たないことが実測で分かったので、Fortinet はこの関数を
 * 使わず毎回全件を取得する（理由は runFortinet_ のコメント）。
 *
 * 取得する:
 *   - 処理済みに無い ID（初出。RSS に載っている限り古くても取得）
 *   - RSS 日付が処理済みの CSAF 最終更新日より新しい（改訂の可能性）
 *   - CSAF 版が未記録の既存行（＝前回の取得に失敗した件。実質のリトライ）
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

/**
 * CSAF 取得後、台帳へ反映するか（最終更新日・版で判定）。
 *
 * hasError は CSAF を取得できなかったことを表す。記録済みの件なら何もしない。
 * CSAF が読めていない以上、台帳を書き換える材料が無いし、
 * 取得できなかった日付（RSS の pubDate で代用している）で比較しても意味がない。
 * 未記録なら true を返し、取得できなかった事実をログに出す経路へ回す。
 */
function needsAdvisoryProcessing_(id, csafDate, csafVersion, known, hasError) {
  if (hasError && known.dates[id]) return false;
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
      const csaf = fetchCiscoCsaf_(it);
      return {
        item: it,
        csaf: csaf,
        updatedAt: csafUpdatedAt_(csaf, it),
        version: csafTrackingVersion_(csaf),
        products: ciscoCsafProductNames_(csaf),
        error: ''
      };
    } catch (e) {
      return { item: it, csaf: null, updatedAt: it.pubDate, version: '', error: String(e) };
    }
  });
}

/**
 * 指定 item の CSAF をまとめて取得する（Fortinet は RSS 全件を渡す）。
 *
 * UrlFetchApp.fetchAll() は複数リクエストを並行して投げるため、
 * 1 件ずつ fetch するより大幅に速い（実測: 約 50 件で 5 秒）。
 *
 * 応答は 3 つに分ける。同じ「取れなかった」でも扱いが違うため。
 *   200      成功
 *   404      CSAF未作成。Fortinet が CSAF を出し始めたのは 2025 年 3 月頃で、それ以前の
 *            アドバイザリには CSAF が遡って作られていない。改訂されると RSS には載るが
 *            CSAF は無いまま（例: FG-IR-22-059）。存在しないものを毎日待っても仕方がないので、
 *            処理済みに記録して再処理を止める（missing: true）。
 *   その他    一時的な失敗として扱う。処理済みには記録せず、翌日の実行で取り直す。
 *
 * 戻り値: [{ item, csaf, updatedAt, version, error, missing }]
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
  let missing = 0;
  let failed = 0;

  const out = items.map(function (it, i) {
    const r = res[i];
    const code = r ? r.getResponseCode() : 0;

    if (code === 200) {
      try {
        const csaf = JSON.parse(r.getContentText());
        ok++;
        return { item: it, csaf: csaf, updatedAt: csafUpdatedAt_(csaf, it),
          version: csafTrackingVersion_(csaf), error: '', missing: false };
      } catch (e) {
        failed++;
        return { item: it, csaf: null, updatedAt: it.pubDate, version: '',
          error: 'CSAF の解析に失敗: ' + e, missing: false };
      }
    }

    if (code === 404) {
      missing++;
      return { item: it, csaf: null, updatedAt: it.pubDate, version: '',
        error: 'CSAF未作成（HTTP 404。ベンダーがこのアドバイザリの CSAF を出していない）',
        missing: true };
    }

    failed++;
    return { item: it, csaf: null, updatedAt: it.pubDate, version: '',
      error: 'CSAF 取得失敗 HTTP ' + code, missing: false };
  });

  Logger.log('CSAF 取得: 成功 ' + ok + ' / CSAF未作成 ' + missing + ' / 失敗 ' + failed +
             '（全 ' + items.length + ' 件）');
  if (failed) {
    Logger.log('  失敗した件は処理済みに記録していません。翌日の実行で取り直します。');
  }
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
    verdict: V_INVEST,
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
    workaround: '',     verdict: V_INVEST,
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
        note: String(r[7] || '').trim(),
        updatedAt: r[8] || ''
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
  row.needsVerdict = false;
  row.needsDisplayAi = false;
  row.needsCodeDisplay = false;
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
 * 当てはまらなければ「その他」（機能を特定できないので影響調査に回る）。
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
    [/web.?ui|fortigate ui|\bgui\b|management\s*(interface|console)|admin\s*portal/, '管理GUI'],
    [/resource\s*exhaust/, '管理GUI'],
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
    if (!isFortinetFeatureVocab_(row.feature) || row.feature === 'その他' || row.feature === '不明') {
      const guessed = guessFortinetFeature_(row);
      if (guessed && guessed !== 'その他') row.feature = guessed;
      else if (!isFortinetFeatureVocab_(row.feature)) row.feature = guessed;
    }
  } else {
    const fromTitle = normalizeCiscoFeature_(row.title || '');
    if (isJunkCiscoFeature_(row.feature)) {
      row.feature = fromTitle;
    } else {
      row.feature = normalizeCiscoFeature_(row.feature || row.title || '');
    }
  }

  row.howToCheck = normalizeHowToCheck_(row);
  if (!isUsableCveSummary_(row.cveSummaryJa)) {
    row.cveSummaryJa = '';
  }
  row.impactJa = preferImpactJa_(row);
}

function truncateJa_(s, max) {
  const t = String(s || '').trim().replace(/\s+/g, ' ');
  if (!t) return '';
  return t.length > max ? t.slice(0, max) : t;
}

/** 英語タイトルコピーをやめ、アドバイザリ本文と CVSS から業務結果を引く */
function fallbackImpactJa_(row) {
  const parts = parseCvssCia_(row.vector);
  if (parts) {
    if (parts.C === 'H' && parts.I === 'H') {
      return '機器を乗っ取られ設定改ざんや通信傍受をされる恐れ';
    }
    if (parts.C === 'H' && parts.I !== 'H') {
      return '機微な管理情報や通信内容が外部に漏れる恐れ';
    }
    if (parts.I === 'H' && parts.C !== 'H') {
      return '設定を改ざんされ意図しない通信経路を作られる恐れ';
    }
  }

  if (isReloadDos_(row) || (parts && parts.A === 'H')) {
    return isReloadDos_(row)
      ? '機器が再起動し、拠点の通信が途切れる恐れ'
      : '機器が停止し、拠点の通信が途切れる恐れ';
  }
  if (isMgmtPlaneDos_(row) || (parts && parts.A === 'L')) {
    return '管理画面が応答しなくなり、運用に支障が出る恐れ';
  }

  const text = advisoryCorpus_(row).toLowerCase();
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

function advisoryCorpus_(r) {
  return [r.title, r.summary, r.impact, r.feature].join('\n');
}

function isReloadDos_(r) {
  return /reload|reboot|unexpected(ly)? (reload|reboot)/i.test(advisoryCorpus_(r));
}

function isResourceExhaustion_(r) {
  return /resource exhaustion|without limits or throttling|allocation of resources/i.test(advisoryCorpus_(r));
}

function isMgmtPlaneDos_(r) {
  const f = String(r.feature || '');
  if (f === '管理GUI' || f === 'WebUI') return true;
  return /web ui|webui|fortigate ui|\bgui\b|management (interface|plane)/i.test(advisoryCorpus_(r))
    || isResourceExhaustion_(r);
}

/** CVSS ベクターから C/I/A を取る。無ければ null */
function parseCvssCia_(vector) {
  const s = String(vector || '');
  if (!s) return null;
  const C = (/\/C:([NHAL])/i.exec(s) || [])[1];
  const I = (/\/I:([NHAL])/i.exec(s) || [])[1];
  const A = (/\/A:([NHAL])/i.exec(s) || [])[1];
  if (!C && !I && !A) return null;
  return {
    C: (C || 'N').toUpperCase(),
    I: (I || 'N').toUpperCase(),
    A: (A || 'N').toUpperCase()
  };
}

function normalizeCiscoFeature_(raw) {
  let s = String(raw || '').trim().replace(/\s+/g, ' ');
  if (!s) return 'IOS XE 基盤';
  s = s.replace(/^Cisco\s+IOS\s*XE\s+Software\s*/i, '');
  s = s.replace(/^Cisco\s+IOS\s*XE\s*/i, '');
  s = s.replace(/^IOS\s*XE\s+Software\s*/i, '');
  if (/security hardening/i.test(s) || !s) return 'IOS XE 基盤';
  if (/web-based|webui|http server|web.?ui|management interface/i.test(s)) return 'WebUI';
  if (/blocks extensible|beep/i.test(s)) return 'BEEP';
  if (/extensible messaging|xmcp/i.test(s)) return 'XMCP Server';
  if (/sd-?wan/i.test(s)) return 'SD-WAN';
  if (/snmp/i.test(s)) return 'SNMP';
  if (/\bssh\b/i.test(s)) return 'SSH';
  if (/core/i.test(s)) return 'IOS XE 基盤';
  if (s.length > 20) s = s.slice(0, 20);
  return s || 'IOS XE 基盤';
}

/** AI が返した英語切れ端・ID っぽい影響機能か */
function isJunkCiscoFeature_(feature) {
  const s = String(feature || '').trim();
  if (!s || s === '不明') return true;
  if (/^cisco-sa-/i.test(s)) return true;
  const known = {
    'WebUI': 1, 'BEEP': 1, 'XMCP Server': 1, 'SD-WAN': 1,
    'SNMP': 1, 'SSH': 1, 'IOS XE 基盤': 1
  };
  if (known[s]) return false;
  // タイトル断片（英単語の切れ端）は統制語彙ではない
  if (/^[A-Za-z]/.test(s) && /\s/.test(s)) return true;
  if (/^[A-Za-z].{0,3}$/.test(s)) return true;
  return false;
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
  // 影響調査中に「臨時対応不要・定期更新枠」を出すと手がかりにならない
  if (row.verdict === V_INVEST) return CHECK_STEPS_CISCO_INVEST;
  return CHECK_STEPS_CISCO_DEFAULT;
}

/** 確認方法が行動可能か検証し、不合格なら機能別テーブルで差し替える */
function normalizeHowToCheck_(row) {
  const raw = String(row.howToCheck || '').trim();
  // 版該否は decideNotification_ 済み。対象行に「show version」を出さない。
  if (row.osStatus === '対象' && isVersionRecheckHowTo_(raw)) {
    return lookupCheckSteps_(row);
  }
  // 影響調査なのに定期更新定型だけ、は差し替え
  if (row.verdict === V_INVEST && isRegularUpdateHowTo_(raw)) {
    return lookupCheckSteps_(row);
  }
  return isActionableHowTo_(raw) ? raw : lookupCheckSteps_(row);
}

/** 「なし」向けの定期更新定型か */
function isRegularUpdateHowTo_(text) {
  return /定期更新枠|臨時対応は不要|次回メンテで更新すれば足りる/i.test(String(text || ''));
}

/** 版の再確認を求める確認方法か */
function isVersionRecheckHowTo_(text) {
  return /影響範囲内|稼働バージョン|show\s+version|get\s+system\s+status/i.test(String(text || ''));
}

/** 人が次の行動を取れる確認方法か（設定確認 or アクション提示） */
function isActionableHowTo_(text) {
  const raw = String(text || '').trim();
  if (!raw) return false;
  if (/アドバイザリの\s*(Affected|Fixed|Solution)|個別アドバイザリ|公開情報と対象バージョン/i.test(raw)) {
    return false;
  }
  const hasJudge = /判断[：:]/.test(raw);
  const hasCmd = /コマンド[：:]/.test(raw) && /(show|get|diagnose)\b/i.test(raw);
  const hasAction = /アクション[：:]/.test(raw);
  return hasJudge && (hasCmd || hasAction);
}

/**
 * 台帳に出す直前にラベルを外す。
 *
 * ラベルは AI 出力の検証に必要なので生成側では残す。ただしセルに並べると
 * 全行の同じ位置に同じ4文字が3回ずつ出て、読みたい中身より先に目に入る。
 * 3行の位置そのものが「どこを見る／何を打つ／どう判断する」を示すので、
 * 表示では見出しを落として中身だけ残す。
 */
function stripCheckLabels_(text) {
  return String(text || '')
    .split('\n')
    .map(function (line) {
      return line.replace(/^\s*(?:確認ポイント|コマンド|アクション|判断)\s*[：:]\s*/, '').trim();
    })
    .filter(function (line) { return line; })
    .join('\n');
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

/**
 * 判定根拠は2行にする。
 * 1行目は構造化された値、2行目は理由と結論。
 * 同じ区切り文字で並べると、文章もフィールドとして読まれて頭に入らない。
 */
function buildDecisionReason_(row) {
  const head = 'OS=' + (row.osStatus || '不明') + ' | KEV=' + (row.kev || KEV_NO);
  const tail = (row.reasonPhrase || '判定材料が不足しているため')
             + '「' + (row.verdict || V_INVEST) + '」';
  return head + '\n' + tail;
}

/**
 * 社内ルールの「定期更新まで待つ根拠」のうち、CVSS ベクターだけで判定できる分。
 *
 * 深刻度では切らない。切るのは到達性と前提条件である。
 * 9.8 でも管理者権限が前提なら、悪用できる者は既に機器を掌握している。
 *
 * @return {{pass: boolean, phrase: string}} pass=false なら定期更新で足りる
 */
function ruleGate_(row) {
  const v = String(row.vector || '');
  if (!v) {
    return { pass: true, phrase: '' };   // ベクター無しは断定できないので調査へ回す
  }
  if (/PR:H/.test(v)) return { pass: false, phrase: '悪用に管理者権限が必要なため' };
  if (/PR:L/.test(v)) return { pass: false, phrase: '悪用に認証済みアカウントが必要なため' };
  if (/AV:P/.test(v)) return { pass: false, phrase: '悪用に機器への物理アクセスが必要なため' };
  if (/AV:L/.test(v)) return { pass: false, phrase: '悪用に機器へのローカルアクセスが必要なため' };
  if (/AV:A/.test(v)) return { pass: false, phrase: '悪用に隣接ネットワークからのアクセスが必要なため' };
  if (/UI:R/.test(v)) return { pass: false, phrase: '悪用に利用者の操作が必要なため' };
  return { pass: true, phrase: '' };
}

/**
 * 影響機能が設定に依存するか。
 *
 *   disabled 自社で無効と断定できる       → なし
 *   config   有効かどうかが設定次第       → 影響調査（人がコマンドで確認）
 *   always   設定に関係なく常に有効       → 影響の重さで判定
 *   unknown  機能を特定できていない       → 影響調査
 *
 * CHECK_STEPS_FORTINET / CHECK_STEPS_CISCO のキーと対応させる。
 * 確認方法に「出力があれば対応が必要」と書くなら、判定は config でなければ嘘になる。
 */
const FEATURE_CONFIG_DEPENDENT = {
  '管理GUI': true, 'SSH': true, 'IPsec VPN': true, 'SSL-VPN': true,
  'Webフィルタ': true, 'SSLインスペクション': true,
  'IPSエンジン': true, 'アンチウイルスエンジン': true,
  'WebUI': true, 'BEEP': true, 'XMCP Server': true, 'SNMP': true, 'SD-WAN': true
};

const FEATURE_ALWAYS_ON = {
  'データプレーン': true, 'IOS XE 基盤': true
};

function featureExposure_(row) {
  const f = String(row.feature || '').trim();
  if (f === 'SSL-VPN' && !SSL_VPN_ENABLED) return 'disabled';
  if (FEATURE_ALWAYS_ON[f]) return 'always';
  if (FEATURE_CONFIG_DEPENDENT[f]) return 'config';
  return 'unknown';
}

/** 悪用されたとき機器掌握または業務停止に至るか（臨時更新条件4） */
function isSevereImpact_(row) {
  if (row.takeover === 'total') return true;
  if (row.serviceStop === 'はい') return true;
  const text = [row.impact, row.title].join(' ').toLowerCase();
  return /remote code|code execution|\brce\b|arbitrary code|command injection|denial of service|\bdos\b/.test(text);
}

/**
 * 自社影響の確定。ベンダー差は featureExposure_ の語彙だけに閉じ込める。
 * AI の後に呼ぶこと（影響機能が決まっていないと判定できない）。
 *
 * ルールゲートは decideNotification_ で先に当たっており、通常ここへ来る行は通過済み。
 * それでも同じ ruleGate_ を呼ぶのは、この関数単体で社内ルール全体を表現しておくため。
 * 判定の入口が2つあると、片方だけ直して食い違う。
 */
function finalizeVerdict_(row, opts) {
  row.vendorPath = row.vendor === VENDOR_CISCO ? 'Cisco' : 'Fortinet';
  if (!opts || !opts.skipKev) {
    row.kev = kevLabel_(row.cve);
  }
  row.osStatus = row.osStatus || '対象';

  if (row.vendor === VENDOR_FORTINET &&
      (!row.aiOk || !isFortinetFeatureVocab_(row.feature) || row.aiConfidence === 'low')) {
    row.feature = guessFortinetFeature_(row);
    if (!row.aiTechImpact) row.aiTechImpact = '不明';
  }

  row.takeover = row.aiTechImpact || '不明';
  row.serviceStop = normalizeServiceStop_(row.aiServiceStop);
  row.externalSurface = isOnExternalSurface_(row.feature) ? 'はい' : 'いいえ';

  const gate = ruleGate_(row);
  const exposure = featureExposure_(row);

  // KEV は件数が稀すぎて主軸にならないが、悪用実績があるものを
  // 「使っていないはず」で流すとルール全体の信頼性が崩れる。最低ラインを調査に固定する。
  if (row.kev === KEV_YES) {
    if (exposure === 'always' && gate.pass && isSevereImpact_(row)) {
      row.verdict = V_ACT;
      row.reasonPhrase = '悪用が確認されており外部から到達するため';
    } else {
      row.verdict = V_INVEST;
      row.reasonPhrase = '悪用が確認されているため';
    }
    row.reason = buildDecisionReason_(row);
    return;
  }

  if (!gate.pass) {
    row.verdict = V_NONE;
    row.reasonPhrase = gate.phrase;
    row.reason = buildDecisionReason_(row);
    return;
  }

  if (exposure === 'disabled') {
    row.verdict = V_NONE;
    row.reasonPhrase = row.feature + ' を自社で無効にしているため';
  } else if (exposure === 'config') {
    row.verdict = V_INVEST;
    row.reasonPhrase = row.feature + ' の利用有無が設定次第のため';
  } else if (exposure === 'unknown') {
    row.verdict = V_INVEST;
    row.reasonPhrase = '影響機能を特定できないため';
  } else if (isSevereImpact_(row)) {
    row.verdict = V_ACT;
    row.reasonPhrase = '外部から無認証で' + row.feature + 'を悪用され機器掌握または業務停止に至るため';
  } else {
    row.verdict = V_NONE;
    row.reasonPhrase = '掌握にも業務停止にも至らないため';
  }
  row.reason = buildDecisionReason_(row);
}

/**
 * AI を呼ばずに結論が出る分をここで確定させる。
 *
 * 確定できるのは3種類。
 *   非保有・製品不明   資産シートだけで決まる
 *   版が影響範囲外     CSAF と資産シートの版比較だけで決まる
 *   ルールゲート落ち   CVSS ベクターだけで決まる（§3 の待てる根拠）
 *
 * ゲート落ちを AI の前に置くのは、影響機能を知る必要が無いから。
 * `PR:H` の行の影響機能を分類しても結論は変わらないので、その分の API を使わない。
 * 残った行（外部から無認証で悪用できる行）だけ AI へ回し、finalizeVerdict_ で確定する。
 *
 * ベンダーで分岐しない（Cisco も設定次第の機能を持つので同じ扱いにする）。
 */
function decideNotification_(row, assets) {
  if (row._lockedVerdict) return;

  initDecisionFields_(row);
  row.fixVersion = pickFixVersion_(row);

  if (!row.product) {
    row.verdict = V_INVEST;
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
    row.verdict = V_NONE;
    row.osStatus = '対象外';
    row.kev = kevLabel_(row.cve);
    row.reasonPhrase = row.product + ' を自社で使用していないため';
    row.reason = buildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  const os = judgeOsApplicability_(row, assets);
  row.osStatus = os.label;
  row.vendorPath = (row.vendor === VENDOR_CISCO) ? 'Cisco' : 'Fortinet';

  if (os.os === 'out') {
    row.verdict = V_NONE;
    row.kev = kevLabel_(row.cve);
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
    row.verdict = V_INVEST;
    row.kev = kevLabel_(row.cve);
    row.reasonPhrase = '自社利用バージョンを判定できないため';
    row.needsDisplayAi = true;
    row.reason = buildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  // 版が影響範囲内。ここから社内ルールを当てる。
  row.kev = kevLabel_(row.cve);

  const gate = ruleGate_(row);
  if (!gate.pass) {
    // KEV 掲載は最低ラインを調査に固定する例外。ゲートで落とさない。
    if (row.kev === KEV_YES) {
      row.verdict = V_INVEST;
      row.reasonPhrase = '悪用が確認されているため';
      row.needsDisplayAi = true;
    } else {
      row.verdict = V_NONE;
      row.reasonPhrase = gate.phrase;
      // 表示列はコードのフォールバックで埋める。AI は呼ばない。
      row.needsCodeDisplay = true;
    }
    row.reason = buildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  // 影響機能が決まらないと判定できないので AI へ回す。
  row.needsFortinetAi = (row.vendor === VENDOR_FORTINET);
  row.needsVerdict = true;
  row.needsDisplayAi = true;
  row.verdict = V_INVEST;
  row.reasonPhrase = '影響機能を確認中のため';
  row.reason = buildDecisionReason_(row);
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
    if (r.verdict === V_NONE && r.reason.indexOf('使用していない') !== -1) {
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

/**
 * 台帳の公式推奨対応列用。英語を残さない。プレーンテキストのみ（リンクは付けない）。
 *
 * Cisco:
 *   - 修正版（稀に CSAF にある）または回避策コマンドがあればそれを出す
 *   - どちらも無いとき（GAS では openVuln 不可）は「更新先はアドバイザリで確認」
 *   - 「回避策なし」は CSAF Workarounds の公式文 "There are no workarounds..." の訳
 */
function formatOfficialAction_(row) {
  if (row.vendor !== VENDOR_CISCO) {
    const fix = jpFix_(row);
    return fix ? jpFixEnglishFallback_(fix) : '';
  }

  const lines = [];
  const vers = row.fixedVersions || [];
  if (vers.length) lines.push(vers[0] + ' 以上に更新が必要');

  const cmds = row.workaroundCmds || [];
  const hint = truncateJa_(row.workaroundJa || '', 40);
  if (cmds.length) {
    lines.push('更新できない場合の回避策: ' + cmds.join(' / ')
             + (hint ? '（' + hint + '）' : ''));
  } else if (hint) {
    lines.push('更新できない場合の回避策: ' + hint);
  }

  if (lines.length) return lines.join('\n');

  if (row.workaroundNone) {
    return '回避策なし。更新先はアドバイザリで確認';
  }
  return '更新先はアドバイザリで確認';
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
  c[V_ACT] = 0; c[V_INVEST] = 0; c[V_NONE] = 0;
  rows.forEach(function (r) { if (c[r.verdict] !== undefined) c[r.verdict]++; });
  return c;
}

// ============================================================
// 5. AI による機能分類・確認方法（台帳表示列）
// ============================================================

function enrichWithAI_(rows) {
  const targets = rows.filter(function (r) {
    return r.needsVerdict || r.needsDisplayAi;
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
        r.impactJa = truncateJa_(pickAiField_(v, ['ユーザ影響', 'user_impact', 'impact_ja']) || '', 50);
        r.cveSummaryJa = truncateJa_(pickAiField_(v, ['内容要約', '脆弱性名和訳', 'cve_summary', 'summary_ja']) || '', 30);
        if (!r.cveSummaryJa) {
          Logger.log('AI 内容要約なし: ' + rowKey_(r));
        }
        r.howToCheck = v['確認方法'] || '';
        r.workaroundJa = truncateJa_(v['回避策'] || '', 40);
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
    if (i + AI_CHUNK_SIZE < targets.length) Utilities.sleep(1000);
  }

  Logger.log('AI 生成: ' + AI_PROVIDER + ' / 成功 ' + ok + ' / 対象 ' + targets.length + ' 行');
  if (!ok) {
    Logger.log('AI が0件のため、Slackの内容は公式タイトルの日本語訳、影響・確認方法はコード側の文面になります。');
  }
}

function rowKey_(r) {
  return r.advisoryId + '|' + r.cve + '|' + r.product;
}

function pickAiField_(obj, names) {
  if (!obj) return '';
  for (let i = 0; i < names.length; i++) {
    const v = obj[names[i]];
    if (v !== undefined && v !== null && String(v).trim()) return String(v).trim();
  }
  return '';
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
      CVSSスコア: r.cvss === '' || r.cvss === undefined ? '' : r.cvss,
      CVSSベクター: r.vector || '',
      OS該否: r.osStatus || '',
      自社利用バージョン: r.selfVersion,
      脆弱性の影響バージョン: (r.affected || []).join(' / '),
      ベンダー提示の緩和策: r.workaround || 'なし',
      ベンダー提示の回避コマンド: (r.workaroundCmds || []).join(' / ') || 'なし'
    };
  });

  return [
    'あなたは社内の情報システム担当者です。脆弱性について、',
    '人が読んで行動できる確認方法・最悪ケースの影響・機能分類を JSON で返してください。',
    '',
    '【禁止】',
    '- 最終判定（あり（対応検討）/ あり（影響調査）/ なし）を書かない',
    '- 自然文の判定根拠を書かない',
    '- set / execute / configure など変更系 CLI',
    '- 「アドバイザリを確認」だけなど、操作しても判断できない文言',
    '- アドバイザリに無い推測',
    '- OS該否が「対象」の行で、稼働バージョンや影響範囲の再確認（show version 等）を書かない',
    '- 複数行で同じ「内容要約」を使い回さない',
    '- 「あり（影響調査）」の行に「臨時対応は不要」「定期更新枠に載せる」だけを書かない',
    '  （調査の手掛かりになる設定確認か、影響条件の特定手順を書く）',
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
    '確認方法: 必ず次のいずれか。読んだ人が次の行動を決められること',
    '  (A) 設定次第の機能 → 3行「確認ポイント／コマンド／判断」',
    '      確認ポイント：〈何が有効なら影響を受けるか〉',
    '      コマンド：〈読み取り専用。Fortinet は show/get/diagnose。Cisco は show 系〉',
    '      判断：〈この出力なら対応が必要／この出力なら定期更新で可〉',
    '  (B) 版は対象済みで設定確認が無い行 → 3行「確認ポイント／アクション／判断」',
    '      確認ポイント：版は対象済み（追加の版確認は不要）',
    '      アクション：〈更新先の確認・定期更新枠への追加など、次にやること〉',
    '      判断：〈臨時対応が要る／定期更新で足りる〉',
    '  アドバイザリの記述に確認手順（Vulnerable Products / Determine 節）があれば、',
    '  設定確認はそのコマンドを優先。版の再確認だけは書かない。',
    '内容要約: Slack「内容」。アドバイザリの記述を読んで30字以内。CVEごとに必ず違う文。',
    '  「認証なし○で機器が応答停止」のような型は禁止。拠点全断などの業務影響は書かない（それはユーザ影響）。',
    'ユーザ影響: 悪用時の業務結果を50字以内。主語は機器または通信。機能名（BEEP等）は書かない。',
    '  CVSSベクターの C/I/A を反映する（C:N I:N A:H なら機器停止・通信途絶。掌握と書かない）。',
    '  同じ型なら同じ文でよい。差は内容要約で出す。',
    '回避策: 「ベンダー提示の緩和策」が「なし」以外なら、何をすると影響を止められるかを日本語40字以内。',
    '  コマンド自体は別に台帳へ載せるので繰り返さない。緩和策が「なし」なら空文字にすること',
    '',
    '出力は次の JSON 配列のみ。前置き・コードフェンスを含めないこと。',
    '[{"key":"FG-IR-26-154|CVE-2025-43892|FortiOS","affected_feature":"Webフィルタ",',
    '  "technical_impact":"partial","service_stop":false,"attack_position":"network",',
    '  "auth_required":"none","evidence":"CSAF記載","confidence":"high",',
    '  "確認方法":"確認ポイント：Webフィルタプロファイルがポリシーに紐づいているか\\nコマンド：show webfilter profile\\n判断：有効なポリシーがあれば対応が必要。未使用なら定期更新で可",',
    '  "内容要約":"認証なしでWebフィルタ警告画面を操作",',
    '  "ユーザ影響":"端末が操作され社内認証情報が盗まれる恐れ",',
    '  "回避策":"該当OIDをSNMPビューから除外して参照を止める"}]'
  ].join('\n');
}

function callGemini_(prompt) {
  const models = [GEMINI_MODEL].concat(GEMINI_MODEL_FALLBACKS || []);
  let lastErr = null;
  for (let i = 0; i < models.length; i++) {
    const model = models[i];
    try {
      const text = callGeminiModel_(model, prompt);
      if (i > 0) Logger.log('AI はフォールバックモデル ' + model + ' で生成しました');
      return text;
    } catch (e) {
      lastErr = e;
      if (!isGeminiDailyQuotaError_(e) || i === models.length - 1) throw e;
      Logger.log(model + ' の無料枠（1日上限）を使い切ったため ' + models[i + 1] + ' に切り替えます');
    }
  }
  throw lastErr;
}

function isGeminiDailyQuotaError_(err) {
  return /PerDay/i.test(String(err && err.message ? err.message : err));
}

function callGeminiModel_(model, prompt) {
  const apiKey = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
  if (!apiKey) throw new Error('GEMINI_API_KEY がスクリプト プロパティに未設定です。');

  const url = 'https://generativelanguage.googleapis.com/v1beta/models/' +
              model + ':generateContent';

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
    countAiRequest_();
    res = UrlFetchApp.fetch(url, options);
    const code = res.getResponseCode();
    if (code === 200) break;

    const bodyText = res.getContentText();
    const waitMs = geminiRetryWaitMs_(code, bodyText, attempt);
    if (waitMs > 0 && attempt < 3) {
      Logger.log('HTTP ' + code + ' (' + model + ') のため ' +
                 Math.round(waitMs / 1000) + '秒待って再試行します（' + attempt + '回目）');
      Utilities.sleep(waitMs);
      continue;
    }
    throw new Error('Gemini API エラー HTTP ' + code + ': ' + bodyText);
  }

  const body = JSON.parse(res.getContentText());
  const cand = (body.candidates || [])[0];

  if (cand && cand.finishReason && cand.finishReason !== 'STOP') {
    Logger.log('警告: finishReason=' + cand.finishReason + '（出力が途中で終わった可能性）');
  }

  const parts = (cand && cand.content && cand.content.parts) || [];
  return parts.map(function (p) { return p.text || ''; }).join('');
}

/** 429 の日次上限はリトライしない（同じ枠を消費するだけ）。分次制限は Retry-After を待つ。 */
function geminiRetryWaitMs_(code, bodyText, attempt) {
  if (code !== 429 && code !== 503) return 0;
  if (code === 429 && /PerDay/i.test(bodyText || '')) return 0;
  let delaySec = attempt * 5;
  try {
    const details = (JSON.parse(bodyText).error || {}).details || [];
    for (let i = 0; i < details.length; i++) {
      const raw = details[i] && details[i].retryDelay;
      if (!raw) continue;
      const n = parseInt(String(raw), 10);
      if (n > 0) delaySec = Math.max(delaySec, n);
    }
  } catch (e) {}
  return Math.min(delaySec, 90) * 1000;
}

function callClaude_(prompt) {
  const apiKey = PropertiesService.getScriptProperties().getProperty('ANTHROPIC_API_KEY');
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY がスクリプト プロパティに未設定です。');

  countAiRequest_();
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
    // r[cVer] が数値 0 でも保持する。Fortinet の CSAF は tracking.version が
    // 常に "0" で、セルに書くと数値 0 になる。`|| ''` だと falsy で空文字に化け、
    // CSAF 側の "0" と一致せず毎回「改訂」と誤判定して再通知していた。
    versions[id] = cVer >= 0 && r[cVer] != null ? String(r[cVer]).trim() : '';
  });
  return { dates: dates, versions: versions };
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
      if (targets[String(ids[i][0]).trim()]) { deleteSheetRowSafe_(sh, i + 2); removed++; }
    }
    if (removed) Logger.log(sh.getName() + ' から古い ' + removed + ' 行を削除しました（改訂のため入れ直します）。');
  });
}

/**
 * 処理したアドバイザリを 1 件 1 行で記録する。
 * 「今月 Fortinet から公表：N 件」の分母はこのシートを数えて出す。
 */
/**
 * 処理済みシートに残す自社判定。
 *
 * 台帳に載らなかった件は、載せなかった根拠がどこにも残らない。
 * 分母（公表 N 件）だけあっても「なぜ 44 件を対象外としたのか」を後から説明できないので、
 * 判定の結論だけをここに書き写す。判断そのものは decideNotification_ が済ませたもので、
 * ここで新しい判断はしない。
 */
function ownershipLabel_(f, advisoryRows, assets) {
  // 値の先頭は必ず 対象 / 対象外 / 判定不能 にする。列を眺めたときに
  // 可否が最初の 2〜3 文字で読めないと、根拠として使えない。
  if (f && f.error) return '判定不能';
  if (isCiscoInformationalAdvisory_(f && f.csaf, f && f.item)) return STATE_JUDGE_INFO;

  const owned = (advisoryRows || []).filter(function (r) {
    return r.product && assetsForProduct_(assets || [], r.product).length;
  });
  if (!owned.length) return '対象外-未保有';
  if (owned.some(function (r) { return r.osStatus !== '対象外'; })) return '対象';
  return '対象外-OS影響外';
}

function writeState_(vendor, todo, rows, assets) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(SHEET_STATE);
  if (!sh) {
    sh = ss.insertSheet(SHEET_STATE);
    sh.appendRow(STATE_HEADERS);
    sh.setFrozenRows(1);
  }

  const byAdvisory = {};
  rows.forEach(function (r) {
    const a = byAdvisory[r.advisoryId] ||
      (byAdvisory[r.advisoryId] = { products: [], initial: r.initialDate, rows: [] });
    pushUnique_(a.products, r.product);
    a.rows.push(r);
  });

  const values = todo.map(function (f) {
    const item = f.item || f;
    const id = item.ir || item.id;
    const a = byAdvisory[id] || { products: [], initial: f.updatedAt || item.pubDate, rows: [] };
    // CSAF から製品名が取れていればそれを使う（自社保有と無関係に「何の製品か」を残す）。
    // 取れない場合だけ、台帳へ展開した行から拾った製品名に落とす。
    const products = (f.products && f.products.length) ? f.products : a.products;
    return [
      vendor,
      f.updatedAt || item.pubDate || '',
      a.initial || f.updatedAt || item.pubDate || '',
      id,
      item.title,
      products.join(', '),
      f.version || '',
      ownershipLabel_(f, a.rows, assets)
    ];
  });

  if (!values.length) return;

  if (sh.getMaxColumns() < STATE_HEADERS.length) {
    sh.insertColumnsAfter(sh.getMaxColumns(), STATE_HEADERS.length - sh.getMaxColumns());
  }

  const startRow = sh.getLastRow() + 1;
  sh.getRange(startRow, 1, values.length, STATE_HEADERS.length).setValues(values);
  sh.getRange(startRow, 2, values.length, 2).setNumberFormat('yyyy/mm/dd');
  Logger.log('処理済みシートに ' + values.length + ' 件のアドバイザリを記録しました。');
}

/**
 * 実行を 1 行残す。通知は増やさない。main() から 1 実行につき 1 回だけ呼ぶ。
 *
 * 記録に失敗しても本体は止めない。履歴のために日次処理を落とすのは本末転倒。
 */
function writeRunLog_(errorText) {
  try {
    if (!runStats_) return;

    const v = runStats_.vendors;
    function sum(key) {
      return v.reduce(function (a, x) { return a + x[key]; }, 0);
    }

    // ベンダー別の数字は 1 列にまとめる。異常時に切り分けられればよく、
    // ベンダーごとに行を分けると「今日動いたか」が 1 行で読めなくなる。
    //
    // 件数だけを並べない。取りに行く仕様がベンダーで違い（Fortinet は毎回全件、
    // Cisco は更新分のみ）、Cisco の「取得 0」を知らない人が読むと
    // 失敗したように見えるため、そうなった理由を必ず添える。
    const detail = v.map(function (x) {
      if (!x.rss && x.note) return x.vendor + '：' + x.note;

      // 数字を記号で並べず文にする。両ベンダーとも「N件を確認、」で始めることで、
      // 取りに行った件数が違っても「どちらも 50 件ちゃんと見た」が先に読める。
      let body;
      if (x.mode === 'all') {
        body = '全件取得';
      } else if (!x.fetched) {
        body = '変更なし';
      } else {
        body = x.fetched + '件取得';
      }

      const inner = [];
      if (x.fetched) {
        inner.push('成功' + x.ok);
        if (x.missing) inner.push('CSAF未作成' + x.missing);
        if (x.failed) inner.push('失敗' + x.failed);
      }

      return x.vendor + ' ' + x.rss + '件：' + body +
             (inner.length ? '（' + inner.join('・') + '）' : '') +
             (x.note ? ' ' + x.note : '');
    }).join('  ');

    const result = errorText ? '失敗' : (sum('failed') ? '要確認' : '正常');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sh = ss.getSheetByName(SHEET_RUNLOG);
    if (!sh) {
      sh = ss.insertSheet(SHEET_RUNLOG);
      sh.appendRow(RUNLOG_HEADERS);
      sh.setFrozenRows(1);
    } else {
      // 列構成を変えたときに見出しだけ差し替える。
      const cur = sh.getRange(1, 1, 1, Math.max(sh.getLastColumn(), 1)).getDisplayValues()[0];
      const same = cur.length === RUNLOG_HEADERS.length &&
                   RUNLOG_HEADERS.every(function (h, i) { return cur[i] === h; });
      if (!same) {
        // 列を減らしたときは右端の古い見出しを消す。残すと見出しだけ 11 列、
        // データは 9 列という状態になり、読む側が列を数え違える。
        if (sh.getLastColumn() > RUNLOG_HEADERS.length) {
          sh.deleteColumns(RUNLOG_HEADERS.length + 1, sh.getLastColumn() - RUNLOG_HEADERS.length);
        }
        sh.getRange(1, 1, 1, RUNLOG_HEADERS.length).setValues([RUNLOG_HEADERS]);
        Logger.log('実行履歴の見出しを ' + RUNLOG_HEADERS.length + ' 列に更新しました。');
      }
    }

    const row = sh.getLastRow() + 1;
    sh.getRange(row, 1, 1, RUNLOG_HEADERS.length).setValues([[
      new Date(),
      result,
      sum('rss'), sum('processed'), sum('ledger'), sum('failed'),
      Math.round((Date.now() - runStats_.startedAt) / 1000),
      aiRequestCount_ - runStats_.aiAtStart,
      errorText ? ('エラー: ' + errorText + (detail ? '  /  ' + detail : '')) : detail
    ]]);
    sh.getRange(row, 1).setNumberFormat('yyyy/mm/dd hh:mm');
  } catch (e) {
    Logger.log('実行履歴の記録に失敗: ' + e);
  }
}

/**
 * 月ごとの公表件数を数える。月次サマリの分母。
 *
 * 台帳の行数は数えない。同じアドバイザリでも実行タイミングで行数が変わり、
 * 集計の意味が定まらないうえ、台帳を数えれば同じ数字が出る。
 */
/** 集計の分母から外す行か。情報通知は Cisco が同じ内容を個別アドバイザリで出し直す重複で、
 *  脆弱性の公表件数として数えると水増しになる。記録自体は証跡として残す。 */
const STATE_JUDGE_INFO = '対象外-情報通知';

function isCountableStateRow_(row, cJudge) {
  return !(cJudge >= 0 && String(row[cJudge]).trim() === STATE_JUDGE_INFO);
}

function countByMonth() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_STATE);
  if (!sh || sh.getLastRow() < 2) { Logger.log('処理済みシートが空です。'); return; }

  const values = sh.getRange(2, 1, sh.getLastRow() - 1, STATE_HEADERS.length).getValues();
  const cUpd = STATE_HEADERS.indexOf('最終更新日');
  const cJudge = STATE_HEADERS.indexOf('自社判定');
  const m = {};
  let skipped = 0;
  values.forEach(function (r) {
    if (!isCountableStateRow_(r, cJudge)) { skipped++; return; }
    const d = r[cUpd];   // 改訂された月に計上する
    const key = (d instanceof Date)
      ? d.getFullYear() + '/' + ('0' + (d.getMonth() + 1)).slice(-2)
      : '(公開日不明)';
    m[key] = (m[key] || 0) + 1;
  });

  Logger.log('--- 月別（最終更新日で集計）---');
  Object.keys(m).sort().reverse().forEach(function (k) {
    Logger.log(k + '  公表 ' + m[k] + ' 件');
  });
  if (skipped) Logger.log('※ 情報通知 ' + skipped + ' 件を除く（公開一覧のお知らせで、実体は個別アドバイザリ側にある）');
}

function countByMonthVendor() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_STATE);
  if (!sh || sh.getLastRow() < 2) { Logger.log('処理済みシートが空です。'); return; }

  const values = sh.getRange(2, 1, sh.getLastRow() - 1, STATE_HEADERS.length).getValues();
  const cVendor = STATE_HEADERS.indexOf('ベンダー');
  const cUpd = STATE_HEADERS.indexOf('最終更新日');
  const cJudge = STATE_HEADERS.indexOf('自社判定');
  const m = {};
  let skipped = 0;
  values.forEach(function (r) {
    if (!isCountableStateRow_(r, cJudge)) { skipped++; return; }
    const d = r[cUpd];
    const key = (d instanceof Date)
      ? d.getFullYear() + '/' + ('0' + (d.getMonth() + 1)).slice(-2)
      : '(公開日不明)';
    const vendor = cVendor >= 0 ? String(r[cVendor]).trim() : VENDOR_FORTINET;
    const bucket = m[key] || (m[key] = {});
    bucket[vendor] = (bucket[vendor] || 0) + 1;
  });

  Logger.log('--- 月別・ベンダー別 ---');
  Object.keys(m).sort().reverse().forEach(function (month) {
    Object.keys(m[month]).sort().forEach(function (vendor) {
      Logger.log(month + '  ' + vendor + ': 公表 ' + m[month][vendor] + ' 件');
    });
  });
  if (skipped) Logger.log('※ 情報通知 ' + skipped + ' 件を除く');
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
    shortTitle_(r.title),             // 4  脆弱性名
    cvss,                             // 5  CVSS
    r.pubDate || '',                  // 6  最終更新日
    action,                           // 7  公式推奨対応
    r.kev || '',                      // 8  KEV
    r.feature || '',                  // 9  影響機能
    r.reason || '',                   // 10 判定根拠
    stripCheckLabels_(r.howToCheck),  // 11 確認方法
    r.impactJa || '',                 // 12 ユーザ影響
    advisoryCell                      // 13 アドバイザリ
  ];
}

/** 台帳向けにタイトルを短くする（英語の長い文書名を切る） */
function shortTitle_(s) {
  const t = String(s || '').trim().replace(/\s+/g, ' ');
  if (!t) return '';
  return t.length > 60 ? t.slice(0, 60) + '…' : t;
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

/** あり（対応検討）→ あり（影響調査）→ なし の順、同じ判定なら公開日の新しい順に並べ替える。 */
function sortLedger_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 3) return;

  const n = sh.getLastRow() - 1;
  const range = sh.getRange(2, 1, n, LEDGER_HEADERS.length);
  const rank = {};
  rank[V_ACT] = 0; rank[V_INVEST] = 1; rank[V_NONE] = 2;

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

  const widths = [90, 100, 140, 220, 70, 100, 220, 55, 120, 280, 320, 220, 150];
  widths.forEach(function (w, i) { sh.setColumnWidth(i + 1, w); });

  sh.setFrozenColumns(6);

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
    if (verdict !== V_ACT && verdict !== V_INVEST && verdict !== V_NONE) continue;
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
        if (w && (r.needsVerdict || r.needsDisplayAi || r.needsCodeDisplay)) {
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

  fillLedgerDisplay_(targets);

  let written = 0;
  targets.forEach(function (t) {
    if (!t.feature && !t.impactJa && !t.howToCheck) return;
    sh.getRange(t.rowIndex, COL['影響機能']).setValue(t.feature || '');
    sh.getRange(t.rowIndex, COL['判定根拠']).setValue(t.reason || '');
    sh.getRange(t.rowIndex, COL['ユーザ影響']).setValue(t.impactJa || '');
    sh.getRange(t.rowIndex, COL['確認方法']).setValue(stripCheckLabels_(t.howToCheck));
    if (t.verdict) sh.getRange(t.rowIndex, COL['自社影響']).setValue(t.verdict);
    if (t.kev) sh.getRange(t.rowIndex, COL['KEV']).setValue(t.kev);
    written++;
  });
  Logger.log('AI 補完: ' + written + ' / ' + targets.length + ' 行を書き戻しました。');

  // 台帳の行数は増えないので合計には足さない。何をしたかだけ内訳に残す。
  addVendorStats_('AI補完', { note: written + ' 行を埋め直し' });
}

// ============================================================
// 7. Slack 通知（日次1通ダイジェスト）
// ============================================================

/**
 * Slack 通知。その日の該当分を 1 通にまとめる。
 *
 * 目的:
 *   1. 自社該当の公開に気づく
 *   2. RSS+AI の既知情報を短く掴む
 *   3. 公式アドバイザリで妥当性と対応を決める（主アクション）
 *   4. 必要なら台帳で詳細（任意）
 *
 * 「なし」は件数のみ。コミ猫風の画像添付はしない（Webhook のみ）。
 */
function notifySlack_(rows) {
  const url = PropertiesService.getScriptProperties().getProperty('SLACK_WEBHOOK_URL');
  if (!url) { Logger.log('SLACK_WEBHOOK_URL 未設定のため通知をスキップします。'); return; }

  const hits = rows
    .filter(function (r) { return r.verdict === V_ACT || r.verdict === V_INVEST; })
    .sort(slackHitSort_);

  if (!hits.length && !NOTIFY_WHEN_NO_HITS) {
    Logger.log('OS 更新の可能性がある新着なし。Slack 通知はスキップします。');
    return;
  }

  const sheetUrl = SpreadsheetApp.getActiveSpreadsheet().getUrl();
  const shown = hits.slice(0, SLACK_MAX_ITEMS);
  const rest = hits.length - SLACK_MAX_ITEMS;
  const payload = buildSlackPayload_(shown, sheetUrl, rest);

  UrlFetchApp.fetch(url, {
    method: 'post',
    contentType: 'application/json',
    muteHttpExceptions: true,
    payload: JSON.stringify(payload)
  });
}

function slackHitSort_(a, b) {
  const da = slackDeviceLabel_(a);
  const db = slackDeviceLabel_(b);
  if (da !== db) return da === 'FortiGate' ? -1 : 1;
  return (Number(b.cvss) || 0) - (Number(a.cvss) || 0);
}

/**
 * ADS Manager 型:
 *   1行目: 新しい脆弱性が発表されました🔍
 *   2行目: FortiGate:1件 Cisco:2件
 */
function buildSlackPayload_(hits, sheetUrl, rest) {
  const summary = slackDeviceSummary_(hits);
  const title = '新しい脆弱性が発表されました:mag:';
  const blocks = [{
    type: 'header',
    text: { type: 'plain_text', text: title, emoji: true }
  }];
  if (summary) {
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: summary }
    });
  }

  hits.forEach(function (r) {
    blocks.push({ type: 'divider' });
    formatSlackItemBlocks_(r).forEach(function (b) { blocks.push(b); });
  });

  const foot = [];
  if (rest > 0) foot.push('ほか ' + rest + ' 件は台帳');
  const links = ['<' + SECURITY_NEXT_VULN_URL + '|Security NEXTで確認>'];
  if (sheetUrl) links.push('<' + sheetUrl + '|判定台帳を確認>');
  foot.push(links.join('  /  '));
  if (foot.length) {
    blocks.push({ type: 'divider' });
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: foot.join('\n') }
    });
  }

  return {
    text: title,
    blocks: blocks
  };
}

function slackDeviceSummary_(rows) {
  const order = ['FortiGate', 'Cisco'];
  const m = {};
  rows.forEach(function (r) {
    const k = slackDeviceLabel_(r);
    m[k] = (m[k] || 0) + 1;
  });
  const keys = order.filter(function (k) { return m[k]; }).concat(
    Object.keys(m).filter(function (k) { return order.indexOf(k) === -1; }).sort()
  );
  return keys.map(function (k) { return k + ':' + m[k] + '件'; }).join(' ');
}

function slackDeviceLabel_(r) {
  if ((r.vendor || '') === VENDOR_CISCO) return 'Cisco';
  return 'FortiGate';
}

/**
 * 1件。
 *   🟡 CVE-…  /  CVSS 5 [中]  /  08/12更新
 *   機器：FortiGate
 *   内容：CVEの日本語要約（無ければタイトルの日本語訳）
 *   影響：業務結果（主語は機器）
 *   推奨対応：…
 */
function formatSlackItemBlocks_(r) {
  const band = slackCvssBand_(r.cvss);
  const cve = slackCveLink_(r) || '（CVEなし）';
  const cvss = (r.cvss === '' || r.cvss === undefined || r.cvss === null)
    ? 'CVSS — [' + band.label + ']'
    : 'CVSS ' + r.cvss + ' [' + band.label + ']';
  const head = [band.emoji + ' *' + cve + '*', cvss];
  const upd = slackUpdatedLabel_(r);
  if (upd) head.push(upd);
  const lines = [
    head.join('  /  '),
    '機器：' + slackDeviceLabel_(r),
    '内容：' + slackContentsJa_(r),
    '影響：' + slackImpactJa_(r),
    '推奨対応：' + slackActionLine_(r)
  ];

  return [{
    type: 'section',
    text: { type: 'mrkdwn', text: lines.join('\n') }
  }];
}

/** アドバイザリの最終更新日。CVE 行の mm/dd更新 */
function slackUpdatedLabel_(r) {
  const d = r.pubDate instanceof Date ? r.pubDate : (r.pubDate ? new Date(r.pubDate) : null);
  if (!d || isNaN(d.getTime())) return '';
  return Utilities.formatDate(d, 'Asia/Tokyo', 'MM/dd') + '更新';
}

function slackActionLine_(r) {
  const first = String(formatOfficialAction_(r) || '').split(/\n/)[0].trim();
  if (!first) return 'アドバイザリを確認';
  return first.length > 40 ? first.slice(0, 40) + '…' : first;
}

/** Slack の「内容」。AI の日本語要約。無ければ公式タイトルの日本語訳。 */
function slackContentsJa_(r) {
  const ai = String(r.cveSummaryJa || r.titleJa || '').trim();
  const text = isUsableCveSummary_(ai) ? ai : titleJaFromAdvisory_(r);
  return text.length > 30 ? text.slice(0, 30) + '…' : text;
}

function isUsableCveSummary_(s) {
  if (!s) return false;
  if (/認証なし.*機器が(応答停止|再起動)/.test(s)) return false;
  if (/^(サービス停止|遠隔コード実行|権限昇格|情報漏えい|脆弱性)$/.test(s)) return false;
  const letters = (s.match(/[A-Za-z]/g) || []).length;
  const ja = (s.match(/[\u3040-\u30ff\u4e00-\u9faf]/g) || []).length;
  if (ja === 0) return false;
  if (letters >= 8 && ja < 4) return false;
  return true;
}

/** 製品名と Vulnerability を落とした公式タイトルを日本語にする。定型の「機器が応答停止」は使わない。 */
function titleJaFromAdvisory_(r) {
  const feat = contentFeatureJa_(r);
  const kind = vulnKindJa_(r);
  if (feat && kind) return feat + 'の' + kind;

  const translated = translateTitlePhrases_(stripAdvisoryTitle_(r));
  if (feat && translated && translated.indexOf(feat) === -1) return feat + 'の' + translated;
  if (translated) return translated;
  if (feat) return feat + 'の脆弱性';
  if (kind) return kind;
  return '（タイトルなし）';
}

function contentFeatureJa_(r) {
  if ((r.vendor || '') === VENDOR_CISCO) {
    const f = normalizeCiscoFeature_(r.feature || r.title || '');
    if (f && f !== 'IOS XE 基盤') return f.replace(/\s+Server$/, '');
    return '';
  }
  const f = String(r.feature || '').trim();
  if (f === '管理GUI' || f === 'WebUI') return '管理画面';
  if (f && f !== '不明' && f !== 'その他' && f !== '—') return f;
  const guessed = guessFortinetFeature_(r);
  if (guessed === '管理GUI') return '管理画面';
  if (guessed && guessed !== 'その他') return guessed;
  return '';
}

function vulnKindJa_(r) {
  const low = advisoryCorpus_(r).toLowerCase() + ' ' + String(r.title || '').toLowerCase();
  if (/remote code|code execution|arbitrary code|command injection|\brce\b/.test(low)) return '遠隔コード実行';
  if (/privilege.?escalat|elevation of privilege/.test(low)) return '権限昇格';
  if (/information disclosure|information leak|sensitive.*expos/.test(low)) return '情報漏えい';
  if (/auth(entication)? bypass|improper authentication/.test(low)) return '認証回避';
  if (/path.?traversal|directory.?traversal/.test(low)) return 'パストラバーサル';
  if (/cross.?site.?script|\bxss\b/.test(low)) return 'クロスサイトスクリプティング';
  if (/sql.?inject/.test(low)) return 'SQLインジェクション';
  if (/buffer overflow|heap overflow|stack overflow/.test(low)) return 'バッファオーバーフロー';
  if (/resource exhaust|\bdos\b|denial of service/.test(low)) return 'サービス停止';
  return '';
}

function stripAdvisoryTitle_(r) {
  let t = String(r.title || '').replace(/\s+/g, ' ').trim();
  if (!t) return '';
  return t
    .replace(/^Cisco IOS(?: Software)? and IOS XE Software\s+/i, '')
    .replace(/^Cisco IOS XE Software\s+/i, '')
    .replace(/^Cisco IOS Software\s+/i, '')
    .replace(/\s+in Fortinet FortiOS$/i, '')
    .replace(/^Fortinet\s+/i, '')
    .replace(/\s+Vulnerabilit(?:y|ies)$/i, '')
    .trim();
}

/** 英語タイトルの定型句だけ日本語にする。プロトコル名（BEEP 等）は残す。 */
function translateTitlePhrases_(en) {
  let s = String(en || '').replace(/\s+/g, ' ').trim();
  if (!s) return '';
  const pairs = [
    [/UI DoS attack/gi, '管理画面のサービス停止'],
    [/DoS attack/gi, 'サービス停止'],
    [/Resource Exhaustion Allowing Denial of Service/gi, 'リソース枯渇によるサービス停止'],
    [/Denial of Service/gi, 'サービス停止'],
    [/Remote Code Execution/gi, '遠隔コード実行'],
    [/Arbitrary Code Execution/gi, '遠隔コード実行'],
    [/Privilege Escalation/gi, '権限昇格'],
    [/Information Disclosure/gi, '情報漏えい'],
    [/Authentication Bypass/gi, '認証回避'],
    [/Command Injection/gi, 'コマンドインジェクション'],
    [/Buffer Over-?read/gi, 'バッファ過剰読み取り'],
    [/Buffer Overflow/gi, 'バッファオーバーフロー'],
    [/Resource Exhaustion/gi, 'リソース枯渇'],
    [/\bDoS\b/gi, 'サービス停止'],
    [/\bRCE\b/gi, '遠隔コード実行'],
    [/\bXSS\b/gi, 'クロスサイトスクリプティング'],
    [/\bWebUI\b/gi, '管理画面'],
    [/\bGUI\b/g, '管理画面'],
    [/\bUI\b/g, '管理画面'],
    [/\battack\b/gi, '攻撃'],
    [/\ballowing\b/gi, 'による'],
    [/\bvulnerabilit(?:y|ies)\b/gi, '']
  ];
  for (let i = 0; i < pairs.length; i++) {
    s = s.replace(pairs[i][0], ' ' + pairs[i][1] + ' ');
  }
  s = s.replace(/\s+/g, ' ').trim();
  s = s.replace(/([^\s])\s+(?=[\u3040-\u30ff\u4e00-\u9faf])/g, '$1の');
  s = s.replace(/の+/g, 'の').replace(/^の+|の+$/g, '');
  s = s.replace(/サービス停止の攻撃/g, 'サービス停止');
  return s.replace(/\s+/g, ' ').trim();
}

/** Slack の「影響」。主語は機器。機能名は足さない。 */
function slackImpactJa_(r) {
  const ja = String(r.impactJa || '').trim();
  const text = ja || fallbackImpactJa_(r);
  return text.length > 40 ? text.slice(0, 40) + '…' : text;
}

/** CVE 文字列を公式アドバイザリへリンク。無ければ ID だけ。 */
function slackCveLink_(r) {
  const cve = String(r.cve || '').trim();
  const url = String(r.advisoryUrl || '').trim();
  const label = cve || String(r.advisoryId || '').trim();
  if (!label) return '';
  return url ? '<' + url + '|' + label + '>' : label;
}

/**
 * CVSS 定性区分。
 *   緊急 9.0–10.0 / 高 7.0–8.9 / 中 4.0–6.9 / 低 0.1–3.9
 */
function slackCvssBand_(score) {
  const n = Number(score);
  if (score === '' || score === undefined || score === null || isNaN(n)) {
    return { label: '不明', emoji: ':white_circle:' };
  }
  if (n >= 9) return { label: '緊急', emoji: ':red_circle:' };
  if (n >= 7) return { label: '高', emoji: ':large_orange_circle:' };
  if (n >= 4) return { label: '中', emoji: ':large_yellow_circle:' };
  if (n > 0) return { label: '低', emoji: ':white_circle:' };
  return { label: '不明', emoji: ':white_circle:' };
}

/**
 * Webhook に送らず、組み立てた payload をログに出す（表示確認用）。
 */
function testSlackBlocks() {
  const sheetUrl = 'https://example.com/ledger';
  const rows = [
    {
      vendor: VENDOR_FORTINET, verdict: V_ACT, product: 'FortiOS',
      selfVersion: 'FortiOS 7.4.11', cve: 'CVE-2026-0001', cvss: 9.8,
      advisoryUrl: 'https://fortiguard.fortinet.com/psirt/FG-IR-26-001',
      advisoryId: 'FG-IR-26-001',
      title: 'Resource Exhaustion Allowing Denial of Service in Fortinet FortiOS',
      cveSummaryJa: '管理画面への負荷で機器が応答停止',
      impactJa: '機器が停止し、拠点の通信が途切れる恐れ',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
      fixVersion: '7.4.12 以上に更新が必要',
      pubDate: new Date('2026-08-12')
    },
    {
      vendor: VENDOR_CISCO, verdict: V_INVEST, product: 'IOS-XE',
      selfVersion: 'IOS-XE 17.15.5', cve: 'CVE-2026-0002', cvss: 7.5,
      advisoryUrl: 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-example',
      advisoryId: 'cisco-sa-example',
      title: 'Cisco IOS XE Software Blocks Extensible Exchange Protocol Denial of Service Vulnerability',
      cveSummaryJa: '不正なBEEP通信で機器が再起動',
      impactJa: '機器が停止し、拠点の通信が途切れる恐れ',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H',
      workaroundNone: true,
      pubDate: new Date('2026-08-05')
    },
    {
      vendor: VENDOR_FORTINET, verdict: V_INVEST, product: 'FortiOS',
      selfVersion: '7.4.11', cve: 'CVE-2026-0003', cvss: 6.5,
      advisoryUrl: 'https://fortiguard.fortinet.com/psirt/FG-IR-26-003',
      advisoryId: 'FG-IR-26-003', title: 'Information disclosure',
      impactJa: '管理情報や認証情報が外部に漏れる恐れ',
      pubDate: new Date('2026-08-20')
    }
  ];
  const payload = buildSlackPayload_(rows, sheetUrl, 0);
  Logger.log(JSON.stringify(payload, null, 2));
  Logger.log('testSlackBlocks: 1行タイトル＋件数の payload を出力しました。');
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

/** 自社影響3値の単体テスト（ネットワーク不要） */
function testJudge() {
  const NET = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  const cases = [
    // ルールゲートで落ちる側。深刻度が高くても前提条件があれば臨時更新しない
    { name: '管理者権限が前提', vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
      feature: 'IPsec VPN', tech: 'total', expect: V_NONE },
    { name: '認証済みが前提', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
      feature: '管理GUI', tech: 'total', expect: V_NONE },
    { name: 'ローカルアクセスが前提', vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      feature: 'データプレーン', tech: 'total', expect: V_NONE },
    { name: '利用者の操作が前提', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
      feature: '管理GUI', tech: 'total', expect: V_NONE },

    // 設定次第の機能は、設定を見ていないので断定しない
    { name: '設定次第の機能', vector: NET, feature: 'Webフィルタ', tech: 'total', expect: V_INVEST },
    { name: '無効にしている機能', vector: NET, feature: 'SSL-VPN', tech: 'total', expect: V_NONE },
    { name: '機能を特定できない', vector: NET, feature: 'その他', tech: '不明', aiOk: false, expect: V_INVEST },
    { name: 'ベクター不明', vector: '', feature: 'その他', tech: '不明', aiOk: false, expect: V_INVEST },

    // 常時有効な機能だけ、影響の重さで臨時更新まで判定する
    { name: '常時有効かつ掌握', vector: NET, feature: 'データプレーン', tech: 'total', expect: V_ACT },
    { name: '常時有効だが軽微', vector: NET, feature: 'データプレーン', tech: 'partial',
      title: 'Information disclosure', impact: 'Information disclosure', expect: V_NONE },

    // KEV は最低ライン。使っていない前提で流さない
    { name: 'KEVあり・設定次第', kev: KEV_YES, vector: NET, feature: 'Webフィルタ',
      tech: 'partial', expect: V_INVEST },
    { name: 'KEVあり・前提条件つき', kev: KEV_YES, vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
      feature: 'データプレーン', tech: 'total', expect: V_INVEST },
    { name: 'KEVあり・常時有効かつ掌握', kev: KEV_YES, vector: NET, feature: 'データプレーン',
      tech: 'total', expect: V_ACT }
  ];

  let pass = 0;
  cases.forEach(function (c, i) {
    const row = {
      vendor: VENDOR_FORTINET, cve: 'CVE-TEST-' + i, osStatus: '対象',
      kev: c.kev || KEV_NO, vector: c.vector,
      feature: c.feature, aiOk: (c.aiOk === undefined) ? true : c.aiOk,
      title: c.title || '', impact: c.impact || '',
      aiTechImpact: c.tech, aiServiceStop: c.stop || 'いいえ',
      aiConfidence: (c.aiOk === false) ? 'low' : 'high'
    };
    finalizeVerdict_(row, { skipKev: true });
    const ok = row.verdict === c.expect && isTwoLineReason_(row.reason);
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + c.name + ' → ' + row.verdict +
               '（期待 ' + c.expect + '） / ' + row.reason.replace('\n', ' ⏎ '));
  });
  Logger.log('自社影響3値: ' + pass + ' / ' + cases.length + ' 件が期待どおり');
}

/** 判定根拠が「1行目=構造値／2行目=理由と結論」の2行になっているか */
function isTwoLineReason_(reason) {
  const lines = String(reason || '').split('\n');
  if (lines.length !== 2) return false;
  return /^OS=\S+ \| KEV=(あり|なし)$/.test(lines[0])
      && /.+「.+」$/.test(lines[1]);
}

/** ルールゲートの単体テスト。落とす理由が根拠欄に出ることまで見る */
function testRuleGate() {
  const cases = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', true, ''],
    ['CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', false, '管理者権限'],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', false, '認証済み'],
    ['CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', false, 'ローカル'],
    ['CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', false, '隣接'],
    ['CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', false, '物理'],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', false, '操作'],
    ['', true, '']                                   // ベクター無しは断定しない
  ];

  let pass = 0;
  cases.forEach(function (c) {
    const got = ruleGate_({ vector: c[0] });
    const ok = got.pass === c[1] && got.phrase.indexOf(c[2]) !== -1;
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + (c[0] || '(ベクターなし)') +
               ' → pass=' + got.pass + ' / ' + (got.phrase || '(理由なし)'));
  });
  Logger.log('ルールゲート: ' + pass + ' / ' + cases.length + ' 件が期待どおり');
}

/**
 * ルールゲートが AI の前に効いているかのテスト（ネットワーク不要）。
 * ここで なし に確定した行は AI を呼ばないので、needsVerdict が立たないこと。
 */
function testGateBeforeAi() {
  const assets = [{ vendor: VENDOR_CISCO, product: 'IOS-XE', version: '17.15.5', tool: 'はい' }];
  const base = {
    vendor: VENDOR_CISCO, product: 'IOS-XE', cve: '', title: '', summary: '', impact: '',
    affected: ['17.15.5'], fixesRaw: '', kev: KEV_NO
  };

  const cases = [
    { name: 'ゲート落ち（PR:H）', vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
      expectVerdict: V_NONE, expectAi: false },
    { name: 'ゲート通過', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      expectVerdict: V_INVEST, expectAi: true }
  ];

  let pass = 0;
  cases.forEach(function (c) {
    const row = JSON.parse(JSON.stringify(base));
    row.vector = c.vector;
    row.pubDate = new Date();
    decideNotification_(row, assets);
    const calledAi = !!(row.needsVerdict || row.needsDisplayAi);
    const ok = row.verdict === c.expectVerdict && calledAi === c.expectAi;
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + c.name + ' → ' + row.verdict +
               ' / AI呼び出し=' + calledAi + '（期待 ' + c.expectVerdict + ' / ' + c.expectAi + '）');
  });
  Logger.log('ゲートの前置き: ' + pass + ' / ' + cases.length + ' 件が期待どおり');
}

/** 影響機能の設定依存分類テスト。CHECK_STEPS の判断文と矛盾しないこと */
function testFeatureExposure() {
  const cases = [
    ['データプレーン', 'always'],
    ['IOS XE 基盤', 'always'],
    ['管理GUI', 'config'],
    ['Webフィルタ', 'config'],
    ['WebUI', 'config'],
    ['SSL-VPN', SSL_VPN_ENABLED ? 'config' : 'disabled'],
    ['その他', 'unknown'],
    ['', 'unknown']
  ];

  let pass = 0;
  cases.forEach(function (c) {
    const got = featureExposure_({ feature: c[0] });
    const ok = got === c[1];
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + (c[0] || '(空)') + ' → ' + got + '（期待 ' + c[1] + '）');
  });
  Logger.log('機能の設定依存分類: ' + pass + ' / ' + cases.length + ' 件が期待どおり');
}

/** 台帳に出す確認方法からラベルが消えているか */
function testStripCheckLabels() {
  const src = '確認ポイント：管理GUIが有効か\nコマンド：show system interface\n判断：http があれば対応が必要';
  const got = stripCheckLabels_(src);
  const ok = got === '管理GUIが有効か\nshow system interface\nhttp があれば対応が必要';
  Logger.log((ok ? 'OK  ' : 'NG  ') + 'ラベル除去 → ' + got.replace(/\n/g, ' ⏎ '));
}

/**
 * Workarounds note の分解テスト（ネットワーク不要）。
 * コマンド行と説明文が分かれ、免責文が落ち、「回避策なし」を取り違えないこと。
 */
function testCiscoWorkaround() {
  const withCmds = {
    document: {
      notes: [{
        title: 'Workarounds',
        text: [
          'Administrators can disable the affected OIDs on a device.',
          'snmp-server view NO_BAD_SNMP snmpUsmMIB excluded',
          'snmp-server community mycomm view NO_BAD_SNMP RO',
          'While this mitigation has been deployed and was proven successful,',
          'customers should consider it a temporary measure.'
        ].join('\n')
      }]
    }
  };
  const none = { document: { notes: [{ title: 'Workarounds', text: 'There are no workarounds that address this vulnerability.' }] } };
  const absent = { document: { notes: [] } };
  const mitigation = {
    document: {
      notes: [{
        title: 'Workarounds',
        text: 'There are no workarounds that address this vulnerability.\n\nHowever, there is a mitigation.\nsnmp-server view NO_BAD_SNMP snmpUsmMIB excluded\nWhile this mitigation has been deployed as a temporary measure.'
      }]
    }
  };

  const a = ciscoWorkaround_(withCmds);
  const b = ciscoWorkaround_(none);
  const c = ciscoWorkaround_(absent);
  const d = ciscoWorkaround_(mitigation);

  const checks = [
    ['コマンド2件を抽出', a.cmds.length === 2],
    ['コマンドが原文のまま', a.cmds[0] === 'snmp-server view NO_BAD_SNMP snmpUsmMIB excluded'],
    ['説明文を保持', a.text.indexOf('disable the affected OIDs') !== -1],
    ['免責文を除去', a.text.indexOf('temporary measure') === -1],
    ['回避策なしを判定', b.none === true && b.cmds.length === 0],
    ['note なしは none=false', c.none === false && c.cmds.length === 0],
    ['no workarounds でも緩和策コマンドは取る', d.none === false && d.cmds.length === 1]
  ];
  let pass = 0;
  checks.forEach(function (c2) {
    if (c2[1]) pass++;
    Logger.log((c2[1] ? 'OK  ' : 'NG  ') + c2[0]);
  });
  Logger.log('回避策の分解: ' + pass + ' / ' + checks.length + ' 件が期待どおり');
}

/** 確認手順テーブルの単体テスト */
function testCheckSteps() {
  let pass = 0;
  let total = 0;
  Object.keys(CHECK_STEPS_FORTINET).forEach(function (f) {
    total++;
    const row = {
      vendor: VENDOR_FORTINET, feature: f, osStatus: '対象', verdict: V_NONE,
      howToCheck: 'アドバイザリの Affected Products を確認'
    };
    const got = normalizeHowToCheck_(row);
    const ok = isActionableHowTo_(got) && !isVersionRecheckHowTo_(got);
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + 'Fortinet ' + f);
  });
  ['WebUI', 'BEEP', 'XMCP Server', 'SD-WAN'].forEach(function (f) {
    total++;
    const row = {
      vendor: VENDOR_CISCO, feature: f, title: f, osStatus: '対象',
      verdict: V_NONE, howToCheck: ''
    };
    const got = normalizeHowToCheck_(row);
    const ok = isActionableHowTo_(got) && !isVersionRecheckHowTo_(got) && /コマンド[：:]/.test(got);
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + 'Cisco ' + f + ' → ' + got.split('\n')[0]);
  });

  total++;
  const noneRow = {
    vendor: VENDOR_CISCO, feature: 'IOS XE 基盤', title: 'Security Hardening',
    osStatus: '対象', verdict: V_NONE, howToCheck: ''
  };
  const noneGot = normalizeHowToCheck_(noneRow);
  const noneOk = isRegularUpdateHowTo_(noneGot);
  if (noneOk) pass++;
  Logger.log((noneOk ? 'OK  ' : 'NG  ') + 'なし → 定期更新定型');

  total++;
  const invRow = {
    vendor: VENDOR_CISCO, feature: 'その他', title: 'Unknown Thing',
    osStatus: '対象', verdict: V_INVEST,
    howToCheck: CHECK_STEPS_CISCO_DEFAULT
  };
  const invGot = normalizeHowToCheck_(invRow);
  const invOk = !isRegularUpdateHowTo_(invGot) && /振り分け|特定/.test(invGot);
  if (invOk) pass++;
  Logger.log((invOk ? 'OK  ' : 'NG  ') + '影響調査 → 定期更新定型を拒否');

  total++;
  const bad = {
    vendor: VENDOR_CISCO, feature: 'IOS XE 基盤', osStatus: '対象', verdict: V_NONE,
    howToCheck: '確認ポイント：稼働バージョンが影響範囲内か\nコマンド：show version\n判断：範囲内なら対応'
  };
  const replaced = normalizeHowToCheck_(bad);
  const rejOk = !isVersionRecheckHowTo_(replaced);
  if (rejOk) pass++;
  Logger.log((rejOk ? 'OK  ' : 'NG  ') + '対象済みの版再確認を差し替え');

  Logger.log('確認手順: ' + pass + ' / ' + total + ' 件が期待どおり');
}

/** 情報通知（notice）は台帳行にしない */
function testCiscoInformationalSkip() {
  const notice = {
    document: {
      category: 'csaf_informational_advisory',
      title: 'Cisco Advance Notification for Publication of August 5, 2026, Security Advisories',
      tracking: { id: 'cisco-sa-notice-L4XfJg8S' }
    },
    product_tree: {
      branches: [{ product: { name: 'Cisco IOS XE Software ', product_id: 'C1' } }]
    },
    vulnerabilities: []
  };
  const item = { id: 'cisco-sa-notice-L4XfJg8S', title: notice.document.title, link: 'https://example.com', pubDate: new Date() };
  const assets = [{ vendor: VENDOR_CISCO, product: 'IOS-XE', version: '17.15.5', tool: 'はい' }];
  const rows = extractCiscoRowsFromCsaf_(notice, item, assets);
  const ok = rows.length === 0 && isCiscoInformationalAdvisory_(notice, item);
  Logger.log((ok ? 'OK  ' : 'NG  ') + 'notice は台帳行 0（got ' + rows.length + '）');
}

/** ユーザ影響が CVSS と矛盾しないことのテスト */
function testImpactJaFromVector() {
  const cases = [
    {
      name: 'DoSのみ',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H',
      expect: /停止|通信/
    },
    {
      name: '掌握',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      expect: /乗っ取|掌握|改ざん/
    }
  ];
  let pass = 0;
  cases.forEach(function (c) {
    const got = fallbackImpactJa_({ vector: c.vector, title: '', impact: '', summary: '' });
    const ok = c.expect.test(got);
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + c.name + ' → ' + got);
  });

  const fixed = preferImpactJa_({
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H',
    impactJa: '機器を掌握され設定改ざんや通信傍受の恐れ'
  });
  const fixOk = /停止|通信/.test(fixed) && !/掌握/.test(fixed);
  if (fixOk) pass++;
  Logger.log((fixOk ? 'OK  ' : 'NG  ') + 'DoSなのに掌握 → 差し替え');
  Logger.log('ユーザ影響ベクター: ' + pass + ' / ' + (cases.length + 1) + ' 件が期待どおり');
}

/** AI が無いとき、内容が英語切れ端ではなく日本語のタイトル訳になること */
function testTitleJaFromAdvisory() {
  const cases = [
    {
      name: 'FortiGate UI DoS',
      row: { vendor: VENDOR_FORTINET, title: 'UI DoS attack', feature: '', summary: '', impact: '' },
      expect: /管理画面/
    },
    {
      name: 'Cisco BEEP',
      row: {
        vendor: VENDOR_CISCO,
        title: 'Cisco IOS XE Software Blocks Extensible Exchange Protocol Denial of Service Vulnerability',
        feature: '', summary: '', impact: ''
      },
      expect: /BEEP/
    },
    {
      name: 'Cisco XMCP',
      row: {
        vendor: VENDOR_CISCO,
        title: 'Cisco IOS XE Software Extensible Messaging Client Protocol Denial of Service Vulnerability',
        feature: '', summary: '', impact: ''
      },
      expect: /XMCP/
    }
  ];
  let pass = 0;
  cases.forEach(function (c) {
    const got = slackContentsJa_(c.row);
    const ok = c.expect.test(got) && /[\u3040-\u30ff\u4e00-\u9faf]/.test(got);
    if (ok) pass++;
    Logger.log((ok ? 'OK  ' : 'NG  ') + c.name + ' → ' + got);
  });
  Logger.log('タイトル日本語訳: ' + pass + ' / ' + cases.length + ' 件が期待どおり');
}

/** Cisco 影響機能名の正規化テスト */
function testCiscoFeatureNormalize_() {
  const cases = [
    ['Cisco IOS XE Software Security Hardening', 'IOS XE 基盤'],
    ['Cisco IOS XE Software Web-Based Management', 'WebUI'],
    ['Cisco IOS XE Software Blocks Extensible Exchange Protocol Denial of Service Vulnerability', 'BEEP'],
    ['Cisco IOS Software and IOS XE Software Extensible Messaging Client Protocol', 'XMCP Server'],
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
    verdict: V_INVEST,
    needsFortinetAi: true, needsVerdict: true,
    selfVersion: 'FortiOS 7.4.5',
    affected: ['FortiOS >=7.4.0|<=7.4.8', 'FortiOS 7.2 all versions'],
    fixesRaw: 'FortiOS 7.6: Upgrade to 7.6.4 or above\nFortiOS 7.4: Upgrade to 7.4.9 or above',
    workaround: '',
    feature: '', impactJa: '', howToCheck: '', plan: ''
  }];
  enrichWithAI_(dummy);
  Logger.log(JSON.stringify(dummy[0], null, 2));
}
