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

/**
 * Slack に 1 通で個別表示する最大件数。超えた分は末尾に件数だけ出す。
 *
 * 通知に出るのは「あり（対応検討）」「あり（影響調査）」だけなので、
 * ここで隠れる行はすべて人が見る必要のある行になる。5 では足りない。
 * 数えているのは台帳の行数（CVE × 製品）で、Cisco の複数 CVE アドバイザリが
 * 1 本あるだけで超える（ClamAV は 1 本で 7 行）。
 *
 * 上限は Slack 側の制約から決めている。1 メッセージ 50 ブロック、
 * カード 1 枚が divider + section の 2 ブロック、ヘッダ・サマリ・末尾で 4 ブロック。
 * 15 枚なら 34 ブロックで収まる。計算上は 23 枚まで入るがそこまで上げないのは、
 * 読む側の限界がブロック上限より手前にあるため。
 */
const SLACK_MAX_ITEMS = 15;

/**
 * Slack の宛先。キー → スクリプトプロパティ名と表示名。
 *
 * 宛先を増やすときはここに 1 行足すだけにする。送信側の関数は触らない。
 *
 * personal のプロパティ名を SLACK_WEBHOOK_URL のまま残しているのは、命名を
 * 揃えたい気持ちより「設定の欠落を沈黙にしない」を優先しているため。
 * 改名した .gs を貼った瞬間、プロパティを直すまで日次通知が黙って止まり、
 * それは「該当が無くて静かな日」と見分けが付かない。
 */
const SLACK_TARGETS = {
  personal: { prop: 'SLACK_WEBHOOK_URL',      label: '個人検証' },
  team:     { prop: 'SLACK_WEBHOOK_URL_TEAM', label: '会社テスト' }
};

/** SLACK_TARGET が未設定・未知のときに使う宛先。 */
const SLACK_TARGET_DEFAULT = 'personal';

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

/**
 * JPCERT/CC の RDF。注意喚起（/at/）だけ拾い、Weekly Report（/wr/）は捨てる。
 *
 * **判定には混ぜない。**注意喚起は CVE 単位ではなく「いま日本で問題になっている事象」で、
 * CVE を持たない回がある（実例: at260019「Fortinet製品に関連する認証情報の漏えい」は
 * CVE の記載が無い）。台帳の行と機械的に突き合わせられないので、緊急度の指標にはならない。
 *
 * それでも拾うのは、ツールの守備範囲（FortiOS / IOS-XE の CVE）の外に自社へ効く情報が
 * あるため。上の FortiBleed は Fortinet PSIRT のアドバイザリではないので RSS にも CSAF にも
 * 出てこず、版の突き合わせという判定の軸にも乗らない。構造的に拾えない種類の情報を、
 * 判定を通さず人に見せるだけの経路で補う。
 *
 * 頻度は年約 29 件（2023〜2026 の 4 年分 106 件を全数確認）。そのうち
 * Fortinet / Cisco 系は 6 件＝年 1.5 件なので、Slack に足しても埋もれない。
 */
const JPCERT_RSS_URL = 'https://www.jpcert.or.jp/rss/jpcert.rdf';

/** 通知済みの注意喚起 ID。スクリプトプロパティにカンマ区切りで置く。 */
const JPCERT_SEEN_PROP = 'JPCERT_SEEN_AT';

/** 既読 ID の保持上限。年 30〜40 件なので 200 あれば 5 年分。 */
const JPCERT_SEEN_MAX = 200;

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
/*
 * 列は確認する人の思考順に並べる。
 *   いつ検知した何か → どれくらい危ないか → どんな影響か → なぜその判定か
 *   → 何を確認しどう直すか → 公式で裏を取る
 * 毎日動いて新着が積まれる表なので、最終更新日は付随情報ではなく
 * 「その行が自分にとって新しいか」を判断する一次情報として先頭に置く。
 */
const LEDGER_HEADERS = [
  '最終更新日',   // 1  いつ検知したか
  '自社影響',     // 2  あり（対応検討）/ あり（影響調査）/ なし。並べ替えの第1キー
  '製品',         // 3
  'CVE',          // 4
  'CVSS',         // 5
  'KEV',          // 6  あり / なし。悪用実績は CVSS より強い信号なので隣に置く
  '脆弱性名',     // 7  CSAF / RSS の文書タイトル（短い表示）
  'ユーザ影響',   // 8  最悪ケース50字以内
  '影響機能',     // 9
  '判定根拠',     // 10 OS=… | KEV=… | ◯◯のため「結論」
  '確認方法',     // 11 確認ポイント／コマンド／判断
  '公式推奨対応', // 12 ベンダー公式（日本語）
  'アドバイザリ', // 13
  // 14 判定の検算用。条件3（AV/PR/UI）も条件4（C/I/A）もこの値から決まるのに、
  //    台帳に無いと読む人が判定根拠の正しさを確かめられない（§4.4 と同じ理由）。
  //    毎回スキャンする値ではないので末尾に置き、左6列固定の設計を崩さない。
  'CVSSベクター'
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
/*
 * 列は確認する人の思考順に並べる。「今月のものか（日付）→ 初出か改訂か（2つの日付の差）
 * → 対象か対象外か → なぜそう判定したか → 何の製品でどんな内容か → 深掘り」。
 * ツールが書きやすい順ではない。CSAF版は人が見る値ではないので末尾に置く。
 */
const STATE_HEADERS = ['最終更新日', '初回公表日', 'ベンダー', 'CVE', 'タイトル', '自社判定',
                       '判定根拠', '対象製品', 'アドバイザリID', 'CSAF版'];

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
 * 列は「確認 → 新規・改訂 → 判定 → 失敗」の順に、上流から下流へ一直線に読めるようにする。
 * 取得件数（実際に CSAF を何本ダウンロードしたか）はここに置かない。
 * Fortinet は毎回全件、Cisco は差分のみという内部事情の数字で、合計すると
 * 「確認 100 なのに取得 50、残り 50 はどこへ？」という誤読を生むため、内訳へ回す。
 *
 * 「対象」「対象以外」はアドバイザリ件数で、台帳の行数ではない。
 * 以前は「台帳追加」「台帳追加なし」と呼んでいたが、実体と合っていなかった。
 * 台帳は 1 アドバイザリが CVE × 製品で複数行に開くうえ、古い「なし」を
 * isLedgerRow_ が落とすので、どう数えてもこの列とは一致しない。
 * ここが答えるのは「自社の資産に当たる公表がいくつあったか」であり、
 * 台帳に何行増えたかではない。
 */
const RUNLOG_HEADERS = ['実行日時', '結果', '確認件数', '差分なし', '更新あり', '対象',
                        '対象以外', '失敗', '所要秒', 'AI呼び出し', '備考'];

/**
 * 人が下した対応の判断を残すシート。ツールは書かない。人だけが書く。
 *
 * 台帳に列を足す案は成立しない。removeRowsFor_ がアドバイザリの改訂ごとに
 * 台帳の行を消して書き直すので、人が書いた内容が消える。台帳は再生成できる
 * ツールの出力、ここは再生成できない人の記録、と役割を分ける。
 *
 * 列は「いつ・何に対して・どう決めたか・なぜ・誰が」の順。
 * 対象時点は改訂検知用で、メニューから起こせば自動で入る（下記）。
 */
const SHEET_DECISION = '判断記録';

/**
 * 月次報告の草案。毎回まるごと作り直すので、人はここに書き足さないこと。
 * データはスプレッドシート、通知は Slack の 2 面に閉じる（§4.9）。
 */
const SHEET_MONTHLY = '月次サマリ';
const DECISION_HEADERS = ['判断日', 'アドバイザリID', 'CVE', '判断', '根拠', '判断者', '対象時点'];

/**
 * 人の判断と、それが自社影響をどう上書きするか。
 *
 * null は「判定を変えない」。保留はツールの判定をそのまま残すための語で、
 * 記録だけ先に置きたいときに使う。
 *
 * 新しい判定値は作らない。「なし」に落とせば台帳には残り Slack からは外れる、
 * という既存の仕組みがそのまま監査要件（判断した記録を残す）を満たす。
 */
const DECISION_VERDICT = {
  '対応不要（定期更新枠）': V_NONE,
  '対応済み':               V_NONE,
  '対応する（実施待ち）':   V_ACT,
  '保留':                   null
};

/** 1 実行のあいだ判断記録を読み直さないための入れ物。実行ごとに空から始まる。 */
let decisions_ = null;

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
    processed: s.processed || 0, ledger: s.ledger || 0, labels: s.labels || {},
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
  const ui = SpreadsheetApp.getUi();
  ui.createMenu('脆弱性ウォッチャー')
    .addItem('データ削除（台帳・処理済み）', 'clearRunData')
    .addItem('Ciscoだけ再取得', 'reprocessCisco')
    .addSeparator()
    .addItem('選択行から判断記録を作る', 'createDecisionFromLedger')
    .addItem('月次サマリ草案を作る（先月分）', 'buildMonthlyReport')
    .addSeparator()
    .addSubMenu(ui.createMenu('Slack テスト送信')
      .addItem('個人検証チャンネルへ', 'sendSlackTestToPersonal')
      .addItem('会社テストチャンネルへ', 'sendSlackTestToTeam'))
    .addToUi();
}

/**
 * 判断記録シートを用意する。既にあれば何もしない（人が書いた行を触らない）。
 * 判断列にはプルダウンを付ける。語彙から外れた値は readDecisions_ が捨てるので、
 * 入力の時点で外せないようにしておく。
 */
function ensureDecisionSheet_() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(SHEET_DECISION);
  if (sh) return sh;

  sh = ss.insertSheet(SHEET_DECISION);
  sh.appendRow(DECISION_HEADERS);
  sh.setFrozenRows(1);
  sh.setColumnWidth(DECISION_HEADERS.indexOf('根拠') + 1, 380);
  sh.setColumnWidth(DECISION_HEADERS.indexOf('判断') + 1, 180);
  applyDecisionValidation_(sh, 2, 200);
  Logger.log('「判断記録」シートを作成しました。');
  return sh;
}

/** 判断列のプルダウン。語彙は DECISION_VERDICT のキーがそのまま正。 */
function applyDecisionValidation_(sh, startRow, numRows) {
  const rule = SpreadsheetApp.newDataValidation()
    .requireValueInList(Object.keys(DECISION_VERDICT), true)
    .setAllowInvalid(false)
    .build();
  sh.getRange(startRow, DECISION_HEADERS.indexOf('判断') + 1, numRows, 1)
    .setDataValidation(rule);
}

/**
 * 台帳で選んだ行から判断記録の行を起こす。
 *
 * 対象時点（改訂検知に使う）を人に手で書かせない。台帳の最終更新日をそのまま
 * 写す。ここを人任せにすると空欄や打ち間違いが出て、readDecisions_ がその行を
 * 捨てる。捨てられたことは気づきにくいので、機械が埋められる欄は機械が埋める。
 *
 * 判断と根拠は空のまま作る。そこは人が決めることで、既定値を置くと
 * 選ばれないまま残る。
 */
function createDecisionFromLedger() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sh = ss.getActiveSheet();
  if (sh.getName() !== SHEET_LEDGER) {
    ss.toast('「台帳」シートで、判断を記録したい行を選んでから実行してください。', '判断記録', 8);
    return;
  }

  const sel = sh.getActiveRange();
  const first = Math.max(sel.getRow(), 2);          // 見出し行は対象外
  const last = sel.getRow() + sel.getNumRows() - 1;
  if (last < first) {
    ss.toast('データ行が選ばれていません。', '判断記録', 8);
    return;
  }

  const n = last - first + 1;
  const text = sh.getRange(first, 1, n, LEDGER_HEADERS.length).getDisplayValues();
  const vals = sh.getRange(first, 1, n, LEDGER_HEADERS.length).getValues();
  const cId = COL['アドバイザリ'] - 1;
  const cCve = COL['CVE'] - 1;
  const cUpd = COL['最終更新日'] - 1;

  const today = new Date();
  const by = Session.getActiveUser().getEmail() || '';
  const rows = [];
  text.forEach(function (t, i) {
    const id = String(t[cId] || '').trim();
    if (!id) return;
    rows.push([today, id, String(t[cCve] || '').trim(), '', '', by, vals[i][cUpd] || '']);
  });

  if (!rows.length) {
    ss.toast('アドバイザリID を読める行がありませんでした。', '判断記録', 8);
    return;
  }

  const dst = ensureDecisionSheet_();
  const start = dst.getLastRow() + 1;
  dst.getRange(start, 1, rows.length, DECISION_HEADERS.length).setValues(rows);
  dst.getRange(start, 1, rows.length, 1).setNumberFormat('yyyy/mm/dd');
  dst.getRange(start, DECISION_HEADERS.indexOf('対象時点') + 1, rows.length, 1)
     .setNumberFormat('yyyy/mm/dd');
  applyDecisionValidation_(dst, start, rows.length);

  ss.toast(rows.length + ' 行を作りました。判断記録シートで「判断」と「根拠」を埋めてください。',
           '判断記録', 8);
  Logger.log('判断記録: 台帳から ' + rows.length + ' 行を起こしました。');
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

  ensureDecisionSheet_();

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

    // JPCERT の注意喚起は判定に混ぜない。取得して通知へ渡すだけ。
    const alerts = newJpcertAlerts_(readAssets_());
    runStats_.jpcert = alerts.length;

    if (notifyRows.length || alerts.length) {
      // 送れた分だけ既読にする。先に印を付けると、Webhook が失効していた日の
      // 注意喚起が誰にも届かないまま消える。
      if (notifySlack_(notifyRows, '', alerts)) markJpcertSeen_(alerts);
    } else {
      backfillAiColumns_();
    }
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
  const labelTotals = {};
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
    }
    // 記録の有無に関わらず、これから書く分は先に消す。前回の実行が台帳を書いた直後に
    // 落ちていると記録が付いておらず、消さずに追記すると同じ行が二重に並ぶ。
    removeRowsFor_(VENDOR_FORTINET, todo.map(function (f) { return f.item.ir; }));

    let rows = [];
    todo.forEach(function (f) {
      if (f.error) {
        Logger.log((f.missing ? 'CSAF未作成: ' : 'CSAF 取得失敗（翌日再取得）: ') +
                   f.item.ir + ' / ' + f.error);
        // RSS に CVSS と説明文があるので、それだけで台帳の行にする。
        // 台帳から落とすと実行ログ以外に痕跡が残らない。
        rows.push(extractFortinetRowFallback_(f.item, assets));
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

    // 取得に失敗した件も記録する（Cisco と同じ方針）。
    // 以前は記録せず翌日やり直していたが、それは失敗が台帳に出ず誰も気づけなかったため。
    // フォールバック行を台帳へ出すようにしたので、その前提は無くなった。
    //
    // 記録してもリトライは止まらない。Fortinet は毎回 RSS 全件の CSAF を取りに行くので、
    // 取得自体は毎日続く。記録が止めるのは台帳への再反映だけで、
    // CSAF が取れるようになった日に版の不一致（未取得 ≠ 0）で自動的に拾われる。
    // 記録しないと、未解決の件が毎日 Slack に出続けることになる。
    const recordable = todo.map(function (f) {
      if (!f.error) return f;
      // 版の欄を空にせず印を置く。空欄のままだと「入力漏れ」と区別が付かない。
      return { item: f.item, csaf: f.csaf, updatedAt: f.updatedAt,
               version: STATE_VERSION_UNAVAILABLE, error: f.error, missing: f.missing };
    });
    const judgeRows = snapshotJudgeRows_(rows);

    const ledgerRows = rows.filter(function (r) { return isLedgerRow_(r, assets); });
    Logger.log('Fortinet 台帳: ' + ledgerRows.length + ' / ' + rows.length + ' 行');

    fillLedgerDisplay_(ledgerRows);

    writeLedger_(ledgerRows);

    // 処理済みへの記録は台帳へ書き終えてから。逆順だと、AI 生成中に 6 分の実行時間制限に
    // 当たったとき「処理済みには記録されたが台帳には無い」状態が残り、
    // 翌日以降は既知として扱われて改訂まで台帳に載らない。
    // この順なら、途中で落ちても記録が付かないので次の実行でやり直せる。
    mergeCounts_(labelTotals, writeState_(VENDOR_FORTINET, recordable, judgeRows, assets));

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
    labels: labelTotals,
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
  // 製品が分からない行を通すのは、CSAF が取れなかったときだけ。
  // それ以外で製品が空なのは抽出の失敗なので、従来どおり落とす。
  // 通さないと、取得に失敗した件が台帳から消えて誰も気づけなくなる。
  if (!row.product) return !!row.noCsaf;
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
  const labelTotals = {};

  while (true) {
    const known = getKnownState_(VENDOR_CISCO);
    const pending = fetched.filter(function (f) {
      // hasError を渡す。渡さないと、記録済みなのに CSAF が取れなかった件で
      // 版の比較（記録は「未取得」／取得結果は空）が永久に一致せず、
      // 毎日その件を作り直して Slack にも出し続ける。
      // いまは selectRssCsafCandidates_ が手前で弾くので表面化しないが、
      // それは偶然で、この関数自身が同じ答えを返せなければ揃っていない。
      return needsAdvisoryProcessing_(f.item.id, f.updatedAt, f.version, known, !!f.error);
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

    // 記録の有無に関わらず、これから書く分は先に消す。前回の実行が台帳を書いた直後に
    // 落ちていると記録が付いておらず、消さずに追記すると同じ行が二重に並ぶ。
    removeRowsFor_(VENDOR_CISCO, todo.map(function (f) { return f.item.id; }));

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
        const fb = extractCiscoRowFallback_(fallbackItem, assets);
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

    // 取得に失敗した件も記録する。Fortinet は記録しない（＝翌日やり直す）が、
    // Cisco は失敗時にフォールバック行を台帳へ出し Slack でも知らせるため、
    // 記録しないと毎日同じ行を作り直すことになる。人に渡した時点で自動リトライは要らない。
    // ただし版を空のままにすると selectRssCsafCandidates_ の「版が空なら再取得」に
    // 毎回引っかかり、取得できない件を永久に取り続ける。印を書いてループを止める。
    const recordable = todo.map(function (f) {
      if (!f.error) return f;
      return { item: f.item, csaf: f.csaf, updatedAt: f.updatedAt,
               version: STATE_VERSION_UNAVAILABLE, error: f.error, missing: f.missing };
    });
    const judgeRows = snapshotJudgeRows_(rows);

    const ledgerRows = rows.filter(function (r) { return isLedgerRow_(r, assets); });
    Logger.log('Cisco 台帳: ' + ledgerRows.length + ' / ' + rows.length + ' 行');

    fillLedgerDisplay_(ledgerRows);

    writeLedger_(ledgerRows);

    // 処理済みへの記録は台帳へ書き終えてから（理由は runFortinet_ の同じ箇所）。
    mergeCounts_(labelTotals, writeState_(VENDOR_CISCO, recordable, judgeRows, assets));

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
    ledger: allLedgerRows.length,
    labels: labelTotals
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
    ? csafDate_(tracking.current_release_date, item.pubDate)
    : csafDate_(tracking.initial_release_date, item.pubDate);
  const initialAt = csafDate_(tracking.initial_release_date, updatedAt);
  const vulnName = String(doc.title || item.title || '').trim();
  const idMap = ciscoProductMap_(csaf);
  const configHints = ciscoConfigHints_(csaf);
  const docClasses = ciscoDocCveClasses_(csaf);
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
    // 行の題名は CVE ごとの title を優先する。Cisco は vulnerabilities[].title に
    // CVE 単位の名前を持ち、1 アドバイザリに複数 CVE がある 11 件のうち 8 件で
    // 行ごとに違う名前が出る（ClamAV の 7 行が ZIP・PDF・Mach-O と分かれる）。
    // アドバイザリ全体の題名を全行に並べると、どの行が何の脆弱性か読めない。
    // 無いときだけ全体の題名に落とす。Fortinet には持ち込まない
    // （あちらの CVE ごとの title は 'FortiOS - LOW - FG-IR-…' で中身が無い）。
    const rowTitle = String(v.title || '').trim() || vulnName;

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

    // CVE 側に何も書かれていないアドバイザリがある。Security Hardening Release は
    // vulnerabilities[].title が全件同一で notes も「Complete.」だけ（実測）。
    // その場合でも document.notes に CVE ごとの CWE 分類表が載っているので、
    // そこから補う。無いと確認する人に手がかりが 1 つも渡らない。
    const summary = [
      noteText_(v, function (n) { return n.category === 'summary'; }),
      docClasses[String(v.cve || '').toUpperCase()] || '',
      configHints
    ].filter(function (s) { return s; }).join('\n\n');

    return {
      vendor: VENDOR_CISCO,
      advisoryId: advisoryId,
      advisoryUrl: item.link,
      pubDate: updatedAt,
      initialDate: initialAt,
      title: rowTitle,
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
function extractCiscoRowFallback_(item, assets) {
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
    // 製品は空のまま（理由は extractFortinetRowFallback_ と同じ）。
    // Cisco の RSS タイトルには製品名が入るが、そこから当てにはいかない。
    // 影響製品を 1 つしか名乗らない題名があり、ClamAV 型は製品名すら書かない。
    // CSAF が無い状態で製品を断定するのは、ここで直している誤りと同じになる。
    product: '',
    noCsaf: true,
    cvss: meta.cvss,
    severity: meta.severity,
    vector: '', unauthRemote: '',
    affected: [],
    summary: decodeCiscoHtml_(item.description || ''),
    impact: '',
    fixesRaw: '',
    workaround: '',
    verdict: V_INVEST,
    // reason ではなく reasonPhrase に置く。reason は decideNotification_ が
    // 「OS=… | KEV=…」の見出しごと組み立て直すので、ここで書いても消える。
    reasonPhrase: 'CSAF を取得できず製品も版も特定できないため',
    selfVersion: '', fixVersion: '',
    feature: '', impactJa: '', howToCheck: '', plan: ''
  };
}

/**
 * document.notes に載っている「CVE ごとの脆弱性クラス」の表を読む。
 *
 * Security Hardening Release のように、CVE 側のフィールドが空でここにしか
 * 中身が無いアドバイザリがある。表はプレーンテキストで
 *   CVE-2026-20267 9.0 CWE-284 Improper access control (covers ...)
 * のように 1 行ずつ並ぶので、CVE の直前で区切って読む。
 *
 * 表が無ければ空を返す。無理に拾わない（誤った説明を付けるくらいなら何も付けない）。
 */
function ciscoDocCveClasses_(csaf) {
  const out = {};
  (((csaf || {}).document || {}).notes || []).forEach(function (n) {
    const t = String(n.text || '').replace(/\s+/g, ' ');
    if (t.indexOf('CWE-') === -1 || t.indexOf('CVE-') === -1) return;
    const re = /(CVE-\d{4}-\d{4,})\s+([\d.]+)\s+(CWE-\d+)\s+(.*?)(?=CVE-\d{4}-\d{4,}|$)/g;
    let m;
    while ((m = re.exec(t)) !== null) {
      const text = (m[3] + ' ' + m[4]).replace(/\s+/g, ' ').trim();
      if (text) out[m[1].toUpperCase()] = text;
    }
  });
  return out;
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
    // description 末尾の "Revised on YYYY-MM-DD" を拾う。
    // 判定には使わない（CSAF の改訂と 41/49 でしか一致せず、見逃しと空振りを生む）。
    // CSAF が取れなかった件の「最終更新日」を埋めるためだけに使う。
    // そこは RSS が唯一の情報源で、使わないと公表日を最終更新日として書くことになる。
    const desc = item.getChildText('description') || '';
    const rev = /Revised on\s*(\d{4})-(\d{2})-(\d{2})/.exec(desc);

    return {
      ir: m ? m[0] : link,
      title: item.getChildText('title'),
      link: link,
      pubDate: parsePubDate_(item.getChildText('pubDate')),
      revisedOn: rev ? new Date(Number(rev[1]), Number(rev[2]) - 1, Number(rev[3])) : '',
      description: desc
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
 *   - CSAF 版が空欄の既存行。取得に失敗した件には「未取得」の印を書くので、
 *     ここに引っかかるのは印が付く前に記録された古い行だけ。
 *     印を書かずに空欄のままにすると、取得できない件を毎日取り続けることになる
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
      // 失敗時の日付は Fortinet と同じ lastSeenDate_ を通す。Cisco の item は
      // revisedOn を持たないので結果は it.pubDate と同値（実測で確認）。
      // 揃えておくのは、両ベンダーの失敗経路を読み比べたときに
      // 「なぜ違うのか」を考えさせないため。差があるなら根拠が要る（§4.5）。
      return { item: it, csaf: null, updatedAt: lastSeenDate_(it), version: '', error: String(e) };
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
        return { item: it, csaf: null, updatedAt: lastSeenDate_(it), version: '',
          error: 'CSAF の解析に失敗: ' + e, missing: false };
      }
    }

    if (code === 404) {
      missing++;
      return { item: it, csaf: null, updatedAt: lastSeenDate_(it), version: '',
        error: 'CSAF未作成（HTTP 404。ベンダーがこのアドバイザリの CSAF を出していない）',
        missing: true };
    }

    failed++;
    return { item: it, csaf: null, updatedAt: lastSeenDate_(it), version: '',
      error: 'CSAF 取得失敗 HTTP ' + code, missing: false };
  });

  Logger.log('CSAF 取得: 成功 ' + ok + ' / CSAF未作成 ' + missing + ' / 失敗 ' + failed +
             '（全 ' + items.length + ' 件）');
  if (failed) {
    Logger.log('  失敗した件は処理済みに記録していません。翌日の実行で取り直します。');
  }
  return out;
}

/**
 * CSAF が取れなかった件の「最終更新日」に使う日付。
 *
 * CSAF が無いと更新日を名乗れる値が無く、公表日で代用すると
 * 「2022 年から一度も更新されていない」ように見える。実際には Fortinet が
 * 2026-08-27 に改訂しており、その事実は RSS の description にしか無い。
 * 判定には使わず、表示する日付としてだけ採用する。
 */
function lastSeenDate_(item) {
  const pub = (item && item.pubDate) || '';
  const rev = (item && item.revisedOn) || '';
  if (rev instanceof Date && pub instanceof Date) return rev > pub ? rev : pub;
  return rev || pub;
}

/**
 * CSAF の日付を Date にする。日本時間に変換して扱う。
 *
 * Cisco の CSAF は "2026-08-19T16:00:00+00:00" のように UTC の 16 時で出るため、
 * 日本時間では翌日 8/20 になる。Cisco の公表ページ（August 19）とは 1 日ずれるが、
 * 運用が日本時間である以上、日本時間で読める方を優先する（月末締めの要件は無い）。
 * 日次トリガーは 9 時台なので、8/20 に拾う件が 8/20 と記録されるのは動きとも合う。
 *
 * Fortinet の CSAF は "2025-08-08T00:00:00" とタイムゾーンを持たず、
 * 実行環境のローカル時刻＝日本時間として解釈されるため、こちらは元から日付が動かない。
 */
function csafDate_(value, fallback) {
  if (!value) return fallback;
  const d = new Date(value);
  return isNaN(d.getTime()) ? fallback : d;
}

function csafUpdatedAt_(csaf, item) {
  const t = ((csaf || {}).document || {}).tracking || {};
  if (t.current_release_date) return csafDate_(t.current_release_date, item.pubDate);
  if (t.initial_release_date) return csafDate_(t.initial_release_date, item.pubDate);
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
    ? csafDate_(tracking.current_release_date, item.pubDate)
    : csafDate_(tracking.initial_release_date, item.pubDate);
  const initialAt = csafDate_(tracking.initial_release_date, updatedAt);

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

/**
 * CSAF が取れなかった Fortinet アドバイザリを、RSS の情報だけで台帳の行にする。
 *
 * アドバイザリページは altcha のボット対策で待機ページしか返らず、
 * プログラムからは本文を取得できない（実測: "Just a moment — verifying connection security"）。
 * 一方 RSS の description には CVSS と説明文が入っており、追加のリクエストも要らない。
 * 取れる情報があるのに台帳から落として通知だけにするのは、確認の手がかりを捨てている。
 * Cisco は以前からこの形（extractCiscoRowFallback_）で、Fortinet だけ無かった。
 *
 * 製品は資産シートのそのベンダーの対象製品を使う。RSS のタイトルに製品名が無く
 * 特定できないため、「自社に関係するかもしれない」側に倒して人の目に入れる。
 * 実際の影響製品はアドバイザリを開いて確認してもらう。
 */
function extractFortinetRowFallback_(item, assets) {
  const text = decodeCiscoHtml_(item.description || '');
  const cvss = /CVSSv3 Score:\s*([\d.]+)/i.exec(text);
  const cves = text.match(/CVE-\d{4}-\d{4,}/gi) || [];

  return {
    vendor: VENDOR_FORTINET,
    advisoryId: item.ir,
    advisoryUrl: item.link,
    pubDate: lastSeenDate_(item),
    initialDate: item.pubDate,
    title: item.title,
    cve: cves.length ? cves[0].toUpperCase() : '',
    // 製品は空のままにする。CSAF が無い以上どの製品かは分からず、
    // 自社の主力製品を充てると「分からない」が「FortiOS だと分かった」に化ける。
    // decideNotification_ が空を見て「製品を特定できないため → 影響調査」に落とし、
    // 台帳の製品列は toRowArray_ が「不明」と表示する。
    product: '',
    noCsaf: true,
    cvss: cvss ? cvss[1] : '',
    severity: '',
    vector: '', unauthRemote: '',
    affected: [],
    summary: text.replace(/\s+/g, ' ').trim(),
    impact: '',
    fixesRaw: '',
    workaround: '',
    verdict: V_INVEST,
    // reason ではなく reasonPhrase に置く。reason は decideNotification_ が
    // 「OS=… | KEV=…」の見出しごと組み立て直すので、ここで書いても消える。
    reasonPhrase: 'CSAF を取得できず製品も版も特定できないため',
    selfVersion: '', fixVersion: '',
    feature: '', impactJa: '', howToCheck: '', plan: ''
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

/**
 * Cisco の影響機能の統制語彙。featureExposure_ が露出を引ける値だけを許す。
 * ここに無い値が入ると exposure が unknown になり、判定が
 * 「影響機能を特定できないため」に固定される。
 */
const CISCO_FEATURE_VOCAB = {
  'WebUI': 1, 'BEEP': 1, 'XMCP Server': 1, 'SD-WAN': 1, 'SNMP': 1, 'SSH': 1,
  'IOS XE 基盤': 1, 'データプレーン': 1, '管理GUI': 1, 'その他': 1
};

/**
 * 統制語彙に無い影響機能か。語彙外ならタイトル由来の値へ落とす。
 *
 * 以前は英語の断片だけを弾いていたので、AI が返した日本語は何でも通っていた。
 * 実測（2026-09-04）で「アクセス制御」「CLI処理」「メモリ管理」のような
 * **脆弱性の種類**が影響機能の欄に入り、機能とは軸の違う値が台帳に並んだ。
 *
 * featureExposure_ はそれらを unknown としか読めないので判定は動かない一方、
 * countFeatures() では別々のバケツに散るため「影響機能を特定できていない行の
 * 割合」を過少に見せる。**判定は変わらないのに計測だけ壊れる**のが厄介で、
 * 直したつもりになってしまう。
 *
 * Fortinet には isFortinetFeatureVocab_ で同じ強制がある。ベンダーで差を付ける
 * 根拠が無いので揃える。
 */
function isJunkCiscoFeature_(feature) {
  const s = String(feature || '').trim();
  if (!s || s === '不明') return true;
  return !CISCO_FEATURE_VOCAB[s];
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
/**
 * CSAF が取れず製品を特定できなかった行の確認方法。
 *
 * 機器固有のコマンドを書かない。**まずアドバイザリ本体を開くのが最初の一歩**で、
 * 製品が分からないまま打つコマンドには意味がない。
 */
const CHECK_STEPS_NO_CSAF = [
  '確認ポイント：アドバイザリ本体を開き、影響製品と影響範囲を確認する',
  'アクション：自社の保有製品に当たるかを判断し、当たるなら版を突き合わせる',
  '判断：当たらなければ対象外。当たるなら影響機能を特定して確認コマンドへ進む'
].join('\n');

function normalizeHowToCheck_(row) {
  const raw = String(row.howToCheck || '').trim();

  // 製品を特定できていない行に、機器固有のコマンドを出させない。
  //
  // 実例（2026-09-06 の実運用）: CSAF が取れなかった FG-IR-22-059
  // （OpenSSL ライブラリの脆弱性）に、AI が「show vpn ssl settings」と書いた。
  // 判定根拠は「製品も版も特定できない」なのに、確認方法は特定できている前提に
  // なっていて矛盾する。打っても意味がないうえ、出力が無いと「影響なし」と
  // 誤解される。AI は RSS の説明文から推測できてしまうので、ここで止める。
  if (row.noCsaf || !String(row.product || '').trim()) return CHECK_STEPS_NO_CSAF;

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
    // 値は true ではなく登録主体（vendorProject）。KEV の登録が別ベンダーの
    // 製品に対するものかを判定根拠に書くために要る（kevVendor_ 参照）。
    // 空文字は入れない。!!set[cve] で掲載を見ているので偽になってしまう。
    if (v.cveID) {
      set[String(v.cveID).toUpperCase()] = String(v.vendorProject || '').trim() || '登録元不明';
    }
  });
  // product まで持つと 78KB になり、CacheService の 100KB 上限まで 470 件しか
  // 余裕が無くなる。vendorProject だけなら 47.6KB で、あと 1,800 件は入る
  // （2026-08-31 版 1,687 件で実測）。
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

/**
 * KEV でその CVE を登録している主体（vendorProject）。分からなければ空。
 *
 * 値が文字列でないときは空を返す。値を true で入れていた頃のキャッシュが
 * 最大 6 時間残るので、その間に落ちないようにする。
 */
function kevVendor_(cve) {
  if (!cve) return '';
  try {
    const v = fetchKevCatalog_()[String(cve).toUpperCase()];
    return (typeof v === 'string') ? v : '';
  } catch (e) {
    return '';
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
 * 9.8 でも管理者権限が前提なら、悪用できる者は既に機器の制御を持っている。
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

/**
 * 設定に関係なく常に有効な機能（社内ルール 条件5）。
 *
 * **ここに設定依存の機能を足さないこと。**この表に載る行だけが impactSeverity_ の
 * 判定へ進み、そこでは A:H を「業務停止」と読んでいる。その読み方は
 * 「基盤が止まれば業務が止まる」という前提に立っているので、管理画面のように
 * 設定次第で止められる機能を足すと前提が崩れ、管理画面の DoS まで臨時更新に上がる
 * （impactSeverity_ のコメント参照）。
 */
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

/**
 * 臨時更新条件4（悪用されると機器の制御を奪われるか業務停止に至る）の判定。
 *
 * **一次情報は CVSS ベクターの C/I/A。**条件3（AV:N / PR:N / UI:N）を
 * ruleGate_ が同じベクターから読んでいるのに、条件4だけ英文のキーワード照合という
 * 別の方法を使っていたのが誤りだった。ベンダーが記述文に何を書くかに依存せず、
 * 構造化された値から読む。
 *
 *   I:H  設定・データを高影響で書き換えられる    → 機器の制御を奪われる
 *   A:H  可用性が完全に失われる                  → 業務停止（前提は下記）
 *   C:H のみ（I/A は N か L）                    → 情報漏えい。条件4の文言には当たらないが、
 *        漏れるのが管理者の認証情報なら制御を奪われる入口になる。CVSS は
 *        「何が漏れるか」を区別しないので機械には判断できない → infoleak
 *   すべて L 以下                                → 部分的な影響にとどまる → no
 *
 * **A:H を「業務停止」と読んでよいのは、この判定に来る行が限られているから。**
 * CVSS の A:H の定義は「影響を受けるコンポーネントの可用性が完全に失われる」で、
 * コンポーネント＝機器全体とは限らない。デーモン 1 本が落ちるだけでも A:H は付く。
 * 実際このコードは ユーザ影響の文面では区別している（isReloadDos_ = 機器が再起動 /
 * isMgmtPlaneDos_ = 管理画面が止まる）。
 *
 * それでも丸めてよいのは、finalizeVerdict_ がここへ来るのを exposure が always の行
 * （FEATURE_ALWAYS_ON = データプレーン / IOS XE 基盤）だけに絞っているため。
 * **基盤が止まれば業務が止まる**ので、そこでは A:H = 業務停止で正しい。
 * 管理画面の DoS は WebUI / 管理GUI = config なので手前で「影響調査」になる。
 *
 * **FEATURE_ALWAYS_ON に設定依存の機能を足すと、この前提が崩れる。**
 * 管理画面の DoS まで臨時更新に上がるので、足すときはここも見直すこと。
 *
 * Scope（S:U / S:C）は見ない。S:U でも基盤が止まれば業務は止まるので、
 * S で絞ると見逃す方向に働く。
 *
 * A:L（性能低下）を業務停止に含めない。含めると軽微な劣化まで臨時更新に上がる。
 * AC（攻撃の難しさ）は見ない。社内ルールの条件3が AV/PR/UI の 3 つだけで
 * AC を含めていないため（2026-09-04 に現状維持で確認）。
 *
 * **ベクターを AI の出力より先に見る。**ベンダーが公開した構造化データより、
 * 記述文から推測した値（takeover / serviceStop）を優先する理由が無い。
 * ベクターが無いときだけ AI と記述文へ落ちる。CVSS v4（VC:H 形式）は
 * parseCvssCia_ が読めず null を返すので、この経路に来る。
 * 拾えなければ unknown（＝調査へ）。
 *
 * @return {'yes'|'infoleak'|'no'|'unknown'}
 */
function impactSeverity_(row) {
  // ベクターが読めればそれが答え。**AI の出力より先に見る。**
  // ベンダーが公開した構造化データより、記述文から推測した値を優先する理由が無い。
  // 以前は takeover/serviceStop（AI の出力）を先に見ていたので、ベクターが
  // C:N/I:N/A:L（軽微）でも AI が total と返せば「対応検討」になっていた。
  // 「条件4はベクターで判定する」という決めと矛盾していた。
  const p = parseCvssCia_(row.vector);
  if (p) {
    if (p.I === 'H' || p.A === 'H') return 'yes';
    if (p.C === 'H') return 'infoleak';
    return 'no';
  }

  // ここから下はベクターが読めないときだけ。CVSS v4（VC:H 形式）や、
  // CSAF が取れず RSS だけで作ったフォールバック行がこの経路に来る。
  if (row.takeover === 'total') return 'yes';
  if (row.serviceStop === 'はい') return 'yes';

  // ベンダーが平文で書く「remote code execution」と CWE 語彙の
  // 「improper neutralization of special elements」は同じことを指すので両方を見る。
  // 当てられなければ「無い」ではなく「分からない」を返す。
  const text = [row.impact, row.title, row.summary].join(' ').toLowerCase();
  if (/remote code|code execution|\brce\b|arbitrary code|command injection|denial of service|\bdos\b/.test(text) ||
      /improper access control|neutralization of special elements|argument injection|bounds of a memory buffer|buffer overflow|out-of-bounds/.test(text)) {
    return 'yes';
  }
  return 'unknown';
}

/** 条件4を満たすか。KEV 分岐など真偽だけ要る場所から使う。 */
function isSevereImpact_(row) {
  return impactSeverity_(row) === 'yes';
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
    // KEV の登録主体が、このアドバイザリのベンダーと違うことがある。
    // FG-IR-26-139 の CVE-2026-31431 は Fortinet の告知だが、KEV の登録は
    // Linux / Kernel で、FortiGate 上で悪用された実績ではない。
    // 判定は変えない（悪用実績を「使っていないはず」で流さない）が、
    // 根拠に由来を書かないと「悪用が確認されている」が言い過ぎになる。
    const src = kevVendor_(row.cve);
    const note = (src && src !== row.vendor) ? '（KEV登録: ' + src + '）' : '';
    if (exposure === 'always' && gate.pass && isSevereImpact_(row)) {
      row.verdict = V_ACT;
      row.reasonPhrase = '悪用が確認されており外部から到達するため' + note;
    } else {
      row.verdict = V_INVEST;
      row.reasonPhrase = '悪用が確認されているため' + note;
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
  } else {
    // 条件4はベクターの C/I/A で決める（impactSeverity_）。
    // 「至らない」と言い切れるのはベクターが読めたときだけ。
    // 分からない行を「なし」にすると Slack からも消えて誰も気づけない。
    const sev = impactSeverity_(row);
    if (sev === 'yes') {
      row.verdict = V_ACT;
      row.reasonPhrase = '外部から無認証で' + row.feature +
                         'を悪用され、機器の制御を奪われるか業務停止に至るため';
    } else if (sev === 'infoleak') {
      row.verdict = V_INVEST;
      row.reasonPhrase = '読み取られる情報の範囲を確認する必要があるため';
    } else if (sev === 'unknown') {
      row.verdict = V_INVEST;
      row.reasonPhrase = '影響の種類を特定できず深刻度を判定できないため';
    } else {
      row.verdict = V_NONE;
      row.reasonPhrase = '機器の制御を奪われることも業務停止に至ることもないため';
    }
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
/**
 * 自社影響を決める。ツールのルールで判定してから、人の判断があれば上書きする。
 *
 * 2 段に分けているのは「ツールがどう判定し、人がどう覆したか」を分けて
 * 追えるようにするため。人の判断をルールの中へ混ぜると、判定根拠を読んでも
 * それがツール由来か人由来か分からなくなる。
 */
function decideNotification_(row, assets) {
  decideByRules_(row, assets);
  applyHumanDecision_(row);
}

/** 判断記録を 1 実行につき 1 回だけ読む。 */
function getDecisions_() {
  if (!decisions_) decisions_ = readDecisions_();
  return decisions_;
}

/**
 * 判断記録シートを読み、`アドバイザリID|CVE` で引けるようにする。
 * CVE 欄が空の行はそのアドバイザリ全体に効く（キーは `ID|`）。
 *
 * 語彙にない判断と、対象時点が空の行は捨ててログに出す。
 * とくに対象時点が無い行は改訂の有無を判定できない。分からないまま
 * 「対応不要」を効かせると見逃しになるので、効かせない側に倒す。
 * 捨てた行はツールの判定のまま台帳に出続けるので、間違いに気づける。
 */
function readDecisions_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_DECISION);
  if (!sh || sh.getLastRow() < 2) return {};

  const n = sh.getLastRow() - 1;
  const range = sh.getRange(2, 1, n, DECISION_HEADERS.length);
  const text = range.getDisplayValues();   // ID は =HYPERLINK() のことがある
  const vals = range.getValues();          // 日付は Date のまま欲しい

  const map = {};
  let dropped = 0;
  for (let i = 0; i < n; i++) {
    const id = String(text[i][1] || '').trim();
    if (!id) continue;

    const action = String(text[i][3] || '').trim();
    if (!DECISION_VERDICT.hasOwnProperty(action)) {
      Logger.log('判断記録: ' + id + ' の判断「' + action + '」は語彙に無いので無視します。');
      dropped++;
      continue;
    }

    const asOf = vals[i][6];
    if (!(asOf instanceof Date) || isNaN(asOf.getTime())) {
      Logger.log('判断記録: ' + id + ' は対象時点が空なので無視します。' +
                 '改訂されたかどうかを判定できません。');
      dropped++;
      continue;
    }

    map[id + '|' + String(text[i][2] || '').trim().toUpperCase()] = {
      decidedAt: vals[i][0],
      action: action,
      note: String(text[i][4] || '').trim(),
      by: String(text[i][5] || '').trim(),
      asOf: asOf
    };
  }
  const kept = Object.keys(map).length;
  if (kept || dropped) Logger.log('判断記録: 有効 ' + kept + ' 件 / 無視 ' + dropped + ' 件');
  return map;
}

/**
 * この行に効く判断を引く。CVE 指定があればそれを優先し、無ければアドバイザリ全体の判断。
 *
 * 判断はそのアドバイザリの「その時点の内容」に対して下したもの。改訂で影響範囲や
 * 修正版が変わったのに前回の「対応不要」が効き続けたら見逃しになる。
 * 最終更新日が対象時点より新しければ判断は無効にし、ツールの判定へ戻す。
 * 既読判定を current_release_date と版で行っているのと同じ考え方。
 */
function lookupDecision_(row) {
  const id = String(row.advisoryId || '').trim();
  if (!id) return null;

  const all = getDecisions_();
  const d = all[id + '|' + String(row.cve || '').trim().toUpperCase()] || all[id + '|'];
  if (!d) return null;

  if (row.pubDate instanceof Date && ymd_(row.pubDate) > ymd_(d.asOf)) {
    Logger.log('判断記録: ' + id + ' は ' + ymd_(d.asOf) + ' 以降に改訂されたため、' +
               '判断「' + d.action + '」を無効にしました。');
    return null;
  }
  return d;
}

/**
 * ツールの判定に人の判断をかぶせる。
 *
 * AI は呼ばない。人が結論を出した行の影響機能を分類しても結論は変わらない。
 * ただし表示列は空にせず、コードのフォールバックで埋める（needsCodeDisplay）。
 */
function applyHumanDecision_(row) {
  const d = lookupDecision_(row);
  if (!d) return;

  const verdict = DECISION_VERDICT[d.action];
  if (verdict) row.verdict = verdict;

  row.humanDecision = d.action;
  row.reasonPhrase = ymd_(d.decidedAt) + ' に ' + (d.by || '記名なし') +
                     ' が「' + d.action + '」と判断' +
                     (d.note ? '（' + truncateJa_(d.note, 60) + '）' : '');
  row.reason = buildDecisionReason_(row);

  row._lockedVerdict = true;
  row.needsVerdict = false;
  row.needsDisplayAi = false;
  row.needsFortinetAi = false;
  row.needsCodeDisplay = true;
}

function decideByRules_(row, assets) {
  if (row._lockedVerdict) return;

  initDecisionFields_(row);
  row.fixVersion = pickFixVersion_(row);

  if (!row.product) {
    row.verdict = V_INVEST;
    row.osStatus = '不明';
    row.kev = kevLabel_(row.cve);
    // 行が理由を持っていればそれを使う。CSAF が取れなかった行にとっては
    // 「製品を特定できない」は結果であって理由ではない。
    row.reasonPhrase = row.reasonPhrase || '製品を特定できないため';
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
/**
 * 台帳と Slack に出す「公式推奨対応」。**空文字を返さないこと。**
 *
 * 以前は Fortinet で修正版が取れないと空を返していた。台帳の列が空欄になると
 * 入力漏れと区別が付かず（§4.1）、しかも Slack 側は slackActionLine_ が
 * 「アドバイザリを確認」を補っていたので、同じ行が台帳と Slack で違って見えていた。
 */
function formatOfficialAction_(row) {
  if (row.vendor !== VENDOR_CISCO) {
    const fix = jpFix_(row);
    return fix ? jpFixEnglishFallback_(fix) : '更新先はアドバイザリで確認';
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
function ownershipJudgement_(f, advisoryRows, assets) {
  // 値の先頭は必ず 対象 / 対象外 / 判定不能 にする。列を眺めたときに
  // 可否が最初の 2〜3 文字で読めないと、根拠として使えない。
  if (f && f.error) {
    return { label: '判定不能', reason: 'CSAF を取得できず判定できない' };
  }
  if (isCiscoInformationalAdvisory_(f && f.csaf, f && f.item)) {
    return { label: STATE_JUDGE_INFO, reason: '脆弱性ではなく公開一覧のお知らせ' };
  }

  const owned = (advisoryRows || []).filter(function (r) {
    return r.product && assetsForProduct_(assets || [], r.product).length;
  });
  if (!owned.length) {
    return { label: '対象外-未保有', reason: '資産に該当する製品が無い' };
  }

  const hit = owned.filter(function (r) { return r.osStatus !== '対象外'; });
  if (hit.length) {
    // ここで reasonPhrase を使ってはいけない。版が影響範囲内だった行では
    // decideNotification_ が社内ルールを当てて「悪用に管理者権限が必要なため」のような
    // 通知要否の理由で上書きしている。この列が答えるのは「なぜ対象と判定したか」であって
    // 「なぜ緊急でないか」ではない。後者は台帳の判定根拠が持っている。
    const self = String(hit[0].selfVersion || '').replace(/\n/g, ' / ').trim();
    return { label: '対象', reason: (self ? self + '｜' : '') + '影響範囲内' };
  }
  return { label: '対象外-OS影響外', reason: judgeReasonText_(owned[0], '影響対象外') };
}

/**
 * 判定に使った数値をそのまま書き写す。
 *
 * 「対象外-OS影響外」とだけ書いても、後から人が正しさを確かめられない。
 * 自社の版と、影響範囲の解釈をここに残しておけば、アドバイザリを開き直さずに
 * 突き合わせができる。台帳に載らなかった行は台帳の判定根拠を参照できないため、
 * この列が唯一の記録になる。
 */
function judgeReasonText_(row, fallback) {
  const self = String(row.selfVersion || '').replace(/\n/g, ' / ').trim();
  const phrase = String(row.reasonPhrase || '').replace(/のため$/, '').trim();
  const parts = [];
  if (self) parts.push(self);
  parts.push(phrase || fallback);
  return parts.join('｜');
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

  const labelCounts = {};
  const values = todo.map(function (f) {
    const item = f.item || f;
    const id = item.ir || item.id;
    const a = byAdvisory[id] || { products: [], initial: f.updatedAt || item.pubDate, rows: [] };
    const judgement = ownershipJudgement_(f, a.rows, assets);
    // CSAF から製品名が取れていればそれを使う（自社保有と無関係に「何の製品か」を残す）。
    // 取れない場合だけ、台帳へ展開した行から拾った製品名に落とす。
    const products = (f.products && f.products.length) ? f.products : a.products;
    return [
      f.updatedAt || item.pubDate || '',
      stateInitialDate_(f, a, item),
      vendor,
      csafCveList_(f.csaf).join(', '),
      stateTitle_(f, item),
      countLabel_(labelCounts, judgement.label),
      judgement.reason,
      products.join(', '),
      advisoryIdCell_(vendor, id, item),
      f.version || ''
    ];
  });

  if (!values.length) return labelCounts;

  if (sh.getMaxColumns() < STATE_HEADERS.length) {
    sh.insertColumnsAfter(sh.getMaxColumns(), STATE_HEADERS.length - sh.getMaxColumns());
  }

  const startRow = sh.getLastRow() + 1;
  sh.getRange(startRow, 1, values.length, STATE_HEADERS.length).setValues(values);
  sh.getRange(startRow, STATE_HEADERS.indexOf('最終更新日') + 1, values.length, 2)
    .setNumberFormat('yyyy/mm/dd');
  Logger.log('処理済みシートに ' + values.length + ' 件のアドバイザリを記録しました。');

  sortState_(sh);
  return labelCounts;
}

/**
 * 処理済みを最終更新日の降順に並べ替える。
 *
 * 追記型なので放っておくと実行順に積まれ、ベンダーも日付も混ざる。
 * 確認する人の出発点は「今月公表されたもの」なので、日付が並んでいないと
 * 毎回フィルタ操作が要る。台帳は毎回ソートしているのに、確認用のこちらが
 * 並んでいないのは筋が通らない。
 * アドバイザリID はハイパーリンクの数式なので、値ではなく数式のまま入れ替える。
 */
function sortState_(sh) {
  if (!sh || sh.getLastRow() < 3) return;

  const n = sh.getLastRow() - 1;
  const range = sh.getRange(2, 1, n, STATE_HEADERS.length);
  const cUpd = STATE_HEADERS.indexOf('最終更新日');
  const cId = STATE_HEADERS.indexOf('アドバイザリID');

  const formulas = range.getFormulas();
  const values = range.getValues();
  for (let i = 0; i < values.length; i++) {
    if (cId >= 0 && formulas[i][cId]) values[i][cId] = formulas[i][cId];
  }

  values.sort(function (a, b) {
    const da = a[cUpd], db = b[cUpd];
    if (da instanceof Date && db instanceof Date) return db - da;
    return 0;
  });

  range.setValues(values);
}

/**
 * 公式アドバイザリの URL。RSS が持っていればそれを使い、無ければ ID から組み立てる。
 *
 * 処理済みシートでは =HYPERLINK() の形でアドバイザリID 列に入れる。
 * セルの値は ID のままなので、ID で突合している既読判定は壊れない。
 * URL 体系が変わると過去行のリンクは古いままになるが、ID の文字列は残るので
 * 人が検索すればたどれる。セルに数式を置く以上これは避けられない。
 */
function advisoryUrlFor_(vendor, advisoryId, item) {
  const fromFeed = String((item && item.link) || '').trim();
  if (fromFeed) return fromFeed;

  const id = String(advisoryId || '').trim();
  if (!id) return '';
  if (vendor === VENDOR_CISCO) return ciscoHumanAdvisoryUrl_(id);
  if (/^FG-IR-/i.test(id)) return 'https://fortiguard.fortinet.com/psirt/' + id;
  return '';
}

/**
 * 処理済みの判定に使う値だけを、AI 生成の前に控えておく。
 *
 * 台帳を先に書くようにしたため、writeState_ は fillLedgerDisplay_ の後に走る。
 * fillLedgerDisplay_ は reasonPhrase を通知判定の文言（「管理GUI の利用有無が
 * 設定次第のため」など）に書き換えるので、そのまま渡すと処理済みの判定根拠に
 * 「自社が対象か」ではなく「なぜ通知するか」が入り、列の意味が変わってしまう。
 */
function snapshotJudgeRows_(rows) {
  return rows.map(function (r) {
    return {
      advisoryId: r.advisoryId, initialDate: r.initialDate, product: r.product,
      osStatus: r.osStatus, selfVersion: r.selfVersion, reasonPhrase: r.reasonPhrase
    };
  });
}

/** バッチごとの判定内訳を 1 実行分に足し込む。 */
function mergeCounts_(into, counts) {
  Object.keys(counts || {}).forEach(function (k) {
    into[k] = (into[k] || 0) + counts[k];
  });
}

/**
 * 処理済みに残すタイトル。CSAF の document.title を最優先にする。
 *
 * Cisco の csaf_20.xml は <title> がアドバイザリ ID そのもので、そのまま使うと
 * ID 列と同じ文字列が 2 列並ぶだけになる（実測 50/50 行）。
 * 人が読める題名は CSAF の中にあるので、そちらを使う。
 */
function stateTitle_(f, item) {
  const t = String((((f || {}).csaf || {}).document || {}).title || '').trim();
  return t || (item && item.title) || '';
}

/**
 * 処理済みに残す初回公表日。CSAF の initial_release_date を最優先にする。
 *
 * 展開した行から拾うと、自社資産に該当せず行が 1 つも作られなかったアドバイザリで
 * 最終更新日が代入され、初出か改訂かの区別が付かなくなる（実測 Cisco 19/50 行）。
 * 日付を 2 列並べる意味そのものが失われるため、CSAF の値を使う。
 */
function stateInitialDate_(f, a, item) {
  const t = ((((f || {}).csaf || {}).document || {}).tracking) || {};
  if (t.initial_release_date) {
    return csafDate_(t.initial_release_date, a.initial || f.updatedAt || '');
  }
  return a.initial || f.updatedAt || (item && item.pubDate) || '';
}

/**
 * アドバイザリが持つ CVE を全部並べる。実測で最大 7 件。
 * 台帳は自社該当分しか持たないので、除外した件の CVE はここにしか残らない。
 * ニュースで見た CVE 番号から自社影響の有無を引けるようにするための列。
 */
function csafCveList_(csaf) {
  const out = [];
  ((csaf || {}).vulnerabilities || []).forEach(function (v) {
    if (v && v.cve) pushUnique_(out, String(v.cve).trim());
  });
  return out;
}

/** アドバイザリID のセル。リンクを張れるときは数式にする（値は ID のまま）。 */
function advisoryIdCell_(vendor, id, item) {
  const url = advisoryUrlFor_(vendor, id, item);
  return url ? '=HYPERLINK("' + url + '","' + id + '")' : id;
}

/** 判定を数えながらそのまま返す。writeState_ の中で 1 度だけ判定するための小道具。 */
function countLabel_(counts, label) {
  counts[label] = (counts[label] || 0) + 1;
  return label;
}

/**
 * JPCERT/CC の注意喚起のうち、自社ベンダーに当たり、まだ知らせていないものを返す。
 *
 * 落ちても main() は止めない。JPCERT は補助の経路で、これが取れないことで
 * 本体の日次処理を落とすのは本末転倒。
 */
function newJpcertAlerts_(assets) {
  try {
    const alerts = fetchJpcertAlerts_();
    const words = jpcertKeywords_(assets);
    const seen = jpcertSeenIds_();

    const hit = alerts.filter(function (a) {
      if (seen[a.id]) return false;
      const t = a.title.toLowerCase();
      return words.some(function (w) { return t.indexOf(w) !== -1; });
    });

    Logger.log('JPCERT 注意喚起: ' + alerts.length + ' 件中 ' + hit.length + ' 件が自社ベンダー該当・未通知');
    return hit;
  } catch (e) {
    Logger.log('JPCERT 取得に失敗しました（本体は続行）: ' + e);
    return [];
  }
}

/**
 * RDF から注意喚起（/at/）だけ取り出す。Weekly Report は定常報告なので捨てる。
 * RSS 1.0 なので item は channel の下ではなく rdf:RDF の直下にある。
 */
function fetchJpcertAlerts_() {
  const res = UrlFetchApp.fetch(JPCERT_RSS_URL, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('JPCERT RDF 取得失敗 HTTP ' + res.getResponseCode());
  }
  const root = XmlService.parse(res.getContentText()).getRootElement();
  const rss = XmlService.getNamespace('http://purl.org/rss/1.0/');
  const dc = XmlService.getNamespace('http://purl.org/dc/elements/1.1/');

  return root.getChildren('item', rss).map(function (it) {
    const link = String(it.getChildText('link', rss) || '').trim();
    return {
      id: String(it.getChildText('identifier', dc) || '').trim(),
      title: String(it.getChildText('title', rss) || '').trim(),
      link: link,
      date: parsePubDate_(it.getChildText('date', dc))
    };
  }).filter(function (a) {
    return a.id && a.link.indexOf('/at/') !== -1;
  });
}

/**
 * 注意喚起の題名に当てる語。資産シートのベンダーと製品から起こす。
 *
 * 機種名（C9200-24PXG-E など）は題名に出ないので使わない。ツール対象外の資産は除く。
 *
 * 社名だけで当てる。製品名まで絞ってはいけない。4 年分の Fortinet / Cisco 系 6 件のうち
 * 3 件は題名に製品名が入っておらず、その中に at260019
 * 「Fortinet製品に関連する認証情報の漏えい」（FortiBleed）が含まれる。
 * 絞るとこの経路を作るきっかけになった 1 件が落ちる。
 *
 * 絞らないことで増えるのは 4 年で 2 件（FortiManager と ASA/FTD の非保有製品）。
 * 落とすのは年 1 件の当たり、拾いすぎるのは年 0.5 件のハズレ。割に合わない。
 */
function jpcertKeywords_(assets) {
  const words = [];
  (assets || []).forEach(function (a) {
    if (a.toolTarget === 'いいえ') return;
    [a.vendor, a.product].forEach(function (v) {
      const w = String(v || '').trim().toLowerCase();
      if (w && w !== '—') pushUnique_(words, w);
    });
  });
  // 題名が製品ブランドで書かれることがある（「Fortinet製FortiGate」など）。
  ['fortigate', 'fortios', 'catalyst', 'ios xe', 'ios-xe'].forEach(function (w) {
    pushUnique_(words, w);
  });
  return words;
}

function jpcertSeenIds_() {
  const raw = PropertiesService.getScriptProperties().getProperty(JPCERT_SEEN_PROP) || '';
  const map = {};
  raw.split(',').forEach(function (s) { const t = s.trim(); if (t) map[t] = true; });
  return map;
}

/**
 * 通知できた分だけ既読にする。送る前に印を付けると、Webhook が失効していた日の
 * 注意喚起が誰にも届かないまま消える。
 */
function markJpcertSeen_(alerts) {
  if (!alerts || !alerts.length) return;
  const seen = Object.keys(jpcertSeenIds_());
  alerts.forEach(function (a) { if (seen.indexOf(a.id) === -1) seen.push(a.id); });
  const keep = seen.slice(-JPCERT_SEEN_MAX);
  PropertiesService.getScriptProperties().setProperty(JPCERT_SEEN_PROP, keep.join(','));
  Logger.log('JPCERT 注意喚起 ' + alerts.length + ' 件を通知済みにしました。');
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
    function judged(label) {
      return v.reduce(function (a, x) { return a + (x.labels[label] || 0); }, 0);
    }

    // Slack の宛先は既定以外のときだけ書く。通常運用では 1 文字も増えない。
    // 検証で会社テストへ向けたまま戻し忘れても、後からこの列で追える。
    const tgt = runStats_.slackTarget;
    const targetNote = (tgt && tgt !== SLACK_TARGET_DEFAULT && SLACK_TARGETS[tgt])
      ? 'Slack宛先: ' + SLACK_TARGETS[tgt].label
      : '';

    // 内訳は「見るべきことがあった日」だけ書く。平常日（更新も失敗もエラーも無い日）は
    // 毎日同じ文字列が並ぶだけで読む価値がなく、空欄にしておけば
    // 「何か書いてある行＝見るべき行」として拾える。
    // JPCERT の注意喚起は出た日だけ書く。CVE の件数とは別枠なので数字に混ぜない。
    const jpNote = runStats_.jpcert ? 'JPCERT注意喚起 ' + runStats_.jpcert + ' 件' : '';

    const worthWriting = !!errorText || sum('processed') > 0 || sum('failed') > 0 ||
                         !!targetNote || !!jpNote;

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

      // 判定の内訳。列に出るのは「対象」と「未保有」だけなので、
      // OS影響外・情報通知・判定不能はここに出さないと件数の足し算が合わなくなる。
      const judge = Object.keys(x.labels).map(function (k) {
        return k + x.labels[k];
      }).join('・');

      return x.vendor + ' ' + x.rss + '件：' + body +
             (inner.length ? '（' + inner.join('・') + '）' : '') +
             (judge ? ' 判定[' + judge + ']' : '') +
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
      sum('rss'),
      // 差分なしは「確認したが前回から変わっていなかった」件数。
      // 差分ゼロの日は他が全部 0 になり、動いた形跡が読めなくなるため列に出す。
      sum('rss') - sum('processed'),
      sum('processed'),
      judged('対象'),
      // 「対象以外」は差し引きで出す。未保有だけを数えると、OS影響外・情報通知・
      // 判定不能がどの列にも現れず、更新あり ＝ 対象 ＋ 対象以外 が崩れる。
      //
      // 「対象外」ではなく「対象以外」と呼ぶ。この残差には判定ラベルの
      // 対象外-未保有 / 対象外-OS影響外 / 対象外-情報通知 に加えて、
      // 判定不能（CSAF が取れず判定できなかった件）も入る。
      // 判定できなかった件を「対象外」と名乗らせると、分からなかった事実が消える。
      // 内訳は備考の 判定[…] にそのまま出る。
      sum('processed') - judged('対象'),
      sum('failed'),
      Math.round((Date.now() - runStats_.startedAt) / 1000),
      aiRequestCount_ - runStats_.aiAtStart,
      [errorText ? 'エラー: ' + errorText : '',
       worthWriting ? detail : '',
       jpNote, targetNote].filter(function (t) { return t; }).join('  /  ')
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

// ============================================================
// 8. 月次サマリ（同じスプレッドシートのシート）
// ============================================================

/**
 * 月次報告の草案を「月次サマリ」シートに書き出す。
 *
 * いま人がやっているのは、処理済み（分母）・台帳（対象行）・判断記録（人の決定）・
 * 実行履歴（欠測の有無）の 4 か所を突き合わせて 1 つの報告にまとめる作業。
 * その突き合わせだけを機械にやらせる。**文章は書かない。**AI も呼ばない。
 * 数字と行を並べるところまでで、読み手に何を言うかは人が書く。
 *
 * 出力先を Google ドキュメントにしない。データはスプレッドシート、通知は Slack、
 * という 2 面に閉じる方針。ドキュメントにすると面が増え、権限も増え、
 * DocumentApp.create() は実行のたびに新しいファイルを作るので年 12 個が
 * ドライブに溜まる（消す仕組みが要る）。同じシートを毎回上書きすれば溜まらない。
 *
 * @param {string=} yyyymm 対象月（'2026-08'）。省略すると先月。
 */
function buildMonthlyReport(yyyymm) {
  const month = yyyymm || prevMonthKey_();

  const state = readSheetRows_(SHEET_STATE, STATE_HEADERS);
  const ledger = readSheetRows_(SHEET_LEDGER, LEDGER_HEADERS);
  const decisions = readSheetRows_(SHEET_DECISION, DECISION_HEADERS);
  const runlog = readSheetRows_(SHEET_RUNLOG, RUNLOG_HEADERS);

  // CSAF版は台帳に無いので処理済みから引いて台帳の行へ付ける。
  attachCsafVersion_(ledger, state);

  const w = monthlyWriter_();
  w.title('脆弱性対応 月次サマリ草案  ' + month);
  w.text('自動生成: ' + ymd_(new Date()) +
         '｜台帳・処理済み・判断記録・実行履歴から機械的に集めた数字と行です。' +
         '文章と結論は人が書いてください。');

  monthlyOverview_(w, month, state, ledger);
  monthlyActionRows_(w, month, ledger);
  monthlyDecisions_(w, month, decisions);
  monthlyNoActionRows_(w, month, ledger);
  monthlyRunHealth_(w, month, runlog);

  writeMonthlySheet_(w, month);
  return month;
}

/**
 * 出力を溜める小道具。節の組み立てから「どこへ書くか」を切り離しておく。
 * 出力先を変えたくなったとき、節の中身に触らずに済む
 * （Google ドキュメントからシートへ移したときに実際そうした）。
 */
function monthlyWriter_() {
  const lines = [];
  return {
    lines: lines,
    title: function (t) { lines.push({ kind: 'title', cells: [t] }); },
    heading: function (t) { lines.push({ kind: 'heading', cells: [t] }); },
    text: function (t) { lines.push({ kind: 'text', cells: [t] }); },
    blank: function () { lines.push({ kind: 'text', cells: [''] }); },
    table: function (headers, rows) {
      lines.push({ kind: 'thead', cells: headers });
      rows.forEach(function (r) { lines.push({ kind: 'trow', cells: r }); });
    }
  };
}

/**
 * 溜めた行を「月次サマリ」シートへ書く。毎回まるごと作り直す。
 *
 * 追記にしない。月を指定して出し直したときに前回の内容が残ると、
 * どこまでが今回の草案なのか読む人に分からない。人が書き足した文章も消えるので、
 * 清書はこのシートの上ではなく報告側で行うこと。
 */
function writeMonthlySheet_(w, month) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(SHEET_MONTHLY);
  if (!sh) sh = ss.insertSheet(SHEET_MONTHLY);
  sh.clear();

  const width = w.lines.reduce(function (a, l) { return Math.max(a, l.cells.length); }, 1);
  const values = w.lines.map(function (l) {
    const row = l.cells.slice();
    while (row.length < width) row.push('');
    return row;
  });
  sh.getRange(1, 1, values.length, width).setValues(values);

  // 書式は行の種類から当てる。太字にするのは見出しと表の 1 行目だけ。
  //
  // 説明文の行は横に結合する。結合しないと、その長い文が列 A の幅を決めてしまい、
  // 同じ列 A を使う表（自社影響・製品）が読めなくなる。
  w.lines.forEach(function (l, i) {
    const r = sh.getRange(i + 1, 1, 1, width);
    if (l.kind === 'title') { r.merge(); r.setFontSize(14).setFontWeight('bold'); }
    else if (l.kind === 'heading') { r.merge(); r.setFontWeight('bold').setBackground('#eef1f5'); }
    else if (l.kind === 'text') { r.merge(); }
    else if (l.kind === 'thead') r.setFontWeight('bold').setBackground('#f5f5f5');
  });

  const all = sh.getRange(1, 1, values.length, width);
  all.setVerticalAlignment('top');
  // 折り返す。節ごとに列の意味が違うので、どの列にも長い値が来る可能性がある。
  // 切り詰めると判定根拠が読めなくなり、報告の材料として使えない。
  all.setWrap(true);

  // 幅は節をまたいで共通。§2 と §4 は同じ列にしてあるので、あとは §3 の
  // 「根拠」（F 列）が読める幅を確保すればよい。
  //  A 最終更新日/判断日   B CSAF版/アドバイザリID   C 自社影響/CVE   D 製品/判断
  //  E CVE/判断者   F CVSS/根拠   G KEV   H 影響機能   I 判定根拠   J 公式推奨対応
  //
  // F は §3 の「根拠」（長い自由記述）に合わせて広く取る。台帳の表では CVSS が
  // そこに来るので余白が出るが、狭くして根拠が読めなくなる方が困る。
  [100, 80, 150, 120, 150, 260, 70, 130, 300, 240].slice(0, width)
    .forEach(function (px, i) { sh.setColumnWidth(i + 1, px); });

  Logger.log('月次サマリ草案（' + month + '）を「' + SHEET_MONTHLY + '」シートに書きました。');
  ss.toast('月次サマリ草案 ' + month + ' を「' + SHEET_MONTHLY + '」シートに書きました。',
           '月次サマリ', 8);
}

/** 先月を 'yyyy-mm' で返す。月初に前月分を作るのが定例なので既定はこれ。 */
function prevMonthKey_() {
  const d = new Date();
  d.setDate(1);
  d.setMonth(d.getMonth() - 1);
  return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2);
}

/** シートを見出し名で引ける形に読む。列順が変わっても添字を書き直さずに済む。 */
function readSheetRows_(name, headers) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(name);
  if (!sh || sh.getLastRow() < 2) return [];
  const n = sh.getLastRow() - 1;
  const range = sh.getRange(2, 1, n, headers.length);
  const vals = range.getValues();
  const text = range.getDisplayValues();
  return vals.map(function (r, i) {
    const o = { _text: {} };
    headers.forEach(function (h, c) { o[h] = r[c]; o._text[h] = text[i][c]; });
    return o;
  });
}

/**
 * 台帳の行に処理済みの CSAF版 を付ける。アドバイザリID で突き合わせる。
 *
 * 台帳の ID は =HYPERLINK() なので値ではなく表示文字列で引く（どちらの
 * シートも _text 側に ID の文字列が入っている）。
 * 引けなかった行は空にする。「0」と書くと未取得と取り違える（§4.1）。
 */
function attachCsafVersion_(ledger, state) {
  const byId = {};
  state.forEach(function (r) {
    const id = String(r._text['アドバイザリID'] || '').trim();
    if (id) byId[id] = String(r._text['CSAF版'] || '').trim();
  });
  ledger.forEach(function (r) {
    const id = String(r._text['アドバイザリ'] || '').trim();
    r._text['CSAF版'] = (id && byId[id] !== undefined) ? byId[id] : '';
  });
}

/** その行が対象月のものか。日付列で判定する。 */
function inMonth_(d, month) {
  if (!(d instanceof Date) || isNaN(d.getTime())) return false;
  return (d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2)) === month;
}

/**
 * 概要。分母（公表件数）は処理済みから、対象は台帳から数える。
 * 分母を台帳から数えてはいけない。台帳には自社製品の行しか無く、
 * 「他社製品だけのアドバイザリ」が落ちて水増しになる。
 */
function monthlyOverview_(w, month, state, ledger) {
  w.blank();
  w.heading('1. 今月の全体像');

  const pub = state.filter(function (r) {
    return inMonth_(r['最終更新日'], month) && r['自社判定'] !== STATE_JUDGE_INFO;
  });
  const byVendor = {};
  pub.forEach(function (r) {
    const v = String(r['ベンダー'] || '').trim() || '不明';
    byVendor[v] = (byVendor[v] || 0) + 1;
  });
  const target = pub.filter(function (r) { return String(r['自社判定']).trim() === '対象'; });

  const rows = ledger.filter(function (r) { return inMonth_(r['最終更新日'], month); });
  const cnt = { act: 0, invest: 0, none: 0 };
  rows.forEach(function (r) {
    const v = String(r['自社影響']).trim();
    if (v === V_ACT) cnt.act++;
    else if (v === V_INVEST) cnt.invest++;
    else if (v === V_NONE) cnt.none++;
  });

  w.text('公表されたアドバイザリ: ' + pub.length + ' 件（' +
    Object.keys(byVendor).sort().map(function (k) { return k + ' ' + byVendor[k]; }).join(' / ') +
    '）※情報通知を除く');
  w.text('うち自社の資産に当たると判定: ' + target.length + ' 件');
  w.text('台帳に載った行: ' + rows.length + ' 行 ／ ' +
    V_ACT + ' ' + cnt.act + ' ／ ' + V_INVEST + ' ' + cnt.invest + ' ／ ' + V_NONE + ' ' + cnt.none);

  // 影響機能が特定できていない行の割合は隠さない。「影響調査」の中身が
  // 「確認すべきことがある」なのか「分からない」なのかで報告の意味が変わる。
  const vague = rows.filter(function (r) {
    const v = String(r['自社影響']).trim();
    if (v !== V_ACT && v !== V_INVEST) return false;
    const f = String(r['影響機能'] || '').trim();
    return !f || f === 'その他' || f === '不明' || f === '—';
  });
  const denom = cnt.act + cnt.invest;
  if (denom) {
    w.text('※ 対象 ' + denom + ' 行のうち ' + vague.length + ' 行（' +
      Math.round(vague.length / denom * 100) + '%）は影響機能を特定できておらず、' +
      '「懸念があるから調査」ではなく「分からないから調査」に分類されています。' +
      '確認の手がかりが無い行なので、報告では分けて扱ってください。');
  }
}

/**
 * 台帳の行を報告に出すときの列。§2 と §4 で同じにする。
 *
 * 節ごとに列を変えると、同じ列 A に「自社影響」と「製品」が来て、
 * 列幅がどちらかに合わなくなる。どちらも台帳の行で形は同じなので、
 * 揃えておけば幅を 1 通り決めれば済む。
 *
 * 先頭 2 列は「その判定が、いつ時点のどの情報に基づくか」。
 * 最終更新日は CSAF の current_release_date、CSAF版は tracking.version で、
 * 既読判定がこの 2 つで改訂を見ているのと同じ組。報告を読む人が
 * 「この結論は古い情報のままではないか」を確かめられるようにする。
 *
 * とくに CSAF版 が「未取得」の行は、**アドバイザリ本体を読めないまま RSS の
 * 情報だけで判定した行**。結論の確からしさが他の行と違うので、報告で
 * 見えないままにしてはいけない。
 */
const MONTHLY_LEDGER_COLS = ['最終更新日', 'CSAF版', '自社影響', '製品', 'CVE', 'CVSS',
                             'KEV', '影響機能', '判定根拠', '公式推奨対応'];

/** 対応検討・影響調査の行。人が動く必要があるもの。 */
function monthlyActionRows_(w, month, ledger) {
  w.blank();
  w.heading('2. 対応の検討・調査が要る行');
  const cols = MONTHLY_LEDGER_COLS;
  const rows = ledger.filter(function (r) {
    const v = String(r['自社影響']).trim();
    return inMonth_(r['最終更新日'], month) && (v === V_ACT || v === V_INVEST);
  });
  if (!rows.length) { w.text('該当なし。'); return; }
  w.table(cols, rows.map(function (r) {
    return cols.map(function (h) { return oneLine_(r._text[h]); });
  }));
}

/** 人がどう決めたか。ツールの判定ではなくこちらが監査で読まれる。 */
function monthlyDecisions_(w, month, decisions) {
  w.blank();
  w.heading('3. 人が下した判断');
  const rows = decisions.filter(function (r) { return inMonth_(r['判断日'], month); });
  if (!rows.length) {
    w.text('この月に記録された判断はありません。' +
      '台帳で行を選び、メニュー「選択行から判断記録を作る」で残せます。');
    return;
  }
  // 「根拠」を最後（F 列）に置く。ここだけ列の意味が台帳の表とずれるので、
  // 長い自由記述が幅を取ってある列に来るように並べる。
  w.table(['判断日', 'アドバイザリID', 'CVE', '判断', '判断者', '根拠'],
    rows.map(function (r) {
      return [ymd_(r['判断日']), oneLine_(r._text['アドバイザリID']), oneLine_(r._text['CVE']),
              oneLine_(r._text['判断']), oneLine_(r._text['判断者']), oneLine_(r._text['根拠'])];
    }));
}

/**
 * 「なし」と判定した行とその根拠。
 * 設計書v3 §5 のとおり、これは報告の主要部分。対応しないと言い切る根拠そのもの。
 */
function monthlyNoActionRows_(w, month, ledger) {
  w.blank();
  w.heading('4. 対応不要と判定した行とその根拠');
  const cols = MONTHLY_LEDGER_COLS;
  const rows = ledger.filter(function (r) {
    return inMonth_(r['最終更新日'], month) && String(r['自社影響']).trim() === V_NONE;
  });
  if (!rows.length) { w.text('該当なし。'); return; }
  w.table(cols, rows.map(function (r) {
    return cols.map(function (h) { return oneLine_(r._text[h]); });
  }));
}

/**
 * その月にツールが動いていたか。
 * 報告の数字は「取れた範囲」でしかないので、欠測日があるならそう書く必要がある。
 */
function monthlyRunHealth_(w, month, runlog) {
  w.blank();
  w.heading('5. ツールの稼働状況');
  const rows = runlog.filter(function (r) { return inMonth_(r['実行日時'], month); });
  if (!rows.length) {
    w.text('実行履歴がありません。この月の数字は根拠が確認できません。');
    return;
  }
  const days = {};
  let ng = 0;
  rows.forEach(function (r) {
    days[ymd_(r['実行日時'])] = true;
    if (String(r['結果']).trim() !== '正常') ng++;
  });
  const n = Object.keys(days).length;
  w.text('実行: ' + rows.length + ' 回 ／ ' + n + ' 日 ／ 正常以外 ' + ng + ' 回');
  const parts = month.split('-');
  const inMonthDays = new Date(Number(parts[0]), Number(parts[1]), 0).getDate();
  if (n < inMonthDays) {
    w.text('※ ' + inMonthDays + ' 日中 ' + n + ' 日しか実行記録がありません。' +
      '実行されなかった日の公表は拾えていない可能性があります。');
  }
}

/** セル内の改行を潰す。表の中で折り返すと読めなくなる。 */
function oneLine_(s) {
  return String(s === undefined || s === null ? '' : s).replace(/\s*\n\s*/g, ' / ').trim();
}

/**
 * 台帳の「影響機能」の分布を出す。月次サマリを作るかどうかの判断材料。
 *
 * 設計書v3 は月次サマリを保留した理由に「影響機能名の表記ゆれが大きく、実測で
 * `不明` が約3割」を挙げている。その後に統制語彙（FORTINET_AI_FEATURES /
 * FEATURE_CONFIG_DEPENDENT）を入れたので、いまも3割なのかを測る。
 *
 * 見るのは最後の 1 行「不明・その他・空欄の合計」。ここが 3 割のままなら、
 * 月次サマリは毎月「影響機能: 不明 3割」という文書を自動生成することになり、
 * 報告に使えない。1 割を切っていれば作れる。
 *
 * 全行と「対象のみ」の 2 本立てで出す。月次報告が扱うのは対象の行なので、
 * 全体の分布より対象だけの分布の方が実態に近い。
 */
function countFeatures() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 2) { Logger.log('台帳が空です。'); return; }

  const values = sh.getRange(2, 1, sh.getLastRow() - 1, LEDGER_HEADERS.length).getValues();
  const cFeature = COL['影響機能'] - 1;
  const cVerdict = COL['自社影響'] - 1;

  report(values, '台帳の全行');
  report(values.filter(function (r) {
    const v = String(r[cVerdict]).trim();
    return v === V_ACT || v === V_INVEST;
  }), '対象の行だけ（' + V_ACT + ' / ' + V_INVEST + '）');

  function report(rows, label) {
    if (!rows.length) { Logger.log('--- ' + label + ': 0 行'); return; }
    const m = {};
    rows.forEach(function (r) {
      const f = String(r[cFeature] || '').trim() || '(空欄)';
      m[f] = (m[f] || 0) + 1;
    });
    const keys = Object.keys(m).sort(function (a, b) { return m[b] - m[a]; });

    Logger.log('--- ' + label + '（' + rows.length + ' 行）');
    keys.forEach(function (k) {
      const pct = Math.round(m[k] / rows.length * 100);
      Logger.log('  ' + padRight_(k, 22) + padLeft_(m[k], 4) + ' 件  (' + padLeft_(pct, 3) + '%)');
    });

    // 「不明」「その他」「空欄」は、機能を特定できなかった行。月次サマリで
    // 使い物になるかはこの合計で決まる。
    const vague = ['不明', 'その他', '(空欄)', '—'].reduce(function (a, k) {
      return a + (m[k] || 0);
    }, 0);
    Logger.log('  → 機能を特定できていない行（不明・その他・空欄）: ' +
               vague + ' 件 (' + Math.round(vague / rows.length * 100) + '%)');
  }
}

/**
 * 表示幅で右に詰める。日本語は 1 文字が 2 桁ぶんの幅を持つので、
 * 文字数で詰めると「管理GUI」と「IOS XE 基盤」で桁が揃わない。
 * 分布を読むときに数字が縦に並んでいないと比較できない。
 */
function padRight_(s, n) {
  let t = String(s);
  while (displayWidth_(t) < n) t += ' ';
  return t;
}

/** 全角（CJK・かな・全角記号）を 2 桁として数えた表示幅。 */
function displayWidth_(s) {
  let w = 0;
  String(s).split('').forEach(function (ch) {
    const c = ch.charCodeAt(0);
    const wide = (c >= 0x1100 && c <= 0x115F) || (c >= 0x2E80 && c <= 0xA4CF) ||
                 (c >= 0xAC00 && c <= 0xD7A3) || (c >= 0xF900 && c <= 0xFAFF) ||
                 (c >= 0xFE30 && c <= 0xFE6F) || (c >= 0xFF00 && c <= 0xFF60) ||
                 (c >= 0xFFE0 && c <= 0xFFE6);
    w += wide ? 2 : 1;
  });
  return w;
}

function padLeft_(s, n) {
  let t = String(s);
  while (t.length < n) t = ' ' + t;
  return t;
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
    r.pubDate || '',                  // 1  最終更新日
    r.verdict || '',                  // 2  自社影響
    r.product || '不明',              // 3  製品
    r.cve || '',                      // 4  CVE
    cvss,                             // 5  CVSS
    r.kev || '',                      // 6  KEV
    shortTitle_(r.title),             // 7  脆弱性名
    r.impactJa || '',                 // 8  ユーザ影響
    r.feature || '',                  // 9  影響機能
    r.reason || '',                   // 10 判定根拠
    stripCheckLabels_(r.howToCheck),  // 11 確認方法
    action,                           // 12 公式推奨対応
    advisoryCell,                     // 13 アドバイザリ
    r.vector || ''                    // 14 CVSSベクター
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

  // 幅は列名で引く。位置で並べると、列順を変えたときに黙ってずれる。
  const widths = {
    '最終更新日': 100, '自社影響': 90, '製品': 100, 'CVE': 140, 'CVSS': 70, 'KEV': 55,
    '脆弱性名': 220, 'ユーザ影響': 220, '影響機能': 120, '判定根拠': 280,
    '確認方法': 320, '公式推奨対応': 220, 'アドバイザリ': 150
  };
  LEDGER_HEADERS.forEach(function (h, i) { sh.setColumnWidth(i + 1, widths[h] || 120); });

  // 「いつ・対応要否・どの機器・どれくらい危ないか」までを固定して、右へ読み進める。
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
 *
 * targetKey を渡すとその宛先へ送る（メニューからのテスト送信）。
 * 省略すると運用宛先（SLACK_TARGET）になるので、main / reprocess の 3 箇所は
 * 宛先を知らないまま呼べる。宛先が増えても呼び出し側は変わらない。
 *
 * alerts は JPCERT の注意喚起。**判定を通っていない情報**なので、CVE のカードとは
 * 混ぜず末尾に別枠で出す。該当 0 件でも注意喚起があれば送る（そうしないと
 * 「CVE の該当が無い日」に注意喚起が消える）。
 *
 * @return {boolean} 実際に送ったか。呼び出し側が既読を進めてよいかの判断に使う。
 */
function notifySlack_(rows, targetKey, alerts) {
  const key = targetKey || operationalSlackTarget_();
  const url = slackWebhookUrl_(key);
  if (!url) return false;

  const hits = rows
    .filter(function (r) { return r.verdict === V_ACT || r.verdict === V_INVEST; })
    .sort(slackHitSort_);
  const notes = alerts || [];

  if (!hits.length && !notes.length && !NOTIFY_WHEN_NO_HITS) {
    Logger.log('OS 更新の可能性がある新着なし。Slack 通知はスキップします。');
    return false;
  }

  const sheetUrl = SpreadsheetApp.getActiveSpreadsheet().getUrl();
  const shown = hits.slice(0, SLACK_MAX_ITEMS);
  const payload = buildSlackPayload_(shown, sheetUrl, hits, notes);

  // 実際に送った宛先だけ実行履歴に残す。ここより上で戻る日は何も送っていないので
  // 記録しない。切り替えたまま戻し忘れた日は、送った実行に必ず印が残る。
  if (runStats_) runStats_.slackTarget = key;

  const code = postSlack_(url, payload);
  Logger.log('Slack 通知を送信しました（' + SLACK_TARGETS[key].label + '）: ' +
             '全 ' + hits.length + ' 件のうち ' + shown.length + ' 件を表示' +
             (notes.length ? ' / JPCERT 注意喚起 ' + notes.length + ' 件' : ''));
  return code === 200;
}

/**
 * 宛先キーから Webhook URL を引く。取れないときは null を返して理由をログに残す。
 * 表示名とプロパティ名の両方を出す。「どの宛先が」「どの設定を」欠いているかが
 * 一度で分からないと、宛先が増えたときにログだけでは切り分けられない。
 */
function slackWebhookUrl_(targetKey) {
  const t = SLACK_TARGETS[targetKey];
  if (!t) {
    Logger.log('Slack 宛先「' + targetKey + '」は定義されていません。送信しません。');
    return null;
  }
  const url = PropertiesService.getScriptProperties().getProperty(t.prop);
  if (!url) {
    Logger.log('Slack ' + t.label + '（' + t.prop + '）が未設定のため通知をスキップします。');
    return null;
  }
  return url;
}

/**
 * 運用（main / reprocess）の宛先。スクリプトプロパティ SLACK_TARGET で切り替える。
 *
 * 未知の値でも送信は止めず、既定へ落として警告だけ出す。
 * ここで止めると、設定の打ち間違いが「Slack が静かな日」と区別できなくなる。
 * 既定へ送ってしまう害より、通知が消えて誰も気づかない害の方が大きい。
 */
function operationalSlackTarget_() {
  const v = String(PropertiesService.getScriptProperties().getProperty('SLACK_TARGET') || '').trim();
  if (!v) return SLACK_TARGET_DEFAULT;
  if (!SLACK_TARGETS[v]) {
    Logger.log('SLACK_TARGET の値「' + v + '」は未知です。' +
               SLACK_TARGETS[SLACK_TARGET_DEFAULT].label + ' に送ります。');
    return SLACK_TARGET_DEFAULT;
  }
  return v;
}

/**
 * Slack へ送る。応答コードを見てログに残す。
 *
 * 以前は muteHttpExceptions のまま結果を捨てていた。宛先が 1 つのうちは
 * 「届かない ＝ すぐ気づく」だったが、宛先が複数になると片方の Webhook だけ
 * 失効しても残りが届き、欠測に気づけなくなる。
 */
function postSlack_(url, payload) {
  const res = UrlFetchApp.fetch(url, {
    method: 'post',
    contentType: 'application/json',
    muteHttpExceptions: true,
    payload: JSON.stringify(payload)
  });
  const code = res.getResponseCode();
  if (code !== 200) {
    Logger.log('Slack 送信に失敗しました: HTTP ' + code + ' ' + res.getContentText());
  }
  return code;
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
function buildSlackPayload_(shown, sheetUrl, all, alerts) {
  // サマリは表示分ではなく全件で数える。ここを shown で数えると、
  // 2 行目の内訳とカードの枚数が一致してしまい、切られた事実がどこにも出ない。
  // 読む人は 2 行目を「今日の該当件数」として読むので、そこが表示件数だと
  // 末尾の残り件数が何に対する残りなのか繋がらなくなる。
  const total = all || shown;
  const rest = total.length - shown.length;
  const summary = slackDeviceSummary_(total);
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

  shown.forEach(function (r) {
    blocks.push({ type: 'divider' });
    formatSlackItemBlocks_(r).forEach(function (b) { blocks.push(b); });
  });

  // JPCERT の注意喚起は CVE のカードと混ぜない。判定を通っていないので、
  // 同じ見た目で並べると「ツールが自社影響ありと判断した」と読まれる。
  // 見出しを付けて別枠にし、リンクだけ渡して判断は人に委ねる。
  (alerts || []).forEach(function (a, i) {
    if (i === 0) {
      blocks.push({ type: 'divider' });
      blocks.push({ type: 'section', text: { type: 'mrkdwn',
        text: ':loudspeaker: *JPCERT/CC 注意喚起*（自社ベンダー該当・判定はしていません）' } });
    }
    blocks.push({ type: 'section', text: { type: 'mrkdwn',
      text: '<' + a.link + '|' + jpcertShortTitle_(a.title) + '>' } });
  });

  const foot = [];
  // 「は台帳」とは書かない。直下のリンクが台帳を指しているので重複する。
  // ここが担うのは「全部は出していない」という事実と、その分母だけ。
  if (rest > 0) foot.push('全 ' + total.length + ' 件のうち ' + shown.length + ' 件を表示');
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

/** 注意喚起の題名。先頭の「注意喚起: 」と末尾の「(公開)」「(更新)」を落として読みやすくする。 */
function jpcertShortTitle_(s) {
  const t = String(s || '').replace(/^注意喚起:\s*/, '').replace(/\s*\((公開|更新)\)\s*$/, '').trim();
  return t.length > 70 ? t.slice(0, 70) + '…' : t;
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
  // formatOfficialAction_ は空を返さないので、ここで補わない。
  // 補うと台帳（補わない側）と Slack で文言が食い違う。
  const first = String(formatOfficialAction_(r) || '').split(/\n/)[0].trim();
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
 * 表示確認に使うサンプル 3 行。台帳の実データではない。
 * 実送信（sendSlackTest_・この下）と、ログ出力（testSlackBlocks・確認用ファイル側）で
 * 同じ内容を使う。
 */
function sampleSlackRows_() {
  return [
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
}


/**
 * サンプル 3 行を実際に Slack へ送る。宛先はスプレッドシートのメニューから選ぶ。
 *
 * 先頭に「テスト送信」の 1 行を足す。中身は架空の CVE（CVE-2026-0001 など）で、
 * 会社のチャンネルに出したとき本物の公表として読まれると実害が出る。
 * 印は buildSlackPayload_ ではなくここで足す。本番の見た目のコードは 1 行も変えない。
 *
 * 実データで見せたいときはこの経路を使わない。SLACK_TARGET を切り替えて
 * reprocessCisco() を実行すれば、本番と同じ経路で 1 通出る。
 */
function sendSlackTest_(targetKey) {
  const t = SLACK_TARGETS[targetKey];
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  const url = slackWebhookUrl_(targetKey);
  if (!url) {
    // メニューから実行するとログを見に行かないので、シート側にも出す。
    ss.toast(t.label + '（' + t.prop + '）が未設定です。', 'Slack テスト送信', 8);
    return;
  }

  const payload = buildSlackPayload_(sampleSlackRows_(), ss.getUrl());
  payload.blocks.unshift({
    type: 'context',
    elements: [{
      type: 'mrkdwn',
      text: ':test_tube: *表示確認のテスト送信です。* 以下は架空のサンプルで、実際の脆弱性ではありません。'
    }]
  });

  const code = postSlack_(url, payload);
  ss.toast(code === 200 ? t.label + ' へ送信しました。'
                        : '送信に失敗しました（HTTP ' + code + '）。実行ログを確認してください。',
           'Slack テスト送信', 8);
}

function sendSlackTestToPersonal() { sendSlackTest_('personal'); }

function sendSlackTestToTeam() { sendSlackTest_('team'); }
