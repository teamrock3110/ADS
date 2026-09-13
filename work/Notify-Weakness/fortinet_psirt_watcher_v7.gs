/**
 * NW機器 脆弱性ウォッチャー for Google Apps Script（v7 / マルチベンダー）
 * ==================================================================
 * Fortinet / Cisco の脆弱性を日次で取得し、自社資産に当たる CVE だけを台帳へ書いて
 * Slack へ 1 通で通知する。自社影響の判定はコード、LLM は日本語生成のみ（設計原則 §1.5）。
 *
 * 設計の根拠・シート構成・追わないと決めたものは `README.md`。
 * 運用・貼り替え・テストの手順は readme.gs。判定ルールは `社内ルール案_OS更新基準.md`。
 *
 * スクリプト プロパティ:
 *   GEMINI_API_KEY / ANTHROPIC_API_KEY / SLACK_WEBHOOK_URL /
 *   JPCERT_SEEN_AT（ツールが書く）
 *
 * 名前の規則（macos_release_monitor.gs と同じ）:
 *   NW 専用の関数は nw〜、定数は NW_〜、シートは「NW〜」。macOS 側は macos〜 / MACOS_〜 / 「macOS〜」。
 *   接頭辞の無いものは両モジュールで共有する部品で、次の 5 つだけ。
 *     postSlack_             Slack 送信
 *     kevCatalogWithStatus_  CISA KEV の取得（取得可否と出典まで返す）
 *     callGemini_            Gemini 呼び出し（内部で callGeminiModel_ / callClaude_ を使う）
 *     countAiRequest_        AI 消費の計数。sharedAiCountToday_ で当日合計を読む（無料枠を食い合わないため）
 *     SLACK_WEBHOOK_PROP     Webhook を入れるプロパティ名
 *   これらの引数や戻り値を変えるときは macOS 側の呼び出しも直すこと。
 *
 * シートの列は key / label の配列で持ち、見出し文字列をコードのキーにしない
 * （macOS 設計確定書 §2.4。見出しを変えた瞬間に全参照が undefined になる型を避ける）。
 *
 * CSAF とは:
 *   ベンダーが脆弱性情報を機械可読な JSON で公開しているファイル。Fortinet / Cisco とも
 *   これが主経路で、影響バージョン・修正版・CVSS・影響の種類が構造化されて入っている。
 *
 */

// ============================================================
// 設定
// ============================================================

/*
 * ここから下、確認用ファイル（fortinet_psirt_watcher_v7_tests.gs）から参照する定数は
 * const ではなく **var** で宣言する。
 *
 * Apps Script は全ファイルをグローバルスコープで実行するが、別ファイルのトップレベル
 * const は参照できないことがある（2026-09-06 実測: test.gs の nwTestAi から NW_V_INVEST が
 * ReferenceError）。var と関数はファイルをまたいで確実に共有される。
 *
 * 対象: AI_PROVIDER / NW_V_ACT / NW_V_INVEST / NW_V_NONE / NW_VENDOR_FORTINET / NW_VENDOR_CISCO /
 *       NW_KEV_YES / NW_KEV_NO / SLACK_WEBHOOK_PROP / NW_SSL_VPN_ENABLED /
 *       NW_CHECK_STEPS_FORTINET / NW_CHECK_STEPS_NO_CSAF / NW_CHECK_STEPS_CISCO_DEFAULT
 *
 * 確認用ファイルから新しい定数を参照したくなったら、その宣言も var に変えること。
 * 値を書き換えないという約束は var でも変わらない（機械が守らないだけ）。
 */

/** 'gemini' か 'claude' */
var AI_PROVIDER = 'gemini';

/**
 * Gemini API のモデル ID。1日上限はモデル別に別枠。
 *
 * 2026-09-06 に ai.google.dev/gemini-api/docs/models で実在を確認した安定版。
 * **モデル ID を変えるときは必ず同ページで確かめること。**推測で置かない。
 */
var GEMINI_MODEL = 'gemini-3.8-flash';
/**
 * 上のモデルが使えないときに順に試す。退避する条件は 2 つ（callGemini_ 参照）。
 *   - 無料枠（1日20回程度・実測）を使い切った
 *   - モデル ID が無効／提供終了になった
 *
 * **1日上限はモデルごとに別勘定なので、段を増やすとその分だけ粘れる。**
 * いずれも 2026-09-06 時点の安定版。世代を上げたときは 1 つ前を先頭に残す。
 */
var GEMINI_MODEL_FALLBACKS = [
  'gemini-3.7-flash', 'gemini-3.6-flash', 'gemini-3.5-flash', 'gemini-2.5-flash'
];
/**
 * Claude のモデル ID。判定はコードが行い、AI は日本語生成だけなので Haiku で足りる。
 * 呼び出しには ANTHROPIC_API_KEY（スクリプト プロパティ）が要る。
 */
var CLAUDE_MODEL = 'claude-haiku-4-5-20251001';

/**
 * AI に投げた HTTP リクエストの回数。実行履歴に残して無料枠の消費を追えるようにする。
 *
 * 数えるのはプロンプトの数ではなく、実際に投げたリクエストの数。
 * リトライもモデルのフォールバックも 1 回ずつ数える。枠を減らすのはリクエストだから。
 * 呼び出しは AI 生成の内側 3 階層で起きるため、引数で持ち回らずここで数える。
 */
var aiRequestCount_ = 0;

function countAiRequest_() {
  aiRequestCount_++;
  bumpSharedAiCount_();
}

/**
 * 当日の AI 消費数をスクリプトプロパティへ積む。**NW と macOS で共有する。**
 *
 * aiRequestCount_ はモジュールスコープの let なので、実行が分かれると数が分かれる。
 * macOS は別トリガー＝別実行なので、これが無いと macOS の消費が
 * 実行履歴の「AI呼び出し」に一切載らず、無料枠が減った理由が追えなくなる。
 * 枠は 1 日 20 回程度・モデル別（GEMINI_MODEL のコメント参照）。
 */
var SHARED_AI_COUNT_PROP = 'AI_COUNT_';

function bumpSharedAiCount_() {
  try {
    const props = PropertiesService.getScriptProperties();
    const key = SHARED_AI_COUNT_PROP + Utilities.formatDate(new Date(), 'Asia/Tokyo', 'yyyyMMdd');
    props.setProperty(key, String((Number(props.getProperty(key)) || 0) + 1));
  } catch (e) {
    // 数えられなくても本処理は止めない。枠の可視化はあくまで補助。
    Logger.log('AI 消費数の記録に失敗: ' + e);
  }
}

/** 当日これまでに投げた AI リクエスト数（NW ＋ macOS の合計）。 */
function sharedAiCountToday_() {
  try {
    const props = PropertiesService.getScriptProperties();
    const key = SHARED_AI_COUNT_PROP + Utilities.formatDate(new Date(), 'Asia/Tokyo', 'yyyyMMdd');
    return Number(props.getProperty(key)) || 0;
  } catch (e) { return 0; }
}

var NW_RSS_URL = 'https://filestore.fortinet.com/fortiguard/rss/ir.xml';
/** Cisco CSAF RSS（主経路）。link/guid に CSAF JSON の URL が直接入る */
var NW_CISCO_CSAF_RSS_URL = 'https://sec.cloudapps.cisco.com/security/center/csaf_20.xml';
/** Cisco 通常 RSS（補助）。CSAF 失敗時のタイトル・概要・人向け URL */
var NW_CISCO_RSS_URL = 'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml';
var NW_CSAF_BASE = 'https://filestore.fortinet.com/fortiguard/psirt/csaf_';

var NW_VENDOR_FORTINET = 'Fortinet';
var NW_VENDOR_CISCO = 'Cisco';

var NW_SHEET_LEDGER = 'NW台帳';
var NW_SHEET_ASSET = 'NW資産';

/**
 * 処理したアドバイザリを 1 行ずつ記録するシート。
 *
 * 台帳には自社製品の行しか書かない。そのままだと、他社製品だけのアドバイザリは
 * 台帳に痕跡が残らず、次回また新着として取り直してしまう（1.8 で直したのと同じ失敗）。
 * さらに「今月 Fortinet から公表：N 件」という分母も出せなくなる。
 * 取得した事実はここに残し、台帳は判断に使う行だけに保つ。
 */
var NW_SHEET_STATE = 'NW処理済み';

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
var NW_KEEP_OUT_OF_SCOPE_MONTHS = 3;

/**
 * Slack に 1 通で個別表示する最大件数。超えた分は末尾に件数だけ出す。
 *
 * 通知に出るのは「あり（対応検討）」「あり（影響調査）」だけなので、ここで隠れる行は
 * すべて人が見る必要のある行になる。数えているのは台帳の行数（CVE × 製品）で、
 * Cisco の複数 CVE アドバイザリが 1 本あるだけで超える（ClamAV は 1 本で 7 行）。
 *
 * 15 の根拠は Slack 側の制約。1 メッセージ 50 ブロック、カード 1 枚が divider +
 * section の 2 ブロック、ヘッダ・サマリ・末尾で 4 ブロック。15 枚なら 34 ブロック。
 * 計算上は 23 枚まで入るが、読む側の限界がブロック上限より手前にある。
 */
var NW_SLACK_MAX_ITEMS = 15;

/**
 * Slack の Webhook URL を入れるスクリプトプロパティ名。
 *
 * **改名しないこと。**改名した .gs を貼った瞬間、プロパティを直すまで日次通知が
 * 黙って止まり、それは「該当が無くて静かな日」と見分けが付かない。
 */
var SLACK_WEBHOOK_PROP = 'SLACK_WEBHOOK_URL';

/** Slack 末尾の外部一覧。URL は表示せずリンクテキストだけ出す */
var NW_SECURITY_NEXT_VULN_URL = 'https://www.security-next.com/category/cat177';

/** 影響ありが 0 件のときも Slack に流すか。日次実行では false が静か */
var NW_NOTIFY_WHEN_NO_HITS = false;

/** 1回の AI 呼び出しで処理する行数。無料枠は回数課金なので、通知対象はできるだけ1回にまとめる */
var NW_AI_CHUNK_SIZE = 10;

/**
 * 自社影響の3値。社内ルール（社内ルール案_OS更新基準.md）の写し。
 *
 * ベースラインは年1回の定期OS更新。ツールの役割は次の切り分けだけ。
 *   NW_V_ACT    臨時更新の条件を満たす。対応時期を検討する
 *   NW_V_INVEST 設定次第で影響が変わる。確認方法を実行して判断する
 *   NW_V_NONE   定期更新で足りる。臨時更新しない根拠がある
 *
 * 「影響が partial だから待てる」のような結論をツールが勝手に出さないこと。
 * 設定を見ていない以上、確認前の正しい状態は NW_V_INVEST である。
 */
var NW_V_ACT = 'あり（対応検討）';
var NW_V_INVEST = 'あり（影響調査）';
var NW_V_NONE = 'なし';

/** SSL-VPN を外面から除外する（無効化済みの場合は false） */
var NW_SSL_VPN_ENABLED = false;

/**
 * JPCERT/CC の RDF。注意喚起（/at/）だけ拾い、Weekly Report（/wr/）は捨てる。
 *
 * **判定には混ぜない。**注意喚起は CVE 単位ではなく「いま日本で問題になっている事象」で、
 * CVE を持たない回がある。台帳の行と機械的に突き合わせられず、緊急度の指標にならない。
 * それでも拾うのは、ツールの守備範囲（FortiOS / IOS-XE の CVE）の外に自社へ効く情報が
 * あるため。判定を通さず人に見せるだけの経路で補う（詳細は設計書 §4.8）。
 *
 * 頻度は年約 29 件（2023〜2026 の 4 年分 106 件を全数確認）。そのうち
 * Fortinet / Cisco 系は 6 件＝年 1.5 件なので、Slack に足しても埋もれない。
 */
var NW_JPCERT_RSS_URL = 'https://www.jpcert.or.jp/rss/jpcert.rdf';

/** 通知済みの注意喚起 ID。スクリプトプロパティにカンマ区切りで置く。 */
var NW_JPCERT_SEEN_PROP = 'JPCERT_SEEN_AT';

/** 既読 ID の保持上限。年 30〜40 件なので 200 あれば 5 年分。 */
var NW_JPCERT_SEEN_MAX = 200;

var KEV_FEED_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
/**
 * CISA 本家が落ちたときの代替。2026-09-08 実測で catalogVersion・件数とも本家と一致
 * （2026.09.04 / 1,695 件）。本家が 200 を返さなかったときだけ使う。
 *
 * 代替を足した理由は、取得失敗が「KEV 掲載なし」と同じ見た目になっていたから。
 * nwIsKevListed_ は例外を握りつぶして false を返すので、CISA が落ちた日は
 * 全 CVE が「なし」になり、KEV で「調査」へ引き上げるはずの行が静かに消えていた。
 */
var KEV_FEED_FALLBACK_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/nwDaily/known_exploited_vulnerabilities.json';

/** 直近の KEV 取得結果。実行履歴の備考へ「照合できたか」を出すために持つ。 */
var kevLastStatus_ = null;

/** Fortinet AI が選ぶ影響機能（外面判定の統制語彙） */
var NW_FORTINET_AI_FEATURES = [
  'IPsec VPN', 'SSL-VPN', '管理GUI', 'SSH',
  'アンチウイルスエンジン', 'IPSエンジン', 'Webフィルタ', 'SSLインスペクション',
  'データプレーン', 'その他', '不明'
];

/** CISA KEV 掲載の有無（台帳表示用） */
var NW_KEV_YES = 'あり';
var NW_KEV_NO = 'なし';

/**
 * 台帳の列。**14 列**で、順序は下の配列そのもの（README §2.1）。
 * key はコード側の名前、label はシートの見出し。両者は独立している（macOS 設計確定書 §2.4）。
 * 行を書くのは nwToRowArray_ で、この配列の順に key を引くので、列順を変えるときはここだけ直す。
 *
 * 列は確認する人の思考順に並べる。
 *   いつ検知した何か → どれくらい危ないか → どんな影響か → なぜその判定か
 *   → 何を確認しどう直すか → 公式で裏を取る
 * 毎日動いて新着が積まれる表なので、最終更新日は付随情報ではなく
 * 「その行が自分にとって新しいか」を判断する一次情報として先頭に置く。
 */
var NW_LEDGER_COLS = [
  { key: 'pubDate',    label: '最終更新日' },   // 1  いつ検知したか
  { key: 'verdict',    label: '自社影響' },     // 2  あり（対応検討）/ あり（影響調査）/ なし。並べ替えの第1キー
  { key: 'product',    label: '製品' },         // 3
  { key: 'cve',        label: 'CVE' },          // 4
  { key: 'cvss',       label: 'CVSS' },         // 5
  { key: 'kev',        label: 'KEV' },          // 6  あり / なし。悪用実績は CVSS より強い信号なので隣に置く
  { key: 'title',      label: '脆弱性名' },     // 7  CSAF / RSS の文書タイトル（短い表示）
  { key: 'impactJa',   label: 'ユーザ影響' },   // 8  最悪ケース50字以内
  { key: 'feature',    label: '影響機能' },     // 9
  { key: 'reason',     label: '判定根拠' },     // 10 OS=… | KEV=… | ◯◯のため「結論」
  { key: 'howToCheck', label: '確認方法' },     // 11 確認ポイント／コマンド／判断
  { key: 'action',     label: '公式推奨対応' }, // 12 ベンダー公式（日本語）
  { key: 'advisory',   label: 'アドバイザリ' }, // 13
  // 14 判定の検算用。条件3（AV/PR/UI）も条件4（C/I/A）もこの値から決まるのに、
  //    台帳に無いと読む人が判定根拠の正しさを確かめられない（§4.4 と同じ理由）。
  //    毎回スキャンする値ではないので末尾に置き、左6列固定の設計を崩さない。
  { key: 'vector',     label: 'CVSSベクター' }
];
var NW_LEDGER_HEADERS = nwHeaders_(NW_LEDGER_COLS);

/** 列定義（key / label の配列）から見出し行を作る。 */
function nwHeaders_(cols) {
  return cols.map(function (c) { return c.label; });
}

/** key から 1 始まりの列番号を引く。無い key はバグなので投げる（空欄に化けさせない）。 */
function nwCol_(cols, key) {
  for (let i = 0; i < cols.length; i++) if (cols[i].key === key) return i + 1;
  throw new Error('列定義に無い key: ' + key);
}

/** 1 行の配列を key で引けるオブジェクトにする。 */
function nwRowToRec_(cols, row) {
  const rec = {};
  cols.forEach(function (c, i) {
    const v = row[i];
    rec[c.key] = (v === undefined || v === null) ? '' : v;
  });
  return rec;
}

/** key で引けるオブジェクトを、列定義の順の配列にする。 */
function nwRecToRow_(cols, rec) {
  return cols.map(function (c) {
    const v = rec[c.key];
    return (v === undefined || v === null) ? '' : v;
  });
}

/**
 * 機能別の確認手順（行動可能）。AI 出力が不合格のときこれで差し替える。
 * 書式: 確認ポイント / コマンド / 判断 の3行。
 */
var NW_CHECK_STEPS_FORTINET = {
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
 * （nwCiscoConfigHints_ で渡し、nwBuildEnrichPrompt_ で優先を指示）。
 *
 * ここを使うのは、AI が失敗したか、行動できない文言を返したときだけ。
 */
var NW_CHECK_STEPS_CISCO = [
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

var NW_CHECK_STEPS_CISCO_DEFAULT = [
  '確認ポイント：版は対象済み（追加の版確認は不要）',
  'アクション：アドバイザリで更新先を確認し、定期更新枠に載せる',
  '判断：臨時対応は不要。次回メンテで更新すれば足りる'
].join('\n');

/** あり（影響調査）向け。定期更新定型は使わない */
var NW_CHECK_STEPS_CISCO_INVEST = [
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
var NW_ASSET_COLS = [
  { key: 'vendor',     label: 'ベンダー' },
  { key: 'category',   label: '種別' },
  { key: 'product',    label: '製品' },
  { key: 'model',      label: '機種' },
  { key: 'version',    label: 'バージョン' },
  { key: 'count',      label: '台数' },
  { key: 'toolTarget', label: 'ツール対象' },
  { key: 'note',       label: '備考' },
  { key: 'updatedAt',  label: '更新日' }
];
var NW_ASSET_HEADERS = nwHeaders_(NW_ASSET_COLS);

var NW_DEFAULT_ASSET_ROWS = [
  [NW_VENDOR_FORTINET, 'UTM', 'FortiOS', 'FortiGate 120G', '7.4.11', 1, 'はい', '', ''],
  [NW_VENDOR_CISCO, 'Switch', 'IOS-XE', 'C9200-24PXG-E', '17.15.5', 1, 'はい', '', ''],
  [NW_VENDOR_CISCO, 'Switch', 'IOS-XE', 'C9200L-24PXG-4X', '17.15.5', 1, 'はい', '', ''],
  [NW_VENDOR_CISCO, 'WLC', 'IOS-XE', 'Catalyst 9800-L', '17.15.5', 1, 'はい', '版は実機確認推奨', ''],
  [NW_VENDOR_CISCO, 'AP', '—', 'CW9166I-Q', '', 1, 'はい', 'WLC管理下', ''],
  [NW_VENDOR_FORTINET, '—', '—', 'FortiClient EMS', '', 1, 'いいえ', 'クライアント・対象外', ''],
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
var NW_STATE_COLS = [
  { key: 'updatedAt',   label: '最終更新日' },
  { key: 'initialDate', label: '初回公表日' },
  { key: 'vendor',      label: 'ベンダー' },
  { key: 'cve',         label: 'CVE' },
  { key: 'title',       label: 'タイトル' },
  { key: 'judgement',   label: '自社判定' },
  { key: 'reason',      label: '判定根拠' },
  { key: 'products',    label: '対象製品' },
  { key: 'advisoryId',  label: 'アドバイザリID' },
  { key: 'csafVersion', label: 'CSAF版' }
];
var NW_STATE_HEADERS = nwHeaders_(NW_STATE_COLS);


/**
 * 実行履歴。1 回の実行につき、ベンダーごとに 1 行。
 *
 * Slack は「判断が要る行があった日」だけ鳴る（NW_NOTIFY_WHEN_NO_HITS = false）。
 * つまり「該当なしだった日」「取得に失敗した日」「トリガーが消えて実行されなかった日」が
 * すべて "Slack が静か" という同じ見え方になる。実行ログは保持期間が短く後から遡れない。
 * 動いた事実だけはここに残し、行が途切れていれば止まったと分かるようにする。
 */
var NW_SHEET_RUNLOG = 'NW実行履歴';
/*
 * 列は「確認 → 新規・改訂 → 判定 → 失敗」の順に、上流から下流へ一直線に読めるようにする。
 * 取得件数（実際に CSAF を何本ダウンロードしたか）はここに置かない。
 * Fortinet は毎回全件、Cisco は差分のみという内部事情の数字で、合計すると
 * 「確認 100 なのに取得 50、残り 50 はどこへ？」という誤読を生むため、内訳へ回す。
 *
 * **「対象」「対象以外」はアドバイザリ件数で、台帳の行数ではない。**台帳は 1 アドバイザリが
 * CVE × 製品で複数行に開くうえ、古い「なし」を nwIsLedgerRow_ が落とすので、どう数えても
 * この列とは一致しない。答えるのは「自社の資産に当たる公表がいくつあったか」であり、
 * 台帳に何行増えたかではない。
 */
var NW_RUNLOG_COLS = [
  { key: 'ranAt',      label: '実行日時' },
  { key: 'result',     label: '結果' },
  { key: 'checked',    label: '確認件数' },
  { key: 'unchanged',  label: '差分なし' },
  { key: 'updated',    label: '更新あり' },
  { key: 'target',     label: '対象' },
  { key: 'nonTarget',  label: '対象以外' },
  { key: 'failed',     label: '失敗' },
  { key: 'seconds',    label: '所要秒' },
  { key: 'aiCalls',    label: 'AI呼び出し' },
  { key: 'note',       label: '備考' }
];
var NW_RUNLOG_HEADERS = nwHeaders_(NW_RUNLOG_COLS);


/**
 * 1 回の実行（nwDaily）で集めた統計。
 *
 * 履歴は「1 日 1 実行 = 1 行」で読めるのが理想なので、ベンダーごとの処理は
 * ここへ足すだけにして、書き出しは nwDaily() が最後に 1 回だけ行う。
 * ベンダー別の数字は「内訳」列に残すので、異常時の切り分けはできる。
 */
var nwRunStats_ = null;

function nwStartRunStats_() {
  nwRunStats_ = { startedAt: Date.now(), aiAtStart: aiRequestCount_, vendors: [] };
}

/** nwDaily() の外から呼ばれた場合（nwReprocessCisco など）は何もしない。 */
function nwAddVendorStats_(vendor, s) {
  if (!nwRunStats_) return;
  nwRunStats_.vendors.push({
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
var NW_STATE_VERSION_UNAVAILABLE = '未取得';

// ============================================================
// エントリポイント
// ============================================================

function nwSetup() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  nwRenameLegacySheets_(ss);

  let ledger = ss.getSheetByName(NW_SHEET_LEDGER);
  if (!ledger) {
    ledger = ss.insertSheet(NW_SHEET_LEDGER);
    ledger.appendRow(NW_LEDGER_HEADERS);
    ledger.setFrozenRows(1);
    nwFormatLedger_(ledger);
    Logger.log('「' + NW_SHEET_LEDGER + '」シートを作成しました。');
  } else {
    Logger.log('「' + NW_SHEET_LEDGER + '」シートは既にあります。列を変えたときはシートを手で直してください（README §2.1）。');
  }

  let asset = ss.getSheetByName(NW_SHEET_ASSET);
  if (!asset) {
    asset = ss.insertSheet(NW_SHEET_ASSET);
    asset.appendRow(NW_ASSET_HEADERS);
    NW_DEFAULT_ASSET_ROWS.forEach(function (r) { asset.appendRow(r); });
    asset.setFrozenRows(1);
    Logger.log('「' + NW_SHEET_ASSET + '」シートを作成しました。');
  } else {
    Logger.log('「' + NW_SHEET_ASSET + '」シートは既にあります。列を変えたときはシートを手で直してください（README §2.4）。');
  }

  let state = ss.getSheetByName(NW_SHEET_STATE);
  if (!state) {
    state = ss.insertSheet(NW_SHEET_STATE);
    state.appendRow(NW_STATE_HEADERS);
    state.setFrozenRows(1);
    state.setColumnWidth(1, 80);
    state.setColumnWidth(2, 100);
    state.setColumnWidth(3, 100);
    state.setColumnWidth(4, 180);
    state.setColumnWidth(5, 400);
    state.setColumnWidth(6, 280);
    state.setColumnWidth(7, 70);
    Logger.log('「' + NW_SHEET_STATE + '」シートを作成しました。分母（今月の公表件数）はここから数えます。');
  } else {
    Logger.log('「' + NW_SHEET_STATE + '」シートは既にあります。');
  }
}

/**
 * 旧名のシート（台帳 / 資産 / 処理済み / 実行履歴）を「NW〜」へ改名する。
 *
 * 2026-09 に macOS 監視（macOS台帳 など）と並べたとき区別が付くよう、NW 側にも接頭辞を付けた。
 * 改名だけで列も行も触らない。新名のシートが既にあれば旧名はそのまま残す（手で確認してもらう）。
 * 一度改名すれば旧名は無くなるので、以後は何もしない。
 */
function nwRenameLegacySheets_(ss) {
  const pairs = [
    ['台帳', NW_SHEET_LEDGER], ['資産', NW_SHEET_ASSET], ['処理済み', NW_SHEET_STATE],
    ['実行履歴', NW_SHEET_RUNLOG]
  ];
  pairs.forEach(function (p) {
    const oldSh = ss.getSheetByName(p[0]);
    if (!oldSh || p[0] === p[1]) return;
    if (ss.getSheetByName(p[1])) {
      Logger.log('「' + p[0] + '」と「' + p[1] + '」が両方あります。どちらを使うか手で確認してください。');
      return;
    }
    oldSh.setName(p[1]);
    Logger.log('「' + p[0] + '」シートを「' + p[1] + '」に改名しました。');
  });
}

/**
 * 「台帳」と「処理済み」の 2 行目以降を削除する（見出し行は残す）。
 * nwDaily() の再取得前や列構成変更後に使う。資産シートは触らない。
 * 誤実行防止のため確認ダイアログを出す。
 */
function nwClearRunData() {
  let ui;
  try {
    ui = SpreadsheetApp.getUi();
  } catch (e) {
    throw new Error('nwClearRunData() は確認ダイアログを出すため、対象のスプレッドシートを開いた状態で実行してください。');
  }
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  const ledger = ss.getSheetByName(NW_SHEET_LEDGER);
  const state = ss.getSheetByName(NW_SHEET_STATE);
  if (!ledger && !state) {
    ui.alert('削除対象なし', '「' + NW_SHEET_LEDGER + '」「' + NW_SHEET_STATE + '」シートが見つかりません。nwSetup() を先に実行してください。', ui.ButtonSet.OK);
    return;
  }

  const ledgerRows = ledger && ledger.getLastRow() > 1 ? ledger.getLastRow() - 1 : 0;
  const stateRows = state && state.getLastRow() > 1 ? state.getLastRow() - 1 : 0;
  if (!ledgerRows && !stateRows) {
    ui.alert('削除対象なし', '「' + NW_SHEET_LEDGER + '」「' + NW_SHEET_STATE + '」に削除するデータ行がありません。', ui.ButtonSet.OK);
    Logger.log('nwClearRunData: 削除対象のデータ行なし');
    return;
  }

  const lines = [];
  if (ledgerRows) lines.push('・' + NW_SHEET_LEDGER + ': ' + ledgerRows + ' 行');
  if (stateRows) lines.push('・' + NW_SHEET_STATE + ': ' + stateRows + ' 行');
  const answer = ui.alert(
    'データ削除の確認',
    '次のデータ行をすべて削除します（見出しの 1 行目は残します）。\n\n' +
    lines.join('\n') +
    '\n\n資産シートは削除しません。\nこの操作は元に戻せません。削除しますか？',
    ui.ButtonSet.YES_NO
  );
  if (answer !== ui.Button.YES) {
    ui.alert('キャンセルしました。データは削除していません。');
    Logger.log('nwClearRunData: ユーザーがキャンセル');
    return;
  }

  const removedLedger = nwDeleteSheetDataRows_(NW_SHEET_LEDGER);
  const removedState = nwDeleteSheetDataRows_(NW_SHEET_STATE);
  const summary = [];
  if (removedLedger) summary.push(NW_SHEET_LEDGER + ' ' + removedLedger + ' 行');
  if (removedState) summary.push(NW_SHEET_STATE + ' ' + removedState + ' 行');
  const msg = summary.length ? summary.join(' / ') + ' を削除しました。' : '削除する行はありませんでした。';
  ui.alert('削除完了', msg + '\n\nnwDaily() を実行して再取得できます。', ui.ButtonSet.OK);
  Logger.log('nwClearRunData: ' + msg);
}

/**
 * Fortinet の処理済みと台帳を消し、RSS 50 件を取り直す。
 * 列を増やしたときなど、既存行を新しい構成で埋め直したいときに手で実行する。
 *
 * 注意: 50 件を一度に再処理するため実行が長い。過去に同等の処理量で
 * 6 分の実行時間制限に到達している。制限に当たると、処理済みには記録されたが
 * 台帳には入らなかった件が残る（nwWriteState_ が台帳書き込みより先に走るため）。
 * その場合はもう一度この関数を実行すれば、消してからやり直すので回復する。
 */
function nwReprocessFortinet() {
  const removedState = nwDeleteVendorStateRows_(NW_VENDOR_FORTINET);
  const removedLedger = nwDeleteVendorLedgerRows_(NW_VENDOR_FORTINET);
  Logger.log('Fortinet 再取得の準備: 処理済み ' + removedState + ' 行 / 台帳 ' +
             removedLedger + ' 行を削除');

  const rows = nwRunFortinet_();
  Logger.log('nwReprocessFortinet 完了: 台帳へ ' + rows.length + ' 行');
  if (rows.length) nwNotifySlack_(rows);
  else Logger.log('Fortinet 台帳 0 行。ログの「自社影響」「OS該当」を確認してください。');
  return rows;
}

/**
 * Cisco の処理済み・台帳だけ消して再取得する。
 * 処理済みに残っていると nwDaily() は Cisco を再取得しない。
 */
function nwReprocessCisco() {
  const removedState = nwDeleteVendorStateRows_(NW_VENDOR_CISCO);
  const removedLedger = nwDeleteVendorLedgerRows_(NW_VENDOR_CISCO);
  Logger.log('Cisco 再取得の準備: 処理済み ' + removedState + ' 行 / 台帳 ' + removedLedger + ' 行を削除');

  const rows = nwRunCisco_();
  Logger.log('nwReprocessCisco 完了: 台帳へ ' + rows.length + ' 行');
  if (rows.length) nwNotifySlack_(rows);
  else Logger.log('Cisco 台帳 0 行。ログの「資産対象外」「情報通知」を確認してください。');
  return rows;
}

function nwDeleteVendorStateRows_(vendor) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(NW_SHEET_STATE);
  if (!sh || sh.getLastRow() < 2) return 0;
  const n = sh.getLastRow() - 1;
  const cVendor = nwCol_(NW_STATE_COLS, 'vendor');
  const cId = nwCol_(NW_STATE_COLS, 'advisoryId');
  const vendors = sh.getRange(2, cVendor, n, 1).getDisplayValues();
  const ids = sh.getRange(2, cId, n, 1).getDisplayValues();
  let removed = 0;
  for (let i = n - 1; i >= 0; i--) {
    const rowVendor = String(vendors[i][0] || '').trim();
    const id = String(ids[i][0] || '').trim();
    if (rowVendor !== vendor && nwVendorFromAdvisoryId_(id) !== vendor) continue;
    nwDeleteSheetRowSafe_(sh, i + 2);
    removed++;
  }
  return removed;
}

function nwDeleteVendorLedgerRows_(vendor) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(NW_SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 2) return 0;
  const n = sh.getLastRow() - 1;
  const col = nwCol_(NW_LEDGER_COLS, 'advisory');
  const ids = sh.getRange(2, col, n, 1).getDisplayValues();
  let removed = 0;
  for (let i = n - 1; i >= 0; i--) {
    if (nwVendorFromAdvisoryId_(ids[i][0]) !== vendor) continue;
    nwDeleteSheetRowSafe_(sh, i + 2);
    removed++;
  }
  return removed;
}

/** 指定シートの 2 行目以降を削除する。削除した行数を返す。 */
function nwDeleteSheetDataRows_(sheetName) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(sheetName);
  if (!sh || sh.getLastRow() < 2) return 0;
  const count = sh.getLastRow() - 1;
  nwClearSheetDataRows_(sh);
  return count;
}

/**
 * 見出し固定のシートは、非固定行をすべて delete できない
 * （「固定されていない行をすべて削除することはできません」）。
 * 中身を消して、余った空行だけ詰める。2行目は必ず残す。
 */
function nwClearSheetDataRows_(sh) {
  const last = sh.getLastRow();
  if (last < 2) return;
  const cols = Math.max(sh.getLastColumn(), 1);
  sh.getRange(2, 1, last - 1, cols).clearContent();
  if (last > 2) sh.deleteRows(3, last - 2);
}

function nwDeleteSheetRowSafe_(sh, row) {
  const frozen = sh.getFrozenRows() || 0;
  if (sh.getMaxRows() - 1 <= frozen) {
    sh.getRange(row, 1, 1, Math.max(sh.getLastColumn(), 1)).clearContent();
    return;
  }
  sh.deleteRow(row);
}

function nwDaily() {
  nwStartRunStats_();
  let runError = '';
  try {
    const fortinetRows = nwRunFortinet_();
    const ciscoRows = nwRunCisco_();
    const notifyRows = fortinetRows.concat(ciscoRows);

    // JPCERT の注意喚起は判定に混ぜない。取得して通知へ渡すだけ。
    const alerts = nwNewJpcertAlerts_(nwReadAssets_());
    nwRunStats_.jpcert = alerts.length;

    if (notifyRows.length || alerts.length) {
      if (nwNotifySlack_(notifyRows, alerts)) nwMarkJpcertSeen_(alerts);
    }
    Logger.log('nwDaily() 完了（Fortinet 台帳 ' + fortinetRows.length +
               ' 行 / Cisco 台帳 ' + ciscoRows.length + ' 行）');
  } catch (e) {
    Logger.log('nwDaily() 失敗: ' + e);
    runError = String(e);
    throw e;
  } finally {
    // 落ちた実行こそ履歴に残す。行が無い＝そもそも実行されなかった、と読めるようにする。
    nwWriteRunLog_(runError);
  }
}

function nwRunFortinet_() {
  const assets = nwFortinetAssets_(nwReadAssets_());
  if (!assets.length) {
    Logger.log('警告: Fortinet 対象の資産がありません。');
  }

  const allItems = nwFetchRssItems_();
  // 処理済みシートはこの実行の中で書き換わらない（間にあるのは外部取得とメールだけ）ので、
  // 1 実行につき 1 回だけ読む。
  const known = nwGetKnownState_(NW_VENDOR_FORTINET);

  // RSS の日付では CSAF の改訂を判断できないため、毎回すべて取得する。
  // 実測: RSS の pubDate / description の "Revised on" と CSAF の current_release_date は
  // 双方向にずれる。RSS だけ動いて CSAF が変わらない件（FG-IR-24-257: Revised on 2026-06-15、
  // CSAF は 2025-08-08 のまま）もあれば、RSS が一切動かないまま CSAF だけ改訂される件
  // （FG-IR-26-139: 2026-05-13 公表 → CSAF 2026-06-08 改訂）もある。後者は RSS の日付で
  // 候補を絞る限り永久に検知できない。よって RSS は ID とタイトルの目次としてだけ使い、
  // 既読判定は CSAF の実データ 1 本に寄せる。fetchAll のパラレル取得で 50 件およそ 5 秒。
  Logger.log('Fortinet RSS: 全 ' + allItems.length +
             ' 件の CSAF を取得します（RSS の日付は CSAF の改訂を表さないため毎回全件）');
  const fetched = nwFetchAllCsaf_(allItems);

  let allLedgerRows = [];
  let processedCount = 0;
  const labelTotals = {};

  // RSS は 50 件しか持たないので、対象は必ず 1 回で捌ける。
  // 以前はここを while で回してバッチ分割していたが、2 周目に入る条件が構造上存在しなかった。
  const todo = fetched.filter(function (f) {
    return nwNeedsAdvisoryProcessing_(f.item.ir, f.updatedAt, f.version, known, !!f.error);
  });

  if (!todo.length) Logger.log('Fortinet: 新着・改訂ともになし。');

  if (todo.length) {
    processedCount += todo.length;
    Logger.log('Fortinet: 処理対象 ' + todo.length + ' 件');

    const revised = todo.filter(function (f) { return known.dates[f.item.ir]; });
    if (revised.length) {
      Logger.log('改訂を検知: ' + revised.map(function (f) {
        return f.item.ir + '（' + known.dates[f.item.ir] + ' → ' + nwYmd_(f.updatedAt) + '）';
      }).join(', '));
    }
    // 記録の有無に関わらず、これから書く分は先に消す。前回の実行が台帳を書いた直後に
    // 落ちていると記録が付いておらず、消さずに追記すると同じ行が二重に並ぶ。
    nwRemoveRowsFor_(NW_VENDOR_FORTINET, todo.map(function (f) { return f.item.ir; }));

    let rows = [];
    todo.forEach(function (f) {
      if (f.error) {
        Logger.log((f.missing ? 'CSAF未作成: ' : 'CSAF 取得失敗（翌日再取得）: ') +
                   f.item.ir + ' / ' + f.error);
        // RSS に CVSS と説明文があるので、それだけで台帳の行にする。
        // 台帳から落とすと実行ログ以外に痕跡が残らない。
        rows.push(nwExtractFortinetRowFallback_(f.item));
        return;
      }
      rows = rows.concat(nwExtractRows_(f.csaf, f.item));
    });
    Logger.log('展開後の行数: ' + rows.length);

    rows.forEach(function (r) { nwDecideNotification_(r, assets); });

    const counts = nwCountVerdicts_(rows);
    Logger.log('全 ' + rows.length + ' 行: ' + NW_V_ACT + ' ' + counts[NW_V_ACT] +
               ' / ' + NW_V_INVEST + ' ' + counts[NW_V_INVEST] + ' / ' + NW_V_NONE + ' ' + counts[NW_V_NONE]);

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
               version: NW_STATE_VERSION_UNAVAILABLE, error: f.error, missing: f.missing };
    });
    const judgeRows = nwSnapshotJudgeRows_(rows);

    const ledgerRows = rows.filter(function (r) { return nwIsLedgerRow_(r, assets); });
    Logger.log('Fortinet 台帳: ' + ledgerRows.length + ' / ' + rows.length + ' 行');

    nwFillLedgerDisplay_(ledgerRows);

    nwWriteLedger_(ledgerRows);

    // 処理済みへの記録は台帳へ書き終えてから。逆順だと、AI 生成中に 6 分の実行時間制限に
    // 当たったとき「処理済みには記録されたが台帳には無い」状態が残り、
    // 翌日以降は既知として扱われて改訂まで台帳に載らない。
    // この順なら、途中で落ちても記録が付かないので次の実行でやり直せる。
    nwMergeCounts_(labelTotals, nwWriteState_(NW_VENDOR_FORTINET, recordable, judgeRows, assets));

    allLedgerRows = allLedgerRows.concat(ledgerRows);
  }

  if (allLedgerRows.length) nwSortLedger_();

  nwAddVendorStats_(NW_VENDOR_FORTINET, {
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
 * 台帳に載せる行かどうか。製品不明・非保有・OS対象外は出さない（処理済みには残る）。
 *
 * 自社影響が「なし」でも、版が影響範囲内なら台帳に残す。社内ルールで臨時更新しないと
 * 判断した記録そのものが監査で必要になる。通知から外れるだけで台帳からは消えない。
 *
 * ただし古い「なし」は落とす。定期更新で解消済みの行が積み上がると、判断が必要な行が
 * 埋もれて台帳を開かなくなる（NW_KEEP_OUT_OF_SCOPE_MONTHS）。
 * 落としても処理済みシートには全件残るので、取得した事実は消えない。
 */
function nwIsLedgerRow_(row, assets) {
  // 製品が分からない行を通すのは、CSAF が取れなかったときだけ。
  // それ以外で製品が空なのは抽出の失敗なので、従来どおり落とす。
  // 通さないと、取得に失敗した件が台帳から消えて誰も気づけなくなる。
  if (!row.product) return !!row.noCsaf;
  if (!nwAssetsForProduct_(assets, row.product).length) return false;
  if (row.osStatus === '対象外') return false;
  if (row.verdict === NW_V_NONE && nwIsStaleOutOfScope_(row.pubDate)) return false;
  return true;
}

/**
 * 台帳の表示列（影響機能・確認方法・ユーザ影響）を埋め、保留中の判定を確定させる。
 *
 * ルールゲートで「なし」に落ちた行は AI を呼ばず、コードのフォールバックだけで埋める。
 * 影響機能を分類しても結論が変わらない行に API を使う理由がない。
 * ただし列を空にはしない。空欄だと「AI が失敗した行」と区別できなくなる。
 */
function nwFillLedgerDisplay_(rows) {
  const needAi = rows.filter(function (r) { return r.needsVerdict || r.needsDisplayAi; });
  const codeOnly = rows.filter(function (r) { return r.needsCodeDisplay; });
  if (!needAi.length && !codeOnly.length) return;

  if (needAi.length) {
    try {
      nwEnrichWithAI_(needAi);
    } catch (e) {
      Logger.log('AI 生成に失敗しました。フォールバックで表示列を埋めます: ' + e);
    }
  }
  if (codeOnly.length) {
    Logger.log('ルールゲートで「なし」に確定した ' + codeOnly.length + ' 行は AI を呼びません。');
  }

  needAi.concat(codeOnly).forEach(function (r) {
    nwApplyFallbackDisplayFields_(r);
    if (r.needsVerdict && !r._lockedVerdict) nwFinalizeVerdict_(r);
    else if (r.feature && r.feature !== '—') r.reason = nwBuildDecisionReason_(r);
    // finalize で影響機能が変わった場合に確認方法を合わせ直す
    r.howToCheck = nwNormalizeHowToCheck_(r);
    r.cveSummaryJa = nwSlackContentsJa_(r);
    r.impactJa = nwPreferImpactJa_(r);
  });
}

/**
 * AI のユーザ影響を採用しつつ、CVSS と明らかに矛盾する文はフォールバックへ戻す。
 */
function nwPreferImpactJa_(row) {
  const ai = nwTruncateJa_(row.impactJa || '', 50);
  const fb = nwTruncateJa_(nwFallbackImpactJa_(row), 50);
  if (!ai) return fb;

  const parts = nwParseCvssCia_(row.vector);
  if (parts) {
    const takeoverWords = /掌握|乗っ取|改ざん|傍受/;
    const dosOnly = parts.C === 'N' && parts.I === 'N' && parts.A === 'H';
    if (dosOnly && takeoverWords.test(ai)) return fb;
    const fullCia = parts.C === 'H' && parts.I === 'H';
    if (fullCia && /停止|全断/.test(ai) && !takeoverWords.test(ai)) return fb;
    if (parts.A !== 'H' && /拠点の通信/.test(ai)) return fb;
  }
  if (nwIsReloadDos_(row) && /応答停止/.test(ai) && !/再起動/.test(ai)) return fb;
  if (nwIsMgmtPlaneDos_(row) && /拠点の通信/.test(ai)) return fb;
  return ai;
}

/** 「なし」を台帳から落としてよいほど古いか。 */
function nwIsStaleOutOfScope_(pubDate) {
  if (!NW_KEEP_OUT_OF_SCOPE_MONTHS) return false;
  if (!(pubDate instanceof Date) || isNaN(pubDate.getTime())) return false;

  const limit = new Date();
  limit.setMonth(limit.getMonth() - NW_KEEP_OUT_OF_SCOPE_MONTHS);
  return pubDate < limit;
}

// ============================================================
// Cisco CSAF RSS（主）→ CSAF JSON / 通常RSS（補助）
// ============================================================

/** CSAF JSON の URL 組み立て保険。主経路は CSAF RSS の guid/link を使う */
var NW_CISCO_CSAF_BASE = 'https://tools.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/';

function nwRunCisco_() {
  const assets = nwCiscoAssets_(nwReadAssets_());
  if (!assets.length) {
    Logger.log('Cisco: ツール対象の資産がありません。スキップします。');
    nwAddVendorStats_(NW_VENDOR_CISCO, { note: '資産に対象機器が無くスキップ' });
    return [];
  }

  const allItems = nwFetchCiscoCsafRssItems_();
  const known = nwGetKnownState_(NW_VENDOR_CISCO);

  const candidates = nwSelectRssCsafCandidates_(allItems, known, function (it) { return it.id; },
    function (it) { return it.pubDate; });
  Logger.log('Cisco CSAF RSS: 全 ' + allItems.length + ' 件 → CSAF 取得 ' + candidates.length +
             ' 件（残りは前回から更新なし。Cisco はフィードの日付が CSAF と一致するため差分のみ取得）');

  const fetched = nwFetchCiscoCsafBatch_(candidates);

  let allLedgerRows = [];
  let processedCount = 0;
  const labelTotals = {};

  // 対象が必ず 1 回で捌ける理由は nwRunFortinet_ の同じ箇所。
  const todo = fetched.filter(function (f) {
    // hasError を渡す。渡さないと、記録済みなのに CSAF が取れなかった件で
    // 版の比較（記録は「未取得」／取得結果は空）が永久に一致せず、
    // 毎日その件を作り直して Slack にも出し続ける。
    // いまは nwSelectRssCsafCandidates_ が手前で弾くので表面化しないが、
    // それは偶然で、この関数自身が同じ答えを返せなければ揃っていない。
    return nwNeedsAdvisoryProcessing_(f.item.id, f.updatedAt, f.version, known, !!f.error);
  });

  if (!todo.length) Logger.log('Cisco: 新着・改訂ともになし。');

  if (todo.length) {
    processedCount += todo.length;
    Logger.log('Cisco 処理対象 ' + todo.length + ' 件');

    // これから書く分は先に消す（理由は nwRunFortinet_ の同じ箇所）。
    nwRemoveRowsFor_(NW_VENDOR_CISCO, todo.map(function (f) { return f.item.id; }));

    let humanIndex = null;
    let rows = [];
    todo.forEach(function (f) {
      if (f.error) {
        Logger.log('Cisco CSAF 取得失敗: ' + f.item.id + ' / ' + f.error);
        if (!humanIndex) humanIndex = nwFetchCiscoHumanRssIndex_();
        const human = humanIndex[f.item.id] || {};
        const fallbackItem = {
          id: f.item.id,
          title: human.title || f.item.title,
          link: human.link || f.item.link || nwCiscoHumanAdvisoryUrl_(f.item.id),
          description: human.description || '',
          pubDate: human.pubDate || f.item.pubDate
        };
        const fb = nwExtractCiscoRowFallback_(fallbackItem);
        if (fb) rows.push(fb);
        return;
      }
      const extracted = nwExtractCiscoRowsFromCsaf_(f.csaf, f.item, assets);
      if (!extracted.length) {
        Logger.log('Cisco 資産対象外: ' + f.item.id);
      }
      rows = rows.concat(extracted);
    });

    rows.forEach(function (r) { nwDecideNotification_(r, assets); });

    const counts = nwCountVerdicts_(rows);
    Logger.log('Cisco 全 ' + rows.length + ' 行: ' + NW_V_ACT + ' ' + counts[NW_V_ACT] +
               ' / ' + NW_V_INVEST + ' ' + counts[NW_V_INVEST] + ' / ' + NW_V_NONE + ' ' + counts[NW_V_NONE]);

    // 取得に失敗した件も記録する（理由は nwRunFortinet_ の同じ箇所。両ベンダー同じ方針）。
    // ただし版を空のままにすると nwSelectRssCsafCandidates_ の「版が空なら再取得」に
    // 毎回引っかかり、取得できない件を永久に取り続ける。印を書いてループを止める。
    const recordable = todo.map(function (f) {
      if (!f.error) return f;
      return { item: f.item, csaf: f.csaf, updatedAt: f.updatedAt,
               version: NW_STATE_VERSION_UNAVAILABLE, error: f.error, missing: f.missing };
    });
    const judgeRows = nwSnapshotJudgeRows_(rows);

    const ledgerRows = rows.filter(function (r) { return nwIsLedgerRow_(r, assets); });
    Logger.log('Cisco 台帳: ' + ledgerRows.length + ' / ' + rows.length + ' 行');

    nwFillLedgerDisplay_(ledgerRows);

    nwWriteLedger_(ledgerRows);

    // 処理済みへの記録は台帳へ書き終えてから（理由は nwRunFortinet_ の同じ箇所）。
    nwMergeCounts_(labelTotals, nwWriteState_(NW_VENDOR_CISCO, recordable, judgeRows, assets));

    allLedgerRows = allLedgerRows.concat(ledgerRows);
  }

  if (allLedgerRows.length) nwSortLedger_();

  nwAddVendorStats_(NW_VENDOR_CISCO, {
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

function nwFetchCiscoCsaf_(itemOrId) {
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
    url = NW_CISCO_CSAF_BASE + id + '/csaf/' + id + '_csaf.json';
  }
  if (!url) throw new Error('CSAF URL が空です');

  const res = UrlFetchApp.fetch(url, { muteHttpExceptions: true, followRedirects: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('HTTP ' + res.getResponseCode() + ' / ' + url);
  }
  return JSON.parse(res.getContentText());
}

/** CSAF product_tree の product_id → 版番号（17.15.5 等） */
function nwCiscoProductMap_(csaf) {
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

function nwCiscoAffectedVersions_(vuln, idMap) {
  const versions = [];
  ((vuln.product_status || {}).known_affected || []).forEach(function (id) {
    const v = nwCiscoVersionFromName_(idMap[id]);
    if (v) nwPushUnique_(versions, v);
  });
  return versions;
}

/** "17.15.5" または "Cisco IOS XE Software 17.15.5" から版番号を取る。 */
function nwCiscoVersionFromName_(name) {
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
function nwCiscoFixedVersions_(vuln, idMap) {
  const versions = [];
  const status = vuln.product_status || {};
  ['fixed', 'first_fixed'].forEach(function (key) {
    (status[key] || []).forEach(function (id) {
      const name = idMap[id] || String(id);
      const m = /(\d+\.\d+(?:\.\d+)?)/.exec(name);
      if (m) nwPushUnique_(versions, m[1]);
    });
  });
  return nwSortVersionsAsc_(versions);
}

function nwSortVersionsAsc_(versions) {
  return versions.slice().sort(function (a, b) {
    return nwCompareVersion_(nwParseVersion_(a) || [0], nwParseVersion_(b) || [0]);
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
function nwCiscoWorkaround_(csaf) {
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
    if (t.length <= 80 && nwIsCiscoConfigCommand_(t)) nwPushUnique_(cmds, t);
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
function nwIsCiscoConfigCommand_(line) {
  return /^(no\s|ip\s|ipv6\s|interface\s|line\s|snmp-server\s|service\s|access-list\s|transport\s|shutdown\b|config-|router\s|control-plane\b|class-map\s|policy-map\s)/i
    .test(line);
}

function nwCiscoConfigHints_(csaf) {
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
 * 台帳用の nwCiscoTargetProducts_ とは目的が違う。あちらは「自社資産のどれに当たるか」を
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
function nwCiscoCsafProductNames_(csaf) {
  const out = [];
  function walk(b) {
    if (!b) return;
    const cat = String(b.category || '');
    if ((cat === 'product_family' || cat === 'product_name') && b.name) {
      const n = String(b.name).trim();
      if (n) nwPushUnique_(out, n);
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

function nwCiscoProductTreeNames_(csaf) {
  const names = [];
  function walk(branch) {
    if (!branch) return;
    // 葉の product.name は版番号が多い。親の Cisco IOS XE Software も拾う。
    if (branch.name) nwPushUnique_(names, branch.name);
    if (branch.product && branch.product.name) nwPushUnique_(names, branch.product.name);
    (branch.branches || []).forEach(walk);
  }
  ((csaf.product_tree || {}).branches || []).forEach(walk);
  return names;
}

/** 製品名の突合（IOS-XE ↔ Cisco IOS XE Software 等）。 */
function nwProductNamesMatch_(assetProduct, csafName) {
  const a = nwNormProduct_(assetProduct);
  const b = nwNormProduct_(csafName);
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
function nwCiscoAdvisoryTargetsAssets_(csaf, assets) {
  const assetProducts = [];
  const assetVersions = [];
  assets.forEach(function (a) {
    if (a.product && a.product !== '—') nwPushUnique_(assetProducts, a.product);
    if (a.version) nwPushUnique_(assetVersions, String(a.version).trim());
  });
  if (!assetProducts.length && !assetVersions.length) return false;

  const treeNames = nwCiscoProductTreeNames_(csaf);
  for (let i = 0; i < assetProducts.length; i++) {
    for (let j = 0; j < treeNames.length; j++) {
      if (nwProductNamesMatch_(assetProducts[i], treeNames[j])) return true;
    }
  }

  if (!assetVersions.length) return false;
  const idMap = nwCiscoProductMap_(csaf);
  const aff = {};
  (csaf.vulnerabilities || []).forEach(function (v) {
    nwCiscoAffectedVersions_(v, idMap).forEach(function (ver) {
      aff[String(ver).trim().toLowerCase()] = true;
    });
  });
  return assetVersions.some(function (v) { return aff[v.toLowerCase()]; });
}

/** 資産シートの製品のうち、このアドバイザリが実際に言及しているもの。 */
function nwCiscoTargetProducts_(csaf, assets) {
  const candidates = [];
  assets.forEach(function (a) {
    if (a.product && a.product !== '—') nwPushUnique_(candidates, a.product);
  });
  if (!candidates.length) return [];

  const treeNames = nwCiscoProductTreeNames_(csaf);
  const idMap = nwCiscoProductMap_(csaf);
  const allAff = [];
  (csaf.vulnerabilities || []).forEach(function (v) {
    nwCiscoAffectedVersions_(v, idMap).forEach(function (ver) { nwPushUnique_(allAff, ver); });
  });

  return candidates.filter(function (p) {
    const np = nwNormProduct_(p);
    if (treeNames.some(function (t) { return nwProductNamesMatch_(p, t); })) return true;
    const vers = assets.filter(function (a) { return nwNormProduct_(a.product) === np; })
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
function nwExtractCiscoRowsFromCsaf_(csaf, item, assets) {
  if (nwIsCiscoInformationalAdvisory_(csaf, item)) {
    Logger.log('Cisco 情報通知（脆弱性ではない）のため台帳対象外: ' +
               ((item && item.id) || ''));
    return [];
  }
  assets = assets || [];
  if (!nwCiscoAdvisoryTargetsAssets_(csaf, assets)) {
    return [];
  }
  const targetProducts = nwCiscoTargetProducts_(csaf, assets);
  if (!targetProducts.length) return [];

  const doc = csaf.document || {};
  const tracking = doc.tracking || {};
  const advisoryId = tracking.id || item.id;
  const updatedAt = tracking.current_release_date
    ? nwCsafDate_(tracking.current_release_date, item.pubDate)
    : nwCsafDate_(tracking.initial_release_date, item.pubDate);
  const initialAt = nwCsafDate_(tracking.initial_release_date, updatedAt);
  const vulnName = String(doc.title || item.title || '').trim();
  const idMap = nwCiscoProductMap_(csaf);
  const configHints = nwCiscoConfigHints_(csaf);
  const docClasses = nwCiscoDocCveClasses_(csaf);
  const vulns = csaf.vulnerabilities || [];
  const product = targetProducts[0];

  // 修正版の自動取得（openVuln）は GAS では使わない。CSAF に版があれば使い、無ければ空。
  const workaround = nwCiscoWorkaround_(csaf);

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

    const affectedVersions = nwCiscoAffectedVersions_(v, idMap);
    // CSAF に fixed が入っている稀な場合だけ拾う。
    const fixedVersions = nwCiscoFixedVersions_(v, idMap);
    const fixes = [];
    (v.remediations || []).forEach(function (r) {
      if (r.category === 'vendor_fix' && r.details) nwPushUnique_(fixes, r.details);
    });

    // CVE 側に何も書かれていないアドバイザリがある。Security Hardening Release は
    // vulnerabilities[].title が全件同一で notes も「Complete.」だけ（実測）。
    // その場合でも document.notes に CVE ごとの CWE 分類表が載っているので、
    // そこから補う。無いと確認する人に手がかりが 1 つも渡らない。
    const summary = [
      nwNoteText_(v, function (n) { return n.category === 'summary'; }),
      docClasses[String(v.cve || '').toUpperCase()] || '',
      configHints
    ].filter(function (s) { return s; }).join('\n\n');

    return {
      vendor: NW_VENDOR_CISCO,
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
      unauthRemote: nwIsUnauthRemote_(vector) ? 'はい' : 'いいえ',
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
      feature: '', impactJa: '', howToCheck: ''
    };
  });
}

/** CSAF 失敗時の保険（通常 RSS）。情報通知 ID は行にしない。 */
function nwExtractCiscoRowFallback_(item) {
  if (nwIsCiscoInformationalAdvisory_(null, item)) {
    Logger.log('Cisco 情報通知のためフォールバック行も作らない: ' + (item && item.id));
    return null;
  }
  const meta = nwParseCiscoRssMeta_(item.description);
  return {
    vendor: NW_VENDOR_CISCO,
    advisoryId: item.id,
    advisoryUrl: item.link,
    pubDate: item.pubDate,
    initialDate: item.pubDate,
    title: item.title,
    cve: meta.cves[0] || nwExtractCveFromText_(item.title + ' ' + item.description),
    // 製品は空のまま（理由は nwExtractFortinetRowFallback_ と同じ）。
    // Cisco の RSS タイトルには製品名が入るが、そこから当てにはいかない。
    // 影響製品を 1 つしか名乗らない題名があり、ClamAV 型は製品名すら書かない。
    // CSAF が無い状態で製品を断定するのは、ここで直している誤りと同じになる。
    product: '',
    noCsaf: true,
    cvss: meta.cvss,
    severity: meta.severity,
    vector: '', unauthRemote: '',
    affected: [],
    summary: nwDecodeCiscoHtml_(item.description || ''),
    impact: '',
    fixesRaw: '',
    workaround: '',
    verdict: NW_V_INVEST,
    // reason ではなく reasonPhrase に置く。reason は nwDecideNotification_ が
    // 「OS=… | KEV=…」の見出しごと組み立て直すので、ここで書いても消える。
    reasonPhrase: 'CSAF を取得できず製品も版も特定できないため',
    selfVersion: '', fixVersion: '',
    feature: '', impactJa: '', howToCheck: ''
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
function nwCiscoDocCveClasses_(csaf) {
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
function nwIsCiscoInformationalAdvisory_(csaf, item) {
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

function nwParseCiscoRssMeta_(description) {
  const html = nwDecodeCiscoHtml_(description);
  const sir = /Security Impact Rating:\s*(\w+)/i.exec(html);
  const cvss = /CVSS Base Score:\s*([\d.]+)/i.exec(html);
  const cves = html.match(/CVE-\d{4}-\d{4,}/gi) || [];
  return {
    severity: sir ? sir[1].toUpperCase() : '',
    cvss: cvss ? cvss[1] : '',
    cves: cves.map(function (c) { return c.toUpperCase(); })
  };
}

function nwDecodeCiscoHtml_(s) {
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
function nwFetchCiscoCsafRssItems_() {
  const res = UrlFetchApp.fetch(NW_CISCO_CSAF_RSS_URL, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('Cisco CSAF RSS 取得失敗 HTTP ' + res.getResponseCode());
  }

  const root = XmlService.parse(res.getContentText()).getRootElement();
  const items = root.getChild('channel').getChildren('item');

  return items.map(function (item) {
    const title = String(item.getChildText('title') || '').trim();
    const guid = String(item.getChildText('guid') || '').trim();
    const link = String(item.getChildText('link') || '').trim();
    const csafUrl = nwNormalizeCiscoCsafUrl_(guid || link);
    const id = nwParseCiscoAdvisoryId_(title || csafUrl || link);
    return {
      id: id,
      title: title || id,
      link: nwCiscoHumanAdvisoryUrl_(id),
      csafUrl: csafUrl,
      description: '',
      pubDate: nwParsePubDate_(item.getChildText('pubDate'))
    };
  }).filter(function (it) { return it.id && it.csafUrl; });
}

/** guid/link からクエリを落とし、https にそろえる */
function nwNormalizeCiscoCsafUrl_(raw) {
  let u = String(raw || '').trim();
  if (!u) return '';
  u = u.replace(/^http:\/\//i, 'https://').replace(/:80\//, '/');
  const q = u.indexOf('?');
  if (q !== -1) u = u.slice(0, q);
  return /\.json$/i.test(u) ? u : '';
}

/** 人向けアドバイザリページ。台帳のハイパーリンク用 */
function nwCiscoHumanAdvisoryUrl_(advisoryId) {
  const id = String(advisoryId || '').trim();
  if (!id) return '';
  return 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/' + id;
}

/**
 * 通常 RSS（補助）。CSAF 取得失敗時にタイトル・概要を補う。
 * 主経路ではないので失敗しても空オブジェクトを返す。
 */
function nwFetchCiscoHumanRssIndex_() {
  try {
    const res = UrlFetchApp.fetch(NW_CISCO_RSS_URL, { muteHttpExceptions: true });
    if (res.getResponseCode() !== 200) return {};
    const root = XmlService.parse(res.getContentText()).getRootElement();
    const items = root.getChild('channel').getChildren('item');
    const map = {};
    items.forEach(function (item) {
      const link = item.getChildText('link') || '';
      const id = nwParseCiscoAdvisoryId_(link);
      if (!id) return;
      map[id] = {
        title: item.getChildText('title') || '',
        link: link,
        description: item.getChildText('description') || '',
        pubDate: nwParsePubDate_(item.getChildText('pubDate'))
      };
    });
    return map;
  } catch (e) {
    Logger.log('Cisco 通常 RSS（補助）取得失敗: ' + e);
    return {};
  }
}

function nwParseCiscoAdvisoryId_(link) {
  const m = /cisco-sa-[a-z0-9-]+/i.exec(link || '');
  return m ? m[0] : String(link || '').trim();
}

function nwExtractCveFromText_(text) {
  const m = /CVE-\d{4}-\d{4,}/gi.exec(String(text || ''));
  return m ? m[0].toUpperCase() : '';
}

/**
 * Cisco 版番号の完全一致判定。
 * CSAF の known_affected を 17.15.5 等の版番号に展開した配列と突き合わせる。
 */
function nwJudgeCiscoVersions_(assetVersions, affectedVersions) {
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
// RSS 取得と CSAF の URL 導出
// ============================================================

/**
 * "Tue, 14 Jul 2026 00:00:00 -0700" や CSAF RSS の "2026-08-21 16:54:40.0" を Date にする。
 * 失敗したら元の文字列を返す。
 */
function nwParsePubDate_(s) {
  if (!s) return '';
  const raw = String(s).trim();
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
function nwSlugifyTitle_(title) {
  return String(title || '')
    .toLowerCase()
    .replace(/['"‘’“”]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function nwCsafUrlFor_(item) {
  return NW_CSAF_BASE + nwSlugifyTitle_(item.title) + '_' + String(item.ir).toLowerCase() + '.json';
}

function nwFetchRssItems_() {
  const res = UrlFetchApp.fetch(NW_RSS_URL, { muteHttpExceptions: true });
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
      pubDate: nwParsePubDate_(item.getChildText('pubDate')),
      revisedOn: rev ? new Date(Number(rev[1]), Number(rev[2]) - 1, Number(rev[3])) : '',
      description: desc
    };
  });
}

// ============================================================
// CSAF の取得と行への展開
// ============================================================

/**
 * CSAF を 1 件取得する（単体確認用。日次実行は nwFetchAllCsaf_ を使う）。
 *
 * かつては失敗時にアドバイザリ HTML から csaf_url を拾う「保険」を持っていたが、
 * その経路は成立しないため削除した。fortiguard.fortinet.com のアドバイザリページは
 * JS で描画され、HTML 中に文字列 "csaf" は 1 度も現れない（altcha によるボット対策も入る）。
 * 残しておくと、失敗のたびに無駄なリクエストを 2 本増やしたうえ、
 * 「取りこぼしても回復手段がある」という誤解だけが残る。
 */
function nwFetchCsaf_(item) {
  const url = nwCsafUrlFor_(item);
  const res = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    throw new Error('CSAF 取得失敗 HTTP ' + res.getResponseCode() + ': ' + url);
  }
  return JSON.parse(res.getContentText());
}

/** Date を 'yyyy-mm-dd' にする。既読判定の突合キーに使うため文字列で揃える。 */
function nwYmd_(d) {
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
 * 使わず毎回全件を取得する（理由は nwRunFortinet_ のコメント）。
 *
 * CSAF 版が空欄の既存行も取り直す。取得に失敗した件には「未取得」の印を書くので、
 * ここに引っかかるのは印が付く前に記録された古い行だけ。**印を書かずに空欄のままに
 * すると、取得できない件を毎日取り続けることになる。**
 */
function nwSelectRssCsafCandidates_(items, known, getId, getRssDate) {
  let skip = 0;
  const out = items.filter(function (it) {
    const id = getId(it);
    const prev = known.dates[id];
    if (!prev) return true;
    if (!known.versions[id]) return true;
    const rssY = nwYmd_(getRssDate(it));
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
function nwNeedsAdvisoryProcessing_(id, csafDate, csafVersion, known, hasError) {
  if (hasError && known.dates[id]) return false;
  if (!known.dates[id]) return true;
  if (nwYmd_(csafDate) !== known.dates[id]) return true;
  if (String(csafVersion || '') !== String(known.versions[id] || '')) return true;
  return false;
}

function nwCsafTrackingVersion_(csaf) {
  const v = (((csaf || {}).document || {}).tracking || {}).version;
  return v === undefined || v === null ? '' : String(v);
}

function nwFetchCiscoCsafBatch_(items) {
  return items.map(function (it, i) {
    if (i > 0) Utilities.sleep(300);
    try {
      const csaf = nwFetchCiscoCsaf_(it);
      return {
        item: it,
        csaf: csaf,
        updatedAt: nwCsafUpdatedAt_(csaf, it),
        version: nwCsafTrackingVersion_(csaf),
        products: nwCiscoCsafProductNames_(csaf),
        error: ''
      };
    } catch (e) {
      // 失敗時の日付は Fortinet と同じ nwLastSeenDate_ を通す。Cisco の item は
      // revisedOn を持たないので結果は it.pubDate と同値（実測で確認）。
      // 揃えておくのは、両ベンダーの失敗経路を読み比べたときに
      // 「なぜ違うのか」を考えさせないため。差があるなら根拠が要る（§4.5）。
      return { item: it, csaf: null, updatedAt: nwLastSeenDate_(it), version: '', error: String(e) };
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
function nwFetchAllCsaf_(items) {
  const reqs = items.map(function (it) {
    return { url: nwCsafUrlFor_(it), muteHttpExceptions: true };
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
        return { item: it, csaf: csaf, updatedAt: nwCsafUpdatedAt_(csaf, it),
          version: nwCsafTrackingVersion_(csaf), error: '', missing: false };
      } catch (e) {
        failed++;
        return { item: it, csaf: null, updatedAt: nwLastSeenDate_(it), version: '',
          error: 'CSAF の解析に失敗: ' + e, missing: false };
      }
    }

    if (code === 404) {
      missing++;
      return { item: it, csaf: null, updatedAt: nwLastSeenDate_(it), version: '',
        error: 'CSAF未作成（HTTP 404。ベンダーがこのアドバイザリの CSAF を出していない）',
        missing: true };
    }

    failed++;
    return { item: it, csaf: null, updatedAt: nwLastSeenDate_(it), version: '',
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
function nwLastSeenDate_(item) {
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
function nwCsafDate_(value, fallback) {
  if (!value) return fallback;
  const d = new Date(value);
  return isNaN(d.getTime()) ? fallback : d;
}

function nwCsafUpdatedAt_(csaf, item) {
  const t = ((csaf || {}).document || {}).tracking || {};
  if (t.current_release_date) return nwCsafDate_(t.current_release_date, item.pubDate);
  if (t.initial_release_date) return nwCsafDate_(t.initial_release_date, item.pubDate);
  return item.pubDate;
}

/** CVSS ベクターから「無認証・リモート・利用者操作不要」かを判定する。LLM 不使用。 */
function nwIsUnauthRemote_(vector) {
  if (!vector) return false;
  return /AV:N/.test(vector) && /PR:N/.test(vector) && /UI:N/.test(vector);
}

function nwNoteText_(v, matcher) {
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
function nwExtractRows_(csaf, item) {
  const doc = csaf.document || {};
  const tracking = doc.tracking || {};
  const advisoryId = tracking.id || item.ir;
  // 台帳に出すのは「最終更新日」であって初回公表日ではない。
  // Fortinet は既存アドバイザリを改訂して影響製品・影響バージョンを追加する。
  // 初回公表日で並べると、改訂で新たに自社が対象になった件が
  // 何か月も前の日付として沈み、「今月見るべきもの」から漏れる。
  // 初回公表日は処理済みシートに残す。
  const updatedAt = tracking.current_release_date
    ? nwCsafDate_(tracking.current_release_date, item.pubDate)
    : nwCsafDate_(tracking.initial_release_date, item.pubDate);
  const initialAt = nwCsafDate_(tracking.initial_release_date, updatedAt);

  // 脆弱性名は document.title を使う。
  // vulnerabilities[].title は "FortiOS - LOW - FG-IR-24-257" のような
  // 製品・深刻度・IDを並べた内部管理用の文字列で、脆弱性の名前ではない。
  const vulnName = String(doc.title || item.title || '').trim();

  // CSAF に vulnerabilities キーが無いアドバイザリがある（実測 50 件中 3 件）。
  // Linux Kernel や npm パッケージなど他社製コンポーネント由来の告知で、
  // 製品・バージョンの対応表が CSAF に載っていない（product_tree も空）。
  //
  // ここで空配列を返すと行が 1 つも作られない。行が無いということは
  // 処理済みシートに記録が残らないため既読にもならず、
  //   ・分母から永久に欠落する（本ツールの第一目的を壊す）
  //   ・毎回取得し直し、実行枠を食い続ける
  // という二重の実害になる。1 行立てて人に回す。
  const vulns = csaf.vulnerabilities || [];
  if (!vulns.length) {
    Logger.log('vulnerabilities なし: ' + advisoryId + '（判定不能として1行記録します）');
    return [nwNoVulnRow_(item, advisoryId, updatedAt, initialAt, vulnName)];
  }

  return vulns.map(function (v) {
    // 製品名は scores[].products が正。known_affected の先頭語では
    // "FortiSOAR PaaS" のような空白入りの名前を切り落としてしまう。
    const products = [];
    let score = '', severity = '', vector = '';

    (v.scores || []).forEach(function (s) {
      (s.products || []).forEach(function (p) { nwPushUnique_(products, p); });
      const c = s.cvss_v4 || s.cvss_v3 || {};
      if (c.vectorString && !vector) vector = c.vectorString;
      if (c.baseScore !== undefined && (score === '' || c.baseScore > score)) {
        score = c.baseScore;
        severity = c.baseSeverity || '';
      }
    });

    const affected = ((v.product_status || {}).known_affected || []);
    const product = products[0] || nwGuessProductFromAffected_(affected);

    const fixes = [];
    (v.remediations || []).forEach(function (r) {
      if (r.category === 'vendor_fix' && r.details) nwPushUnique_(fixes, r.details);
    });

    const workaround = nwNoteText_(v, function (n) {
      return String(n.title || '').toLowerCase().indexOf('workaround') !== -1;
    });

    return {
      vendor: NW_VENDOR_FORTINET,
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
      unauthRemote: nwIsUnauthRemote_(vector) ? 'はい' : 'いいえ',
      affected: affected,                       // 配列のまま持つ
      summary: nwNoteText_(v, function (n) { return n.category === 'summary'; }),
      impact: (v.threats || [])
        .filter(function (t) { return t.category === 'impact'; })
        .map(function (t) { return t.details; })
        .join(', '),
      fixesRaw: fixes.join('\n'),
      workaround: (workaround && workaround.toUpperCase() !== 'N/A') ? workaround : '',
      verdict: '', reason: '', selfVersion: '', fixVersion: '',
      feature: '', impactJa: '', howToCheck: ''
    };
  });
}

/**
 * CSAF に脆弱性情報が無いアドバイザリ用の 1 行。
 * 使える情報はタイトル・公開日・URL だけなので、判定はせず人に回す。
 * タイトルに CVE 番号が書かれていることがあるので拾う
 * （例: "Linux Kernel Vulnerability copy.fail - CVE-2026-31431"）。
 */
function nwNoVulnRow_(item, advisoryId, pubDate, initialAt, vulnName) {
  const m = /CVE-\d{4}-\d{4,}/.exec(vulnName || '');
  return {
    vendor: NW_VENDOR_FORTINET,
    advisoryId: advisoryId,
    advisoryUrl: item.link,
    pubDate: pubDate,
    initialDate: initialAt,
    title: vulnName,
    cve: m ? m[0] : '',
    product: '',
    cvss: '', severity: '', vector: '', unauthRemote: '',
    affected: [], summary: vulnName, impact: '', fixesRaw: '', workaround: '',
    verdict: NW_V_INVEST,
    reason: 'この情報元だけでは自社への影響を自動判定できません。アドバイザリを人が読んで判定してください。',
    selfVersion: '', fixVersion: '',
    feature: '', impactJa: '', howToCheck: ''
  };
}

/** scores に products がない場合の保険。既知の製品名で最長一致させる。 */
function nwGuessProductFromAffected_(affected) {
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
 * Cisco は以前からこの形（nwExtractCiscoRowFallback_）で、Fortinet だけ無かった。
 *
 * 製品は名乗らない（空のまま）。RSS のタイトルに製品名が無く、主力製品を充てると
 * 「分からない」が「FortiOS だと分かった」に化ける（§4.7）。詳細は本体のコメント。
 */
function nwExtractFortinetRowFallback_(item) {
  const text = nwDecodeCiscoHtml_(item.description || '');
  const cvss = /CVSSv3 Score:\s*([\d.]+)/i.exec(text);
  const cves = text.match(/CVE-\d{4}-\d{4,}/gi) || [];

  return {
    vendor: NW_VENDOR_FORTINET,
    advisoryId: item.ir,
    advisoryUrl: item.link,
    pubDate: nwLastSeenDate_(item),
    initialDate: item.pubDate,
    title: item.title,
    cve: cves.length ? cves[0].toUpperCase() : '',
    // 製品は空のままにする。CSAF が無い以上どの製品かは分からず、
    // 自社の主力製品を充てると「分からない」が「FortiOS だと分かった」に化ける。
    // nwDecideNotification_ が空を見て「製品を特定できないため → 影響調査」に落とし、
    // 台帳の製品列は nwToRowArray_ が「不明」と表示する。
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
    verdict: NW_V_INVEST,
    // reasonPhrase に置く理由は nwExtractCiscoRowFallback_ の同じ箇所。
    reasonPhrase: 'CSAF を取得できず製品も版も特定できないため',
    selfVersion: '', fixVersion: '',
    feature: '', impactJa: '', howToCheck: ''
  };
}

function nwPushUnique_(arr, val) {
  if (val && arr.indexOf(val) === -1) arr.push(val);
}

function nwUniqueStrings_(arr) {
  const seen = {};
  const out = [];
  (arr || []).forEach(function (v) {
    const s = String(v || '').trim();
    if (s && !seen[s]) { seen[s] = true; out.push(s); }
  });
  return out;
}

// ============================================================
// バージョン比較（コードで実行・LLM 不使用）
// ============================================================

/** "7.4.5" → [7,4,5]。数値に解釈できない要素があれば null（＝比較不能）を返す。 */
function nwParseVersion_(s) {
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
function nwCompareVersion_(a, b) {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = (a[i] === undefined) ? 0 : a[i];
    const y = (b[i] === undefined) ? 0 : b[i];
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** known_affected の文字列から製品名の部分を取り除き、バージョン表記だけにする。 */
function nwStripProductPrefix_(entry, product) {
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
function nwMatchesSpec_(ver, body) {
  const b = String(body || '').trim();
  if (!b) return null;

  if (/^all versions$/i.test(b)) return true;

  let m = /^(\d+(?:\.\d+)*)\s+all versions$/i.exec(b);
  if (m) {
    const base = nwParseVersion_(m[1]);
    if (!base) return null;
    for (let i = 0; i < base.length; i++) {
      if ((ver[i] === undefined ? 0 : ver[i]) !== base[i]) return false;
    }
    return true;
  }

  m = /^>=\s*([^\s|]+)\s*\|\s*<=\s*([^\s|]+)$/.exec(b);
  if (m) {
    const lo = nwParseVersion_(m[1]), hi = nwParseVersion_(m[2]);
    if (!lo || !hi) return null;
    return nwCompareVersion_(ver, lo) >= 0 && nwCompareVersion_(ver, hi) <= 0;
  }

  m = /^([^\s]+)\s+and above$/i.exec(b);
  if (m) {
    const lo2 = nwParseVersion_(m[1]);
    if (!lo2) return null;
    return nwCompareVersion_(ver, lo2) >= 0;
  }

  m = /^([^\s]+)$/.exec(b);
  if (m) {
    const ex = nwParseVersion_(m[1]);
    if (!ex) return null;
    return nwCompareVersion_(ver, ex) === 0;
  }

  return null;  // 未知の表記。推測せず判定不能にする
}

/**
 * 自社バージョン（複数可）と影響バージョン一覧を突き合わせる。
 * 戻り値: { hit: bool, unknown: bool, matched: '一致した表記' }
 */
function nwJudgeVersions_(assetVersions, affectedEntries, product) {
  let unknown = false, matched = '';

  for (let i = 0; i < assetVersions.length; i++) {
    const ver = nwParseVersion_(assetVersions[i]);
    if (!ver) { unknown = true; continue; }

    for (let j = 0; j < affectedEntries.length; j++) {
      const body = nwStripProductPrefix_(affectedEntries[j], product);
      const r = nwMatchesSpec_(ver, body);
      if (r === true) return { hit: true, unknown: false, matched: affectedEntries[j] };
      if (r === null) unknown = true;
    }
  }
  return { hit: false, unknown: unknown, matched: matched };
}

// ============================================================
// 通知判定（コードで実行・LLM 不使用）
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
function nwJpRange_(entry, product) {
  const b = nwStripProductPrefix_(entry, product);
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
function nwBranchRange_(row, versions) {
  for (let i = 0; i < versions.length; i++) {
    const v = nwParseVersion_(versions[i]);
    if (!v || v.length < 2) continue;
    const branch = v.slice(0, 2).join('.');

    for (let j = 0; j < row.affected.length; j++) {
      const body = nwStripProductPrefix_(row.affected[j], row.product);
      const head = /^(?:>=\s*)?(\d+(?:\.\d+)+)/.exec(body);
      if (!head) continue;
      if (head[1].split('.').slice(0, 2).join('.') === branch) {
        return { branch: branch, range: nwJpRange_(row.affected[j], row.product) };
      }
    }
  }
  return null;
}

/** 製品名を突合用に正規化する。"FortiClient EMS" と "FortiClientEMS" を同じ扱いにする。 */
function nwNormProduct_(s) {
  return String(s || '').toLowerCase().replace(/[\s_-]/g, '');
}

function nwReadAssets_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(NW_SHEET_ASSET);
  if (!sh || sh.getLastRow() < 2) return [];

  // 見出しが v7 形式（先頭が「ベンダー」）でなければ止める。v6 形式の互換読みは
  // 2026-09-13 に外した。黙って別の解釈で読むと、判定の根拠が分からなくなる。
  const first = String(sh.getRange(1, 1).getValue() || '').trim();
  if (first !== NW_ASSET_COLS[0].label) {
    throw new Error('「' + NW_SHEET_ASSET + '」の見出しが想定と違います（1 列目が「' + first + '」）。' +
                    'README §2.4 の列順に直してください。');
  }

  const values = sh.getRange(2, 1, sh.getLastRow() - 1, NW_ASSET_COLS.length).getValues();
  return values.map(function (row) { return nwRowToRec_(NW_ASSET_COLS, row); })
    .filter(function (a) { return a.product || a.model; })
    .map(function (a) {
      return {
        vendor: String(a.vendor || '').trim(),
        category: String(a.category || '').trim(),
        product: String(a.product || '').trim(),
        model: String(a.model || '').trim(),
        version: String(a.version || '').trim(),
        count: a.count,
        toolTarget: String(a.toolTarget || 'はい').trim(),
        note: String(a.note || '').trim(),
        updatedAt: a.updatedAt || ''
      };
    });
}

function nwFortinetAssets_(assets) {
  return assets.filter(function (a) {
    if (a.toolTarget === 'いいえ') return false;
    const v = a.vendor || NW_VENDOR_FORTINET;
    return v === NW_VENDOR_FORTINET && a.product && a.product !== '—';
  });
}

function nwCiscoAssets_(assets) {
  return assets.filter(function (a) {
    if (a.toolTarget === 'いいえ') return false;
    return a.vendor === NW_VENDOR_CISCO;
  });
}

function nwAssetsForProduct_(assets, product) {
  const p = nwNormProduct_(product);
  if (!p) return [];
  return assets.filter(function (a) { return nwNormProduct_(a.product) === p; });
}

function nwInitDecisionFields_(row) {
  row.osStatus = row.osStatus || '';
  row.kev = row.kev || '';
  row.externalSurface = row.externalSurface || '';
  row.takeover = row.takeover || '';
  row.serviceStop = row.serviceStop || '';
  row.aiTechImpact = row.aiTechImpact || '';
  row.aiServiceStop = row.aiServiceStop || '';
  row.aiConfidence = row.aiConfidence || '';
  row.needsFortinetAi = false;
  row.needsVerdict = false;
  row.needsDisplayAi = false;
  row.needsCodeDisplay = false;
}

function nwKevLabel_(cve) {
  return nwIsKevListed_(cve) ? NW_KEV_YES : NW_KEV_NO;
}

/** AI 失敗時でも影響機能・確認方法・ユーザ影響を空にしない */
function nwIsFortinetFeatureVocab_(feature) {
  return NW_FORTINET_AI_FEATURES.indexOf(String(feature || '').trim()) !== -1;
}

/**
 * タイトル・要約・impact から Fortinet 統制語彙へ寄せる。
 * 当てはまらなければ「その他」（機能を特定できないので影響調査に回る）。
 */
function nwGuessFortinetFeature_(row) {
  const text = [row.feature, row.title, row.summary, row.impact].join(' ').toLowerCase();
  if (nwIsFortinetFeatureVocab_(row.feature)) return row.feature;
  const rules = [
    [/ssl[- ]?vpn|sslvpn/, 'SSL-VPN'],
    [/ipsec/, 'IPsec VPN'],
    [/web\s*filter|webfilter/, 'Webフィルタ'],
    [/ssl\s*inspect|deep\s*inspect/, 'SSLインスペクション'],
    [/\bips\b|intrusion\s*prevention/, 'IPSエンジン'],
    [/anti[- ]?virus|\bav\b|fortiguard/, 'アンチウイルスエンジン'],
    [/\bssh\b/, 'SSH'],
    // 単独の UI も拾う。Fortinet は管理画面の脆弱性を「UI DoS attack」のように
    // 題名へ書くことがあり、web.?ui にも \bgui\b にも当たらない。
    // 2026-09-06 実測: AI が 管理GUI を返した日は分類できたのに、返さなかった日は
    // ここで復元できず「その他 → 影響機能を特定できないため」に落ちた。
    // **同じアドバイザリの分類が日によって変わる**ので、保険側で決定的にする。
    [/web.?ui|fortigate ui|\bgui\b|\bui\b|management\s*(interface|console)|admin\s*portal/, '管理GUI'],
    [/resource\s*exhaust/, '管理GUI'],
    [/data\s*plane|dataplane|\bwad\b|kernel|buffer\s*over/, 'データプレーン'],
    [/captive\s*portal/, 'その他']
  ];
  for (let i = 0; i < rules.length; i++) {
    if (rules[i][0].test(text)) return rules[i][1];
  }
  return 'その他';
}

function nwApplyFallbackDisplayFields_(row) {
  if (row.vendor === NW_VENDOR_FORTINET) {
    if (!nwIsFortinetFeatureVocab_(row.feature) || row.feature === 'その他' || row.feature === '不明') {
      const guessed = nwGuessFortinetFeature_(row);
      if (guessed && guessed !== 'その他') row.feature = guessed;
      else if (!nwIsFortinetFeatureVocab_(row.feature)) row.feature = guessed;
    }
  } else {
    const fromTitle = nwNormalizeCiscoFeature_(row.title || '');
    if (nwIsJunkCiscoFeature_(row.feature)) {
      row.feature = fromTitle;
    } else {
      row.feature = nwNormalizeCiscoFeature_(row.feature || row.title || '');
    }
  }

  row.howToCheck = nwNormalizeHowToCheck_(row);
  if (!nwIsUsableCveSummary_(row.cveSummaryJa)) {
    row.cveSummaryJa = '';
  }
  row.impactJa = nwPreferImpactJa_(row);
}

function nwTruncateJa_(s, max) {
  const t = String(s || '').trim().replace(/\s+/g, ' ');
  if (!t) return '';
  return t.length > max ? t.slice(0, max) : t;
}

/** 英語タイトルコピーをやめ、アドバイザリ本文と CVSS から業務結果を引く */
function nwFallbackImpactJa_(row) {
  const parts = nwParseCvssCia_(row.vector);
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

  if (nwIsReloadDos_(row) || (parts && parts.A === 'H')) {
    return nwIsReloadDos_(row)
      ? '機器が再起動し、拠点の通信が途切れる恐れ'
      : '機器が停止し、拠点の通信が途切れる恐れ';
  }
  if (nwIsMgmtPlaneDos_(row) || (parts && parts.A === 'L')) {
    return '管理画面が応答しなくなり、運用に支障が出る恐れ';
  }

  const text = nwAdvisoryCorpus_(row).toLowerCase();
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

function nwAdvisoryCorpus_(r) {
  return [r.title, r.summary, r.impact, r.feature].join('\n');
}

function nwIsReloadDos_(r) {
  return /reload|reboot|unexpected(ly)? (reload|reboot)/i.test(nwAdvisoryCorpus_(r));
}

function nwIsResourceExhaustion_(r) {
  return /resource exhaustion|without limits or throttling|allocation of resources/i.test(nwAdvisoryCorpus_(r));
}

function nwIsMgmtPlaneDos_(r) {
  const f = String(r.feature || '');
  if (f === '管理GUI' || f === 'WebUI') return true;
  return /web ui|webui|fortigate ui|\bgui\b|management (interface|plane)/i.test(nwAdvisoryCorpus_(r))
    || nwIsResourceExhaustion_(r);
}

/** CVSS ベクターから C/I/A を取る。無ければ null */
function nwParseCvssCia_(vector) {
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

function nwNormalizeCiscoFeature_(raw) {
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
 * Cisco の影響機能の統制語彙。nwFeatureExposure_ が露出を引ける値だけを許す。
 * ここに無い値が入ると exposure が unknown になり、判定が
 * 「影響機能を特定できないため」に固定される。
 */
var NW_CISCO_FEATURE_VOCAB = {
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
 * nwFeatureExposure_ はそれらを unknown としか読めないので判定は動かないが、台帳を
 * 眺めたときに「影響機能を特定できていない行」が実際より少なく見える。
 * **判定は変わらないのに見え方だけ壊れる**ので、直したつもりになってしまう。
 *
 * Fortinet には nwIsFortinetFeatureVocab_ で同じ強制がある。ベンダーで差を付ける
 * 根拠が無いので揃える。
 */
function nwIsJunkCiscoFeature_(feature) {
  const s = String(feature || '').trim();
  if (!s || s === '不明') return true;
  return !NW_CISCO_FEATURE_VOCAB[s];
}

function nwLookupCheckSteps_(row) {
  if (row.vendor === NW_VENDOR_FORTINET) {
    const f = row.feature || 'その他';
    return NW_CHECK_STEPS_FORTINET[f] || NW_CHECK_STEPS_FORTINET['その他'];
  }
  const text = [row.feature, row.title].join(' ');
  for (let i = 0; i < NW_CHECK_STEPS_CISCO.length; i++) {
    if (NW_CHECK_STEPS_CISCO[i].re.test(text)) return NW_CHECK_STEPS_CISCO[i].text;
  }
  // 影響調査中に「臨時対応不要・定期更新枠」を出すと手がかりにならない
  if (row.verdict === NW_V_INVEST) return NW_CHECK_STEPS_CISCO_INVEST;
  return NW_CHECK_STEPS_CISCO_DEFAULT;
}

/**
 * CSAF が取れず製品を特定できなかった行の確認方法。
 *
 * 機器固有のコマンドを書かない。**まずアドバイザリ本体を開くのが最初の一歩**で、
 * 製品が分からないまま打つコマンドには意味がない。
 */
var NW_CHECK_STEPS_NO_CSAF = [
  '確認ポイント：アドバイザリ本体を開き、影響製品と影響範囲を確認する',
  'アクション：自社の保有製品に当たるかを判断し、当たるなら版を突き合わせる',
  '判断：当たらなければ対象外。当たるなら影響機能を特定して確認コマンドへ進む'
].join('\n');

function nwNormalizeHowToCheck_(row) {
  const raw = String(row.howToCheck || '').trim();

  // 製品を特定できていない行に、機器固有のコマンドを出させない。
  //
  // 実例（2026-09-06 の実運用）: CSAF が取れなかった FG-IR-22-059
  // （OpenSSL ライブラリの脆弱性）に、AI が「show vpn ssl settings」と書いた。
  // 判定根拠は「製品も版も特定できない」なのに、確認方法は特定できている前提に
  // なっていて矛盾する。打っても意味がないうえ、出力が無いと「影響なし」と
  // 誤解される。AI は RSS の説明文から推測できてしまうので、ここで止める。
  if (row.noCsaf || !String(row.product || '').trim()) return NW_CHECK_STEPS_NO_CSAF;

  // 版該否は nwDecideNotification_ 済み。対象行に「show version」を出さない。
  if (row.osStatus === '対象' && nwIsVersionRecheckHowTo_(raw)) {
    return nwLookupCheckSteps_(row);
  }
  if (row.verdict === NW_V_INVEST && nwIsRegularUpdateHowTo_(raw)) {
    return nwLookupCheckSteps_(row);
  }
  return nwIsActionableHowTo_(raw) ? raw : nwLookupCheckSteps_(row);
}

/** 「なし」向けの定期更新定型か */
function nwIsRegularUpdateHowTo_(text) {
  return /定期更新枠|臨時対応は不要|次回メンテで更新すれば足りる/i.test(String(text || ''));
}

/** 版の再確認を求める確認方法か */
function nwIsVersionRecheckHowTo_(text) {
  return /影響範囲内|稼働バージョン|show\s+version|get\s+system\s+status/i.test(String(text || ''));
}

/** 人が次の行動を取れる確認方法か（設定確認 or アクション提示） */
function nwIsActionableHowTo_(text) {
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
function nwStripCheckLabels_(text) {
  return String(text || '')
    .split('\n')
    .map(function (line) {
      return line.replace(/^\s*(?:確認ポイント|コマンド|アクション|判断)\s*[：:]\s*/, '').trim();
    })
    .filter(function (line) { return line; })
    .join('\n');
}

// ============================================================
// KEV カタログ
// ============================================================

/**
 * KEV カタログを取得し、成否と出典まで返す。NW と macOS の両方がこれを使う。
 *
 * **例外を投げない。**呼ぶ側が「取れなかった」と「掲載が無い」を区別できるようにするため。
 * 従来どおり例外で扱いたい経路には nwFetchKevCatalog_() を残してある。
 *
 * キャッシュキーを kev_catalog_v2 にしてある。**戻り値の形を変えたので必ず変えること。**
 * 旧キーのままだと貼り替え直後の最大 6 時間、旧形（素のマップ）が返って
 * .map が undefined になり、KEV が全件「なし」に落ちる。
 * 同じ事故は値を true で入れていた頃に一度起きている（nwKevVendor_ のコメント）。
 */
function kevCatalogWithStatus_() {
  if (kevLastStatus_) return kevLastStatus_;

  const cache = CacheService.getScriptCache();
  const cached = cache.get('kev_catalog_v2');
  if (cached) {
    try {
      const c = JSON.parse(cached);
      if (c && c.map) {
        kevLastStatus_ = { ok: true, map: c.map, source: c.source, fetchedAt: c.fetchedAt, error: '' };
        return kevLastStatus_;
      }
    } catch (e) { /* 再取得 */ }
  }

  const errors = [];
  const sources = [[KEV_FEED_URL, 'CISA'], [KEV_FEED_FALLBACK_URL, 'CISA_GitHubミラー']];
  for (let i = 0; i < sources.length; i++) {
    try {
      const res = UrlFetchApp.fetch(sources[i][0], { muteHttpExceptions: true });
      if (res.getResponseCode() !== 200) {
        throw new Error('HTTP ' + res.getResponseCode());
      }
      const body = JSON.parse(res.getContentText());
      if (!body || !Array.isArray(body.vulnerabilities)) throw new Error('vulnerabilities 配列が無い');

      const set = {};
      body.vulnerabilities.forEach(function (v) {
        // 値は true ではなく登録主体（vendorProject）。KEV の登録が別ベンダーの
        // 製品に対するものかを判定根拠に書くために要る（nwKevVendor_ 参照）。
        // 空文字は入れない。!!set[cve] で掲載を見ているので偽になってしまう。
        if (v.cveID) {
          set[String(v.cveID).toUpperCase()] = String(v.vendorProject || '').trim() || '登録元不明';
        }
      });

      const payload = { map: set, source: sources[i][1], fetchedAt: new Date().toISOString() };
      // product まで持つと 78KB になり、CacheService の 100KB 上限まで 470 件しか
      // 余裕が無くなる。vendorProject だけなら 47.6KB で、あと 1,800 件は入る
      // （2026-08-31 版 1,687 件で実測）。
      try { cache.put('kev_catalog_v2', JSON.stringify(payload), 21600); } catch (e) {
        Logger.log('KEV キャッシュ保存に失敗（取得自体は成功）: ' + e);
      }
      if (i > 0) Logger.log('KEV は代替経路 ' + sources[i][1] + ' から取得しました: ' + errors.join(' / '));
      kevLastStatus_ = { ok: true, map: set, source: sources[i][1], fetchedAt: payload.fetchedAt, error: '' };
      return kevLastStatus_;
    } catch (e) {
      errors.push(sources[i][1] + ': ' + e.message);
    }
  }

  Logger.log('KEV 取得失敗（全経路）: ' + errors.join(' / '));
  kevLastStatus_ = { ok: false, map: {}, source: '', fetchedAt: '', error: errors.join(' / ') };
  return kevLastStatus_;
}

/** 従来の呼び出し口。素のマップを返し、取れなければ投げる。外形は変えていない。 */
function nwFetchKevCatalog_() {
  const r = kevCatalogWithStatus_();
  if (!r.ok) throw new Error('KEV 取得失敗 ' + r.error);
  return r.map;
}

function nwIsKevListed_(cve) {
  if (!cve) return false;
  try {
    const set = nwFetchKevCatalog_();
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
function nwKevVendor_(cve) {
  if (!cve) return '';
  try {
    const v = nwFetchKevCatalog_()[String(cve).toUpperCase()];
    return (typeof v === 'string') ? v : '';
  } catch (e) {
    return '';
  }
}

// ============================================================
// OS 該当・ベンダー別判定
// ============================================================

function nwJudgeOsApplicability_(row, assets) {
  if (!row.product) {
    return { os: 'unknown', label: '不明', detail: '製品不明' };
  }
  const mine = nwAssetsForProduct_(assets, row.product);
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
  const res = (row.vendor === NW_VENDOR_CISCO)
    ? nwJudgeCiscoVersions_(versions, row.affected)
    : nwJudgeVersions_(versions, row.affected, row.product);
  if (res.hit) {
    if (row.vendor !== NW_VENDOR_CISCO) nwNarrowFixVersion_(row, assets);
    return { os: 'hit', label: '対象', detail: '' };
  }
  if (res.unknown) {
    return { os: 'unknown', label: '不明', detail: '版解釈不能' };
  }
  if (row.vendor === NW_VENDOR_CISCO) {
    const uniq = nwUniqueStrings_(versions);
    return { os: 'out', label: '対象外', detail: '自社版 ' + uniq.join(', ') + ' は影響対象外' };
  }
  const b = nwBranchRange_(row, versions);
  const detail = b
    ? b.branch + ' 系の影響は ' + b.range + ' まで'
    : '利用中の系列が影響対象外';
  return { os: 'out', label: '対象外', detail: detail };
}

/**
 * 影響機能が外部から到達できる面に出ているか。
 *
 * **いまは判定に使っていない。**結果は row.externalSurface に入るだけで、台帳にも
 * 処理済みにも Slack にも出ない。自社影響を決めているのは nwFeatureExposure_
 * （NW_FEATURE_ALWAYS_ON = 常時有効か、設定次第か）のほうで、社内ルールの条件と
 * 直接対応するのはそちら。「外面」は社内ルールにも設計書にも無い概念。
 *
 * 将来の判定条件の候補として残している。使うなら社内ルール側に基準を作るのが先。
 */
function nwIsOnExternalSurface_(feature) {
  const f = String(feature || '').trim();
  if (!f || f === '不明' || f === 'その他') return false;
  if (f === 'データプレーン') return true;
  if (f === 'SSL-VPN' && !NW_SSL_VPN_ENABLED) return false;
  const surface = {
    'IPsec VPN': true, 'SSL-VPN': true, '管理GUI': true, 'SSH': true,
    'アンチウイルスエンジン': true, 'IPSエンジン': true,
    'Webフィルタ': true, 'SSLインスペクション': true
  };
  return !!surface[f];
}

function nwNormalizeServiceStop_(v) {
  if (v === true || v === 'true' || v === 'はい') return 'はい';
  if (v === false || v === 'false' || v === 'いいえ') return 'いいえ';
  return '不明';
}

/**
 * 判定根拠は2行にする。
 * 1行目は構造化された値、2行目は理由と結論。
 * 同じ区切り文字で並べると、文章もフィールドとして読まれて頭に入らない。
 */
function nwBuildDecisionReason_(row) {
  const head = 'OS=' + (row.osStatus || '不明') + ' | KEV=' + (row.kev || NW_KEV_NO);
  const tail = (row.reasonPhrase || '判定材料が不足しているため')
             + '「' + (row.verdict || NW_V_INVEST) + '」';
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
function nwRuleGate_(row) {
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
 * NW_CHECK_STEPS_FORTINET / NW_CHECK_STEPS_CISCO のキーと対応させる。
 * 確認方法に「出力があれば対応が必要」と書くなら、判定は config でなければ嘘になる。
 */
var NW_FEATURE_CONFIG_DEPENDENT = {
  '管理GUI': true, 'SSH': true, 'IPsec VPN': true, 'SSL-VPN': true,
  'Webフィルタ': true, 'SSLインスペクション': true,
  'IPSエンジン': true, 'アンチウイルスエンジン': true,
  'WebUI': true, 'BEEP': true, 'XMCP Server': true, 'SNMP': true, 'SD-WAN': true
};

/**
 * 設定に関係なく常に有効な機能（社内ルール 条件5）。
 *
 * **ここに設定依存の機能を足さないこと。**この表に載る行だけが nwImpactSeverity_ の
 * 判定へ進み、そこでは A:H を「業務停止」と読んでいる。その読み方は
 * 「基盤が止まれば業務が止まる」という前提に立っているので、管理画面のように
 * 設定次第で止められる機能を足すと前提が崩れ、管理画面の DoS まで臨時更新に上がる
 * （nwImpactSeverity_ のコメント参照）。
 */
var NW_FEATURE_ALWAYS_ON = {
  'データプレーン': true, 'IOS XE 基盤': true
};

function nwFeatureExposure_(row) {
  const f = String(row.feature || '').trim();
  if (f === 'SSL-VPN' && !NW_SSL_VPN_ENABLED) return 'disabled';
  if (NW_FEATURE_ALWAYS_ON[f]) return 'always';
  if (NW_FEATURE_CONFIG_DEPENDENT[f]) return 'config';
  return 'unknown';
}

/**
 * 臨時更新条件4（悪用されると機器の制御を奪われるか業務停止に至る）の判定。詳細は設計書 §4.9。
 *
 * **一次情報は CVSS ベクターの C/I/A。**条件3 を nwRuleGate_ が同じベクターから読んでいるので、
 * 条件4も同じ構造化された値から読む（ベンダーが記述文に何を書くかに依存させない）。
 * マッピングは直下のコードのとおり。
 *
 * **C:H のみを「なし」にしない。**漏れるのが管理者の認証情報なら制御を奪われる入口に
 * なるが、CVSS は「何が漏れるか」を区別しないので機械には判断できない → infoleak。
 *
 * **A:H を「業務停止」と読んでよいのは、この判定に来る行が限られているから。**
 * CVSS の A:H は「影響を受けるコンポーネントの可用性が完全に失われる」で、
 * コンポーネント＝機器全体とは限らない（デーモン 1 本が落ちるだけでも付く）。
 * それでも丸めてよいのは、nwFinalizeVerdict_ がここへ来るのを exposure が always の行
 * （NW_FEATURE_ALWAYS_ON = データプレーン / IOS XE 基盤）だけに絞っているため。
 * 基盤が止まれば業務が止まる。管理画面の DoS は config なので手前で「影響調査」になる。
 *
 * **NW_FEATURE_ALWAYS_ON に設定依存の機能を足すと、この前提が崩れる。**
 * 管理画面の DoS まで臨時更新に上がるので、足すときはここも見直すこと。
 *
 * Scope は見ない（S:U でも基盤が止まれば業務は止まるので、絞ると見逃す方向に働く）。
 * A:L（性能低下）は業務停止に含めない。AC も見ない（社内ルールの条件3が AV/PR/UI の
 * 3 つだけで AC を含めていないため。2026-09-04 に現状維持で確認）。
 *
 * **ベクターを AI の出力より先に見る。**ベンダーが公開した構造化データより、記述文から
 * 推測した値（takeover / serviceStop）を優先する理由が無い。読めないときだけ AI と
 * 記述文へ落ちる（CVSS v4 は nwParseCvssCia_ が null を返すのでこの経路）。
 * 拾えなければ unknown（＝調査へ）。
 *
 * @return {'yes'|'infoleak'|'no'|'unknown'}
 */
function nwImpactSeverity_(row) {
  // ベクターが読めればそれが答え（理由は上の JSDoc）。
  const p = nwParseCvssCia_(row.vector);
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
function nwIsSevereImpact_(row) {
  return nwImpactSeverity_(row) === 'yes';
}

/**
 * 自社影響の確定。ベンダー差は nwFeatureExposure_ の語彙だけに閉じ込める。
 * AI の後に呼ぶこと（影響機能が決まっていないと判定できない）。
 *
 * ルールゲートは nwDecideNotification_ で先に当たっており、通常ここへ来る行は通過済み。
 * それでも同じ nwRuleGate_ を呼ぶのは、この関数単体で社内ルール全体を表現しておくため。
 * 判定の入口が2つあると、片方だけ直して食い違う。
 */
function nwFinalizeVerdict_(row, opts) {
  if (!opts || !opts.skipKev) {
    row.kev = nwKevLabel_(row.cve);
  }
  row.osStatus = row.osStatus || '対象';

  if (row.vendor === NW_VENDOR_FORTINET &&
      (!row.aiOk || !nwIsFortinetFeatureVocab_(row.feature) || row.aiConfidence === 'low')) {
    row.feature = nwGuessFortinetFeature_(row);
    if (!row.aiTechImpact) row.aiTechImpact = '不明';
  }

  row.takeover = row.aiTechImpact || '不明';
  row.serviceStop = nwNormalizeServiceStop_(row.aiServiceStop);
  row.externalSurface = nwIsOnExternalSurface_(row.feature) ? 'はい' : 'いいえ';

  const gate = nwRuleGate_(row);
  const exposure = nwFeatureExposure_(row);

  // KEV は件数が稀すぎて主軸にならないが、悪用実績があるものを
  // 「使っていないはず」で流すとルール全体の信頼性が崩れる。最低ラインを調査に固定する。
  if (row.kev === NW_KEV_YES) {
    // KEV の登録主体が、このアドバイザリのベンダーと違うことがある。
    // FG-IR-26-139 の CVE-2026-31431 は Fortinet の告知だが、KEV の登録は
    // Linux / Kernel で、FortiGate 上で悪用された実績ではない。
    // 判定は変えない（悪用実績を「使っていないはず」で流さない）が、
    // 根拠に由来を書かないと「悪用が確認されている」が言い過ぎになる。
    const src = nwKevVendor_(row.cve);
    const note = (src && src !== row.vendor) ? '（KEV登録: ' + src + '）' : '';
    if (exposure === 'always' && gate.pass && nwIsSevereImpact_(row)) {
      row.verdict = NW_V_ACT;
      row.reasonPhrase = '悪用が確認されており外部から到達するため' + note;
    } else {
      row.verdict = NW_V_INVEST;
      row.reasonPhrase = '悪用が確認されているため' + note;
    }
    row.reason = nwBuildDecisionReason_(row);
    return;
  }

  if (!gate.pass) {
    row.verdict = NW_V_NONE;
    row.reasonPhrase = gate.phrase;
    row.reason = nwBuildDecisionReason_(row);
    return;
  }

  if (exposure === 'disabled') {
    row.verdict = NW_V_NONE;
    row.reasonPhrase = row.feature + ' を自社で無効にしているため';
  } else if (exposure === 'config') {
    row.verdict = NW_V_INVEST;
    row.reasonPhrase = row.feature + ' の利用有無が設定次第のため';
  } else if (exposure === 'unknown') {
    row.verdict = NW_V_INVEST;
    row.reasonPhrase = '影響機能を特定できないため';
  } else {
    // 条件4はベクターの C/I/A で決める（nwImpactSeverity_）。
    // 「至らない」と言い切れるのはベクターが読めたときだけ。
    // 分からない行を「なし」にすると Slack からも消えて誰も気づけない。
    const sev = nwImpactSeverity_(row);
    if (sev === 'yes') {
      row.verdict = NW_V_ACT;
      row.reasonPhrase = '外部から無認証で' + row.feature +
                         'を悪用され、機器の制御を奪われるか業務停止に至るため';
    } else if (sev === 'infoleak') {
      row.verdict = NW_V_INVEST;
      row.reasonPhrase = '読み取られる情報の範囲を確認する必要があるため';
    } else if (sev === 'unknown') {
      row.verdict = NW_V_INVEST;
      row.reasonPhrase = '影響の種類を特定できず深刻度を判定できないため';
    } else {
      row.verdict = NW_V_NONE;
      row.reasonPhrase = '機器の制御を奪われることも業務停止に至ることもないため';
    }
  }
  row.reason = nwBuildDecisionReason_(row);
}

/**
 * 自社影響を決める。ツールのルールだけで判定する。
 *
 * 人の判断でここを上書きする仕組み（判断記録シート）は 2026-09-13 に外した。
 * 利用者が求めていない運用で、1 行も書かれないまま残っていたため。
 */
function nwDecideNotification_(row, assets) {
  nwDecideByRules_(row, assets);
}

/**
 * AI を呼ばずに結論が出る分をここで確定させる。
 *
 * 確定できるのは3種類。
 *   非保有・製品不明   資産シートだけで決まる
 *   版が影響範囲外     CSAF と資産シートの版比較だけで決まる
 *   ルールゲート落ち   CVSS ベクターだけで決まる（社内ルール §3 の待てる根拠）
 *
 * ゲート落ちを AI の前に置くのは、影響機能を知る必要が無いから。
 * `PR:H` の行の影響機能を分類しても結論は変わらないので、その分の API を使わない。
 * 残った行（外部から無認証で悪用できる行）だけ AI へ回し、nwFinalizeVerdict_ で確定する。
 *
 * ベンダーで分岐しない（Cisco も設定次第の機能を持つので同じ扱いにする）。
 */
function nwDecideByRules_(row, assets) {
  if (row._lockedVerdict) return;

  nwInitDecisionFields_(row);
  row.fixVersion = nwPickFixVersion_(row);

  if (!row.product) {
    row.verdict = NW_V_INVEST;
    row.osStatus = '不明';
    row.kev = nwKevLabel_(row.cve);
    // 行が理由を持っていればそれを使う。CSAF が取れなかった行にとっては
    // 「製品を特定できない」は結果であって理由ではない。
    row.reasonPhrase = row.reasonPhrase || '製品を特定できないため';
    row.needsDisplayAi = true;
    row.reason = nwBuildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  const mine = nwAssetsForProduct_(assets, row.product);
  if (!mine.length) {
    row.verdict = NW_V_NONE;
    row.osStatus = '対象外';
    row.kev = nwKevLabel_(row.cve);
    row.reasonPhrase = row.product + ' を自社で使用していないため';
    row.reason = nwBuildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  const os = nwJudgeOsApplicability_(row, assets);
  row.osStatus = os.label;

  if (os.os === 'out') {
    row.verdict = NW_V_NONE;
    row.kev = nwKevLabel_(row.cve);
    if (os.detail && /ため$/.test(os.detail)) {
      row.reasonPhrase = os.detail;
    } else {
      row.reasonPhrase = (os.detail || '影響対象外') + 'のため';
    }
    row.reason = nwBuildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  if (os.os === 'unknown') {
    row.verdict = NW_V_INVEST;
    row.kev = nwKevLabel_(row.cve);
    row.reasonPhrase = '自社利用バージョンを判定できないため';
    row.needsDisplayAi = true;
    row.reason = nwBuildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  // 版が影響範囲内。ここから社内ルールを当てる。
  row.kev = nwKevLabel_(row.cve);

  const gate = nwRuleGate_(row);
  if (!gate.pass) {
    // KEV 掲載は最低ラインを調査に固定する例外。ゲートで落とさない。
    if (row.kev === NW_KEV_YES) {
      row.verdict = NW_V_INVEST;
      row.reasonPhrase = '悪用が確認されているため';
      row.needsDisplayAi = true;
    } else {
      row.verdict = NW_V_NONE;
      row.reasonPhrase = gate.phrase;
      // 表示列はコードのフォールバックで埋める。AI は呼ばない。
      row.needsCodeDisplay = true;
    }
    row.reason = nwBuildDecisionReason_(row);
    row._lockedVerdict = true;
    return;
  }

  // 影響機能が決まらないと判定できないので AI へ回す。
  row.needsFortinetAi = (row.vendor === NW_VENDOR_FORTINET);
  row.needsVerdict = true;
  row.needsDisplayAi = true;
  row.verdict = NW_V_INVEST;
  row.reasonPhrase = '影響機能を確認中のため';
  row.reason = nwBuildDecisionReason_(row);
}

/**
 * 修正バージョンを、自社が使っている系列の行だけ抜き出す。
 * remediations の details は
 *   "FortiOS 7.6: Upgrade to 7.6.4 or above\nFortiOS 7.4: Upgrade to 7.4.9 or above\n..."
 * のように系列ごとに1行で並ぶ。全部を1セルに入れると読み手が自分の行を探すことになる。
 */
function nwPickFixVersion_(row) {
  const raw = String(row.fixesRaw || '').trim();
  if (!raw) return '';
  const lines = raw.split('\n').map(function (s) { return s.trim(); }).filter(function (s) { return s; });
  return lines.join('\n');
}

/** 自社バージョンが決まったあとに、該当系列の修正指示だけへ絞り込む。 */
function nwNarrowFixVersion_(row, assets) {
  const mine = nwAssetsForProduct_(assets, row.product);
  if (!mine.length || !row.fixesRaw) return;

  const branches = mine.map(function (a) {
    const v = nwParseVersion_(a.version);
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
function nwJpFix_(row) {
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
      const target = nwMigrateTarget_(row, branch);
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
function nwMigrateTarget_(row, branchLabel) {
  const cur = nwParseVersion_(String(branchLabel).replace(/^\S+\s*/, ''));
  if (!cur) return '';

  let best = null;
  String(row.fixesRaw || '').split('\n').forEach(function (line) {
    const m = /^(.+?)\s*:\s*(.+)$/.exec(line.trim());
    if (!m) return;
    const b = nwParseVersion_(m[1].replace(/^\S+\s*/, ''));
    const u = /Upgrade to\s+(?:upcoming\s+)?([\d.]+)\s+or above/i.exec(m[2]);
    if (!b || !u) return;
    if (nwCompareVersion_(b, cur) <= 0) return;               // 自社系列より上だけ
    const v = nwParseVersion_(u[1]);
    if (!v) return;
    if (!best || nwCompareVersion_(v, best.v) < 0) best = { v: v, s: u[1] };
  });
  return best ? best.s : '';
}

/**
 * 台帳と Slack に出す「公式推奨対応」。英語を残さない。プレーンテキストのみ
 * （リンクは付けない）。**空文字を返さないこと。**
 *
 * 以前は Fortinet で修正版が取れないと空を返していた。台帳の列が空欄になると
 * 入力漏れと区別が付かず（§4.1）、しかも Slack 側は nwSlackActionLine_ が
 * 「アドバイザリを確認」を補っていたので、同じ行が台帳と Slack で違って見えていた。
 *
 * Cisco:
 *   - 修正版（稀に CSAF にある）または回避策コマンドがあればそれを出す
 *   - どちらも無いとき（GAS では openVuln 不可）は「更新先はアドバイザリで確認」
 *   - 「回避策なし」は CSAF Workarounds の公式文 "There are no workarounds..." の訳
 */
function nwFormatOfficialAction_(row) {
  if (row.vendor !== NW_VENDOR_CISCO) {
    const fix = nwJpFix_(row);
    return fix ? nwJpFixEnglishFallback_(fix) : '更新先はアドバイザリで確認';
  }

  const lines = [];
  const vers = row.fixedVersions || [];
  if (vers.length) lines.push(vers[0] + ' 以上に更新が必要');

  const cmds = row.workaroundCmds || [];
  const hint = nwTruncateJa_(row.workaroundJa || '', 40);
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
function nwJpFixEnglishFallback_(text) {
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

function nwCountVerdicts_(rows) {
  const c = {};
  c[NW_V_ACT] = 0; c[NW_V_INVEST] = 0; c[NW_V_NONE] = 0;
  rows.forEach(function (r) { if (c[r.verdict] !== undefined) c[r.verdict]++; });
  return c;
}

// ============================================================
// AI による機能分類・確認方法（台帳表示列）
// ============================================================

function nwEnrichWithAI_(targets) {
  // 呼び出し元（nwFillLedgerDisplay_）が needsVerdict || needsDisplayAi で絞った
  // 空でない配列だけを渡す。ここで同じ条件をもう一度書かない。
  let ok = 0;

  for (let i = 0; i < targets.length; i += NW_AI_CHUNK_SIZE) {
    const chunk = targets.slice(i, i + NW_AI_CHUNK_SIZE);
    const label = (Math.floor(i / NW_AI_CHUNK_SIZE) + 1) + '回目(' + chunk.length + '件)';

    try {
      const prompt = nwBuildEnrichPrompt_(chunk);
      const text = (AI_PROVIDER === 'claude') ? callClaude_(prompt) : callGemini_(prompt);

      const s = text.indexOf('[');
      const e = text.lastIndexOf(']');
      if (s === -1 || e === -1) throw new Error('JSON配列が見つかりません: ' + text.slice(0, 200));

      const parsed = JSON.parse(text.slice(s, e + 1));
      const byKey = {};
      parsed.forEach(function (v) { byKey[v.key] = v; });

      chunk.forEach(function (r) {
        const v = byKey[nwRowKey_(r)];
        if (!v) {
          r.aiOk = false;
          return;
        }
        r.feature = v.affected_feature || '不明';
        r.aiTechImpact = v.technical_impact || '不明';
        r.aiServiceStop = v.service_stop;
        r.aiConfidence = v.confidence || '';
        r.impactJa = nwTruncateJa_(nwPickAiField_(v, ['ユーザ影響', 'user_impact', 'impact_ja']) || '', 50);
        r.cveSummaryJa = nwTruncateJa_(nwPickAiField_(v, ['内容要約', '脆弱性名和訳', 'cve_summary', 'summary_ja']) || '', 30);
        if (!r.cveSummaryJa) {
          Logger.log('AI 内容要約なし: ' + nwRowKey_(r));
        }
        r.howToCheck = v['確認方法'] || '';
        r.workaroundJa = nwTruncateJa_(v['回避策'] || '', 40);
        if (r.vendor === NW_VENDOR_CISCO) {
          r.feature = nwNormalizeCiscoFeature_(r.feature);
          r.aiOk = true;
        } else if (!nwIsFortinetFeatureVocab_(r.feature)) {
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
    if (i + NW_AI_CHUNK_SIZE < targets.length) Utilities.sleep(1000);
  }

  Logger.log('AI 生成: ' + AI_PROVIDER + ' / 成功 ' + ok + ' / 対象 ' + targets.length + ' 行');
  if (!ok) {
    Logger.log('AI が0件のため、Slackの内容は公式タイトルの日本語訳、影響・確認方法はコード側の文面になります。');
  }
}

function nwRowKey_(r) {
  return r.advisoryId + '|' + r.cve + '|' + r.product;
}

function nwPickAiField_(obj, names) {
  if (!obj) return '';
  for (let i = 0; i < names.length; i++) {
    const v = obj[names[i]];
    if (v !== undefined && v !== null && String(v).trim()) return String(v).trim();
  }
  return '';
}

function nwBuildEnrichPrompt_(rows) {
  const payload = rows.map(function (r) {
    return {
      key: nwRowKey_(r),
      ベンダー: r.vendor || NW_VENDOR_FORTINET,
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
    '  Fortinet: 次のいずれか1つ → ' + NW_FORTINET_AI_FEATURES.join(' / '),
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

function callGemini_(prompt, responseSchema) {
  const models = [GEMINI_MODEL].concat(GEMINI_MODEL_FALLBACKS || []);
  let lastErr = null;
  for (let i = 0; i < models.length; i++) {
    const model = models[i];
    try {
      const text = callGeminiModel_(model, prompt, responseSchema);
      if (i > 0) Logger.log('AI はフォールバックモデル ' + model + ' で生成しました');
      return text;
    } catch (e) {
      lastErr = e;
      if (!shouldFallbackGeminiModel_(e) || i === models.length - 1) throw e;
      Logger.log(model + ' が使えないため ' + models[i + 1] + ' に切り替えます: ' + e);
    }
  }
  throw lastErr;
}

/**
 * 次のモデルへ退避すべきエラーか。
 *
 * 1. 日次上限（本文に PerDay）。**503 は過負荷で別物なので退避しない**
 *    （退避すると枠の残る世代を無駄に消費する）
 * 2. モデル ID が無効・提供終了（404 / NOT_FOUND）。退避しないと AI 出力が全滅し、
 *    台帳の 3 列がコードのフォールバック文言だけになる
 */
function shouldFallbackGeminiModel_(err) {
  const msg = String(err && err.message ? err.message : err);
  if (/PerDay/i.test(msg)) return true;
  return /HTTP 404/.test(msg) || /NOT_FOUND/i.test(msg);
}

function callGeminiModel_(model, prompt, responseSchema) {
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
      // responseSchema は省略可。渡さなければ従来と同じ設定になるので、
      // 既存の呼び出し（nwEnrichWithAI_）の挙動は変わらない。
      generationConfig: responseSchema
        ? { responseMimeType: 'application/json', maxOutputTokens: 32768, responseSchema: responseSchema }
        : { responseMimeType: 'application/json', maxOutputTokens: 32768 }
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
// 台帳への記録
// ============================================================

/**
 * 既読のアドバイザリ ID を集める。
 *
 * 台帳ではなく処理済みシートから読む。台帳には自社製品の行しか無いため、
 * 台帳を既読の根拠にすると、他社製品だけのアドバイザリを毎回取り直してしまう。
 */
function nwGetKnownState_(vendor) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(NW_SHEET_STATE);
  const dates = {};
  const versions = {};
  if (!sh || sh.getLastRow() < 2) return { dates: dates, versions: versions };

  const values = sh.getRange(2, 1, sh.getLastRow() - 1, NW_STATE_COLS.length).getValues();

  values.forEach(function (row) {
    const r = nwRowToRec_(NW_STATE_COLS, row);
    const rowVendor = String(r.vendor).trim();
    if (vendor && rowVendor !== vendor) return;
    const id = String(r.advisoryId).trim();
    if (!id) return;
    dates[id] = nwYmd_(r.updatedAt);
    // r.csafVersion が数値 0 でも保持する。Fortinet の CSAF は tracking.version が
    // 常に "0" で、セルに書くと数値 0 になる。`|| ''` だと falsy で空文字に化け、
    // CSAF 側の "0" と一致せず毎回「改訂」と誤判定して再通知していた。
    versions[id] = r.csafVersion != null ? String(r.csafVersion).trim() : '';
  });
  return { dates: dates, versions: versions };
}

function nwVendorFromAdvisoryId_(advisoryId) {
  const id = String(advisoryId || '').trim();
  if (/^cisco-sa-/i.test(id)) return NW_VENDOR_CISCO;
  if (/^FG-IR-/i.test(id)) return NW_VENDOR_FORTINET;
  return '';
}

/**
 * 指定したアドバイザリの行を、台帳と処理済みシートから消す。
 * 改訂されたアドバイザリを入れ直す前に呼ぶ。
 */
function nwRemoveRowsFor_(vendor, advisoryIds) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const targets = {};
  advisoryIds.forEach(function (id) { targets[id] = true; });

  const specs = [
    { sh: ss.getSheetByName(NW_SHEET_LEDGER), col: nwCol_(NW_LEDGER_COLS, 'advisory'), width: NW_LEDGER_COLS.length, inferVendor: true },
    { sh: ss.getSheetByName(NW_SHEET_STATE), colVendor: nwCol_(NW_STATE_COLS, 'vendor'), col: nwCol_(NW_STATE_COLS, 'advisoryId'), width: NW_STATE_COLS.length }
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
        if (nwVendorFromAdvisoryId_(ids[i][0]) !== vendor) continue;
      } else {
        const rowVendor = String(vendors[i][0] || NW_VENDOR_FORTINET).trim();
        if (rowVendor !== vendor) continue;
      }
      if (targets[String(ids[i][0]).trim()]) { nwDeleteSheetRowSafe_(sh, i + 2); removed++; }
    }
    if (removed) Logger.log(sh.getName() + ' から古い ' + removed + ' 行を削除しました（改訂のため入れ直します）。');
  });
}

/**
 * 処理済みシートに残す自社判定。
 *
 * 台帳に載らなかった件は、載せなかった根拠がどこにも残らない。
 * 分母（公表 N 件）だけあっても「なぜ 44 件を対象外としたのか」を後から説明できないので、
 * 判定の結論だけをここに書き写す。判断そのものは nwDecideNotification_ が済ませたもので、
 * ここで新しい判断はしない。
 */
function nwOwnershipJudgement_(f, advisoryRows, assets) {
  // 値の先頭は必ず 対象 / 対象外 / 判定不能 にする。列を眺めたときに
  // 可否が最初の 2〜3 文字で読めないと、根拠として使えない。
  if (f && f.error) {
    return { label: '判定不能', reason: 'CSAF を取得できず判定できない' };
  }
  if (nwIsCiscoInformationalAdvisory_(f && f.csaf, f && f.item)) {
    return { label: NW_STATE_JUDGE_INFO, reason: '脆弱性ではなく公開一覧のお知らせ' };
  }

  const owned = (advisoryRows || []).filter(function (r) {
    return r.product && nwAssetsForProduct_(assets || [], r.product).length;
  });
  if (!owned.length) {
    return { label: '対象外-未保有', reason: '資産に該当する製品が無い' };
  }

  const hit = owned.filter(function (r) { return r.osStatus !== '対象外'; });
  if (hit.length) {
    // ここで reasonPhrase を使ってはいけない。版が影響範囲内だった行では
    // nwDecideNotification_ が社内ルールを当てて「悪用に管理者権限が必要なため」のような
    // 通知要否の理由で上書きしている。この列が答えるのは「なぜ対象と判定したか」であって
    // 「なぜ緊急でないか」ではない。後者は台帳の判定根拠が持っている。
    const self = String(hit[0].selfVersion || '').replace(/\n/g, ' / ').trim();
    return { label: '対象', reason: (self ? self + '｜' : '') + '影響範囲内' };
  }
  return { label: '対象外-OS影響外', reason: nwJudgeReasonText_(owned[0], '影響対象外') };
}

/**
 * 判定に使った数値をそのまま書き写す。
 *
 * 「対象外-OS影響外」とだけ書いても、後から人が正しさを確かめられない。
 * 自社の版と、影響範囲の解釈をここに残しておけば、アドバイザリを開き直さずに
 * 突き合わせができる。台帳に載らなかった行は台帳の判定根拠を参照できないため、
 * この列が唯一の記録になる。
 */
function nwJudgeReasonText_(row, fallback) {
  const self = String(row.selfVersion || '').replace(/\n/g, ' / ').trim();
  const phrase = String(row.reasonPhrase || '').replace(/のため$/, '').trim();
  const parts = [];
  if (self) parts.push(self);
  parts.push(phrase || fallback);
  return parts.join('｜');
}

function nwWriteState_(vendor, todo, rows, assets) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(NW_SHEET_STATE);
  if (!sh) {
    sh = ss.insertSheet(NW_SHEET_STATE);
    sh.appendRow(NW_STATE_HEADERS);
    sh.setFrozenRows(1);
  }

  const byAdvisory = {};
  rows.forEach(function (r) {
    const a = byAdvisory[r.advisoryId] ||
      (byAdvisory[r.advisoryId] = { products: [], initial: r.initialDate, rows: [] });
    nwPushUnique_(a.products, r.product);
    a.rows.push(r);
  });

  const labelCounts = {};
  const values = todo.map(function (f) {
    const item = f.item || f;
    const id = item.ir || item.id;
    const a = byAdvisory[id] || { products: [], initial: f.updatedAt || item.pubDate, rows: [] };
    const judgement = nwOwnershipJudgement_(f, a.rows, assets);
    // CSAF から製品名が取れていればそれを使う（自社保有と無関係に「何の製品か」を残す）。
    // 取れない場合だけ、台帳へ展開した行から拾った製品名に落とす。
    const products = (f.products && f.products.length) ? f.products : a.products;
    return nwRecToRow_(NW_STATE_COLS, {
      updatedAt: f.updatedAt || item.pubDate || '',
      initialDate: nwStateInitialDate_(f, a, item),
      vendor: vendor,
      cve: nwCsafCveList_(f.csaf).join(', '),
      title: nwStateTitle_(f, item),
      judgement: nwCountLabel_(labelCounts, judgement.label),
      reason: judgement.reason,
      products: products.join(', '),
      advisoryId: nwAdvisoryIdCell_(vendor, id, item),
      csafVersion: f.version || ''
    });
  });

  if (!values.length) return labelCounts;

  if (sh.getMaxColumns() < NW_STATE_COLS.length) {
    sh.insertColumnsAfter(sh.getMaxColumns(), NW_STATE_COLS.length - sh.getMaxColumns());
  }

  const startRow = sh.getLastRow() + 1;
  sh.getRange(startRow, 1, values.length, NW_STATE_COLS.length).setValues(values);
  sh.getRange(startRow, nwCol_(NW_STATE_COLS, 'updatedAt'), values.length, 2)
    .setNumberFormat('yyyy/mm/dd');
  Logger.log('処理済みシートに ' + values.length + ' 件のアドバイザリを記録しました。');

  nwSortState_(sh);
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
function nwSortState_(sh) {
  if (!sh || sh.getLastRow() < 3) return;

  const n = sh.getLastRow() - 1;
  const range = sh.getRange(2, 1, n, NW_STATE_HEADERS.length);
  const cUpd = nwCol_(NW_STATE_COLS, 'updatedAt') - 1;
  const cId = nwCol_(NW_STATE_COLS, 'advisoryId') - 1;

  const formulas = range.getFormulas();
  const values = range.getValues();
  for (let i = 0; i < values.length; i++) {
    if (formulas[i][cId]) values[i][cId] = formulas[i][cId];
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
function nwAdvisoryUrlFor_(vendor, advisoryId, item) {
  const fromFeed = String((item && item.link) || '').trim();
  if (fromFeed) return fromFeed;

  const id = String(advisoryId || '').trim();
  if (!id) return '';
  if (vendor === NW_VENDOR_CISCO) return nwCiscoHumanAdvisoryUrl_(id);
  if (/^FG-IR-/i.test(id)) return 'https://fortiguard.fortinet.com/psirt/' + id;
  return '';
}

/**
 * 処理済みの判定に使う値だけを、AI 生成の前に控えておく。
 *
 * 台帳を先に書くようにしたため、nwWriteState_ は nwFillLedgerDisplay_ の後に走る。
 * nwFillLedgerDisplay_ は reasonPhrase を通知判定の文言（「管理GUI の利用有無が
 * 設定次第のため」など）に書き換えるので、そのまま渡すと処理済みの判定根拠に
 * 「自社が対象か」ではなく「なぜ通知するか」が入り、列の意味が変わってしまう。
 */
function nwSnapshotJudgeRows_(rows) {
  return rows.map(function (r) {
    return {
      advisoryId: r.advisoryId, initialDate: r.initialDate, product: r.product,
      osStatus: r.osStatus, selfVersion: r.selfVersion, reasonPhrase: r.reasonPhrase
    };
  });
}

/** バッチごとの判定内訳を 1 実行分に足し込む。 */
function nwMergeCounts_(into, counts) {
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
function nwStateTitle_(f, item) {
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
function nwStateInitialDate_(f, a, item) {
  const t = ((((f || {}).csaf || {}).document || {}).tracking) || {};
  if (t.initial_release_date) {
    return nwCsafDate_(t.initial_release_date, a.initial || f.updatedAt || '');
  }
  return a.initial || f.updatedAt || (item && item.pubDate) || '';
}

/**
 * アドバイザリが持つ CVE を全部並べる。実測で最大 7 件。
 * 台帳は自社該当分しか持たないので、除外した件の CVE はここにしか残らない。
 * ニュースで見た CVE 番号から自社影響の有無を引けるようにするための列。
 */
function nwCsafCveList_(csaf) {
  const out = [];
  ((csaf || {}).vulnerabilities || []).forEach(function (v) {
    if (v && v.cve) nwPushUnique_(out, String(v.cve).trim());
  });
  return out;
}

/** アドバイザリID のセル。リンクを張れるときは数式にする（値は ID のまま）。 */
function nwAdvisoryIdCell_(vendor, id, item) {
  const url = nwAdvisoryUrlFor_(vendor, id, item);
  return url ? '=HYPERLINK("' + url + '","' + id + '")' : id;
}

/** 判定を数えながらそのまま返す。nwWriteState_ の中で 1 度だけ判定するための小道具。 */
function nwCountLabel_(counts, label) {
  counts[label] = (counts[label] || 0) + 1;
  return label;
}

/**
 * JPCERT/CC の注意喚起のうち、自社ベンダーに当たり、まだ知らせていないものを返す。
 *
 * 落ちても nwDaily() は止めない。JPCERT は補助の経路で、これが取れないことで
 * 本体の日次処理を落とすのは本末転倒。
 */
function nwNewJpcertAlerts_(assets) {
  try {
    const alerts = nwFetchJpcertAlerts_();
    const words = nwJpcertKeywords_(assets);
    const seen = nwJpcertSeenIds_();

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
function nwFetchJpcertAlerts_() {
  const res = UrlFetchApp.fetch(NW_JPCERT_RSS_URL, { muteHttpExceptions: true });
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
      date: nwParsePubDate_(it.getChildText('date', dc))
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
 * **社名だけで当てる。製品名まで絞ってはいけない。**4 年分の Fortinet / Cisco 系 6 件の
 * うち 3 件は題名に製品名が入っておらず、その中にこの経路を作るきっかけになった
 * at260019「Fortinet製品に関連する認証情報の漏えい」（FortiBleed）が含まれる。
 * 絞らないことで増えるハズレは 4 年で 2 件。落とすのは年 1 件の当たりで割に合わない。
 */
function nwJpcertKeywords_(assets) {
  const words = [];
  (assets || []).forEach(function (a) {
    if (a.toolTarget === 'いいえ') return;
    [a.vendor, a.product].forEach(function (v) {
      const w = String(v || '').trim().toLowerCase();
      if (w && w !== '—') nwPushUnique_(words, w);
    });
  });
  // 題名が製品ブランドで書かれることがある（「Fortinet製FortiGate」など）。
  ['fortigate', 'fortios', 'catalyst', 'ios xe', 'ios-xe'].forEach(function (w) {
    nwPushUnique_(words, w);
  });
  return words;
}

function nwJpcertSeenIds_() {
  const raw = PropertiesService.getScriptProperties().getProperty(NW_JPCERT_SEEN_PROP) || '';
  const map = {};
  raw.split(',').forEach(function (s) { const t = s.trim(); if (t) map[t] = true; });
  return map;
}

/**
 * 通知できた分だけ既読にする。送る前に印を付けると、Webhook が失効していた日の
 * 注意喚起が誰にも届かないまま消える。
 */
function nwMarkJpcertSeen_(alerts) {
  if (!alerts || !alerts.length) return;
  const seen = Object.keys(nwJpcertSeenIds_());
  alerts.forEach(function (a) { if (seen.indexOf(a.id) === -1) seen.push(a.id); });
  const keep = seen.slice(-NW_JPCERT_SEEN_MAX);
  PropertiesService.getScriptProperties().setProperty(NW_JPCERT_SEEN_PROP, keep.join(','));
  Logger.log('JPCERT 注意喚起 ' + alerts.length + ' 件を通知済みにしました。');
}

/**
 * 実行を 1 行残す。通知は増やさない。nwDaily() から 1 実行につき 1 回だけ呼ぶ。
 *
 * 記録に失敗しても本体は止めない。履歴のために日次処理を落とすのは本末転倒。
 */
function nwWriteRunLog_(errorText) {
  try {
    if (!nwRunStats_) return;

    const v = nwRunStats_.vendors;
    function sum(key) {
      return v.reduce(function (a, x) { return a + x[key]; }, 0);
    }
    function judged(label) {
      return v.reduce(function (a, x) { return a + (x.labels[label] || 0); }, 0);
    }

    // 内訳は「見るべきことがあった日」だけ書く。平常日（更新も失敗もエラーも無い日）は
    // 毎日同じ文字列が並ぶだけで読む価値がなく、空欄にしておけば
    // 「何か書いてある行＝見るべき行」として拾える。
    // JPCERT の注意喚起は出た日だけ書く。CVE の件数とは別枠なので数字に混ぜない。
    const jpNote = nwRunStats_.jpcert ? 'JPCERT注意喚起 ' + nwRunStats_.jpcert + ' 件' : '';

    // KEV が取れなかった日は必ず書く。取得失敗と「掲載なし」が同じ見た目になるため、
    // ここに出さないと判定が緩んだ日を後から見分けられない（README §4.15）。
    const kevNote = (kevLastStatus_ && !kevLastStatus_.ok)
      ? 'KEV照合不可（全経路失敗）' + (kevLastStatus_.error ? '：' + kevLastStatus_.error : '')
      : (kevLastStatus_ && kevLastStatus_.source && kevLastStatus_.source !== 'CISA'
          ? 'KEV出典：' + kevLastStatus_.source : '');

    // macOS モジュールは別トリガーで動くので、止まっても Slack が静かなだけで気づけない。
    // 見る場所を実行履歴 1 か所に保つため、ここに死活を出す。
    // macOS のファイルを貼っていない環境でも落ちないよう typeof で守る。
    const macosNote = (typeof macosHealthNote_ === 'function') ? macosHealthNote_() : '';

    const worthWriting = !!errorText || sum('processed') > 0 || sum('failed') > 0 ||
                         !!jpNote;

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
    let sh = ss.getSheetByName(NW_SHEET_RUNLOG);
    if (!sh) {
      sh = ss.insertSheet(NW_SHEET_RUNLOG);
      sh.appendRow(NW_RUNLOG_HEADERS);
      sh.setFrozenRows(1);
    } else {
      const cur = sh.getRange(1, 1, 1, Math.max(sh.getLastColumn(), 1)).getDisplayValues()[0];
      const same = cur.length === NW_RUNLOG_HEADERS.length &&
                   NW_RUNLOG_HEADERS.every(function (h, i) { return cur[i] === h; });
      if (!same) {
        // 列を減らしたときは右端の古い見出しを消す。残すと見出しだけ 11 列、
        // データは 9 列という状態になり、読む側が列を数え違える。
        if (sh.getLastColumn() > NW_RUNLOG_HEADERS.length) {
          sh.deleteColumns(NW_RUNLOG_HEADERS.length + 1, sh.getLastColumn() - NW_RUNLOG_HEADERS.length);
        }
        sh.getRange(1, 1, 1, NW_RUNLOG_HEADERS.length).setValues([NW_RUNLOG_HEADERS]);
        Logger.log('実行履歴の見出しを ' + NW_RUNLOG_HEADERS.length + ' 列に更新しました。');
      }
    }

    const row = sh.getLastRow() + 1;
    sh.getRange(row, 1, 1, NW_RUNLOG_COLS.length).setValues([nwRecToRow_(NW_RUNLOG_COLS, {
      ranAt: new Date(),
      result: result,
      checked: sum('rss'),
      // 差分なしは「確認したが前回から変わっていなかった」件数。
      // 差分ゼロの日は他が全部 0 になり、動いた形跡が読めなくなるため列に出す。
      unchanged: sum('rss') - sum('processed'),
      updated: sum('processed'),
      target: judged('対象'),
      // 「対象以外」は差し引きで出す。未保有だけを数えると、OS影響外・情報通知・
      // 判定不能がどの列にも現れず、更新あり ＝ 対象 ＋ 対象以外 が崩れる。
      //
      // 「対象外」ではなく「対象以外」と呼ぶ。この残差には判定ラベルの
      // 対象外-未保有 / 対象外-OS影響外 / 対象外-情報通知 に加えて、
      // 判定不能（CSAF が取れず判定できなかった件）も入る。
      // 判定できなかった件を「対象外」と名乗らせると、分からなかった事実が消える。
      // 内訳は備考の 判定[…] にそのまま出る。
      nonTarget: sum('processed') - judged('対象'),
      failed: sum('failed'),
      seconds: Math.round((Date.now() - nwRunStats_.startedAt) / 1000),
      aiCalls: aiRequestCount_ - nwRunStats_.aiAtStart,
      note: [errorText ? 'エラー: ' + errorText : '',
             worthWriting ? detail : '',
             jpNote, kevNote, macosNote].filter(function (t) { return t; }).join('  /  ')
    })]);
    sh.getRange(row, 1).setNumberFormat('yyyy/mm/dd hh:mm');
  } catch (e) {
    Logger.log('実行履歴の記録に失敗: ' + e);
  }
}

/** 処理済みシートの自社判定に書く値。情報通知は Cisco が同じ内容を個別アドバイザリで
 *  出し直す重複なので、脆弱性の公表件数として数えると水増しになる。記録は証跡として残す。 */
var NW_STATE_JUDGE_INFO = '対象外-情報通知';

function nwToRowArray_(r) {
  const advisoryCell = r.advisoryUrl
    ? '=HYPERLINK("' + r.advisoryUrl + '","' + r.advisoryId + '")'
    : r.advisoryId;

  const action = nwFormatOfficialAction_(r);
  const cvss = (r.cvss === '' || r.cvss === undefined) ? '' : String(r.cvss);

  // 列の並びは NW_LEDGER_COLS が決める。ここは key ごとの値を用意するだけ。
  return nwRecToRow_(NW_LEDGER_COLS, {
    pubDate: r.pubDate || '',
    verdict: r.verdict || '',
    product: r.product || '不明',
    cve: r.cve || '',
    cvss: cvss,
    kev: r.kev || '',
    title: nwShortTitle_(r.title),
    impactJa: r.impactJa || '',
    feature: r.feature || '',
    reason: r.reason || '',
    howToCheck: nwStripCheckLabels_(r.howToCheck),
    action: action,
    advisory: advisoryCell,
    vector: r.vector || ''
  });
}

/** 台帳向けにタイトルを短くする（英語の長い文書名を切る） */
function nwShortTitle_(s) {
  const t = String(s || '').trim().replace(/\s+/g, ' ');
  if (!t) return '';
  return t.length > 60 ? t.slice(0, 60) + '…' : t;
}

function nwWriteLedger_(rows) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(NW_SHEET_LEDGER);
  if (!sh) throw new Error('「' + NW_SHEET_LEDGER + '」シートがありません。nwSetup() を先に実行してください。');
  if (!rows.length) return;

  const values = rows.map(nwToRowArray_);
  const startRow = sh.getLastRow() + 1;
  sh.getRange(startRow, 1, values.length, NW_LEDGER_HEADERS.length).setValues(values);
  sh.getRange(startRow, nwCol_(NW_LEDGER_COLS, 'pubDate'), values.length, 1).setNumberFormat('yyyy/mm/dd');
  Logger.log('台帳に ' + values.length + ' 行を追記しました。');
}

/** あり（対応検討）→ あり（影響調査）→ なし の順、同じ判定なら公開日の新しい順に並べ替える。 */
function nwSortLedger_() {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(NW_SHEET_LEDGER);
  if (!sh || sh.getLastRow() < 3) return;

  const n = sh.getLastRow() - 1;
  const range = sh.getRange(2, 1, n, NW_LEDGER_HEADERS.length);
  const rank = {};
  rank[NW_V_ACT] = 0; rank[NW_V_INVEST] = 1; rank[NW_V_NONE] = 2;

  const cAdv = nwCol_(NW_LEDGER_COLS, 'advisory') - 1;
  const cVerdict = nwCol_(NW_LEDGER_COLS, 'verdict') - 1;
  const cDate = nwCol_(NW_LEDGER_COLS, 'pubDate') - 1;
  const formulas = range.getFormulas();
  const values = range.getValues();
  for (let i = 0; i < values.length; i++) {
    const f = formulas[i][cAdv];
    if (f) values[i][cAdv] = f;
  }

  values.sort(function (a, b) {
    const ra = rank[a[cVerdict]], rb = rank[b[cVerdict]];
    const va = (ra === undefined) ? 3 : ra, vb = (rb === undefined) ? 3 : rb;
    if (va !== vb) return va - vb;
    const da = a[cDate], db = b[cDate];
    if (da instanceof Date && db instanceof Date) return db - da;
    return 0;
  });

  range.setValues(values);
}

function nwFormatLedger_(sh) {
  sh.getRange(1, 1, 1, NW_LEDGER_HEADERS.length)
    .setFontWeight('bold')
    .setBackground('#f0f0f0');

  // 幅は列の key で引く。位置で並べると、列順を変えたときに黙ってずれる。
  const widths = {
    pubDate: 100, verdict: 90, product: 100, cve: 140, cvss: 70, kev: 55,
    title: 220, impactJa: 220, feature: 120, reason: 280,
    howToCheck: 320, action: 220, advisory: 150
  };
  NW_LEDGER_COLS.forEach(function (c, i) { sh.setColumnWidth(i + 1, widths[c.key] || 120); });

  // 「いつ・対応要否・どの機器・どれくらい危ないか」までを固定して、右へ読み進める。
  sh.setFrozenColumns(6);

  const all = sh.getRange(1, 1, sh.getMaxRows(), NW_LEDGER_HEADERS.length);
  all.setVerticalAlignment('top');
  all.setWrap(true);
}

// ============================================================
// Slack 通知（日次1通ダイジェスト）
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
 * 「なし」は件数のみ。画像添付はしない（Webhook のみ）。
 *
 * alerts は JPCERT の注意喚起。**判定を通っていない情報**なので CVE のカードとは混ぜず
 * 末尾に別枠で出す。該当 0 件でも注意喚起があれば送る（そうしないと消える）。
 *
 * @return {boolean} 実際に送ったか。呼び出し側が既読を進めてよいかの判断に使う。
 */
function nwNotifySlack_(rows, alerts) {
  const url = String(PropertiesService.getScriptProperties()
    .getProperty(SLACK_WEBHOOK_PROP) || '').trim();
  if (!url) {
    Logger.log(SLACK_WEBHOOK_PROP + ' が未設定です。Slack へは送りません。');
    return false;
  }

  const hits = rows
    .filter(function (r) { return r.verdict === NW_V_ACT || r.verdict === NW_V_INVEST; })
    .sort(nwSlackHitSort_);
  const notes = alerts || [];

  if (!hits.length && !notes.length && !NW_NOTIFY_WHEN_NO_HITS) {
    Logger.log('OS 更新の可能性がある新着なし。Slack 通知はスキップします。');
    return false;
  }

  const sheetUrl = SpreadsheetApp.getActiveSpreadsheet().getUrl();
  const shown = hits.slice(0, NW_SLACK_MAX_ITEMS);
  const payload = nwBuildSlackPayload_(shown, sheetUrl, hits, notes);

  const code = postSlack_(url, payload);
  Logger.log('Slack 通知を送信しました: ' +
             '全 ' + hits.length + ' 件のうち ' + shown.length + ' 件を表示' +
             (notes.length ? ' / JPCERT 注意喚起 ' + notes.length + ' 件' : ''));
  return code === 200;
}

/**
 * Slack へ送る。応答コードを見てログに残す。
 *
 * 以前は muteHttpExceptions のまま結果を捨てていた。Webhook だけ
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

function nwSlackHitSort_(a, b) {
  const da = nwSlackDeviceLabel_(a);
  const db = nwSlackDeviceLabel_(b);
  if (da !== db) return da === 'FortiGate' ? -1 : 1;
  return (Number(b.cvss) || 0) - (Number(a.cvss) || 0);
}

/**
 * ADS Manager 型:
 *   1行目: 新しい脆弱性が発表されました🔍
 *   2行目: FortiGate:1件 Cisco:2件
 */
function nwBuildSlackPayload_(shown, sheetUrl, all, alerts) {
  // サマリは表示分ではなく全件で数える。ここを shown で数えると、
  // 2 行目の内訳とカードの枚数が一致してしまい、切られた事実がどこにも出ない。
  // 読む人は 2 行目を「今日の該当件数」として読むので、そこが表示件数だと
  // 末尾の残り件数が何に対する残りなのか繋がらなくなる。
  const total = all || shown;
  const rest = total.length - shown.length;
  const summary = nwSlackDeviceSummary_(total);
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
    nwFormatSlackItemBlocks_(r).forEach(function (b) { blocks.push(b); });
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
      text: '<' + a.link + '|' + nwJpcertShortTitle_(a.title) + '>' } });
  });

  const foot = [];
  // 「は台帳」とは書かない。直下のリンクが台帳を指しているので重複する。
  // ここが担うのは「全部は出していない」という事実と、その分母だけ。
  if (rest > 0) foot.push('全 ' + total.length + ' 件のうち ' + shown.length + ' 件を表示');
  const links = ['<' + NW_SECURITY_NEXT_VULN_URL + '|Security NEXTで確認>'];
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
function nwJpcertShortTitle_(s) {
  const t = String(s || '').replace(/^注意喚起:\s*/, '').replace(/\s*\((公開|更新)\)\s*$/, '').trim();
  return t.length > 70 ? t.slice(0, 70) + '…' : t;
}

function nwSlackDeviceSummary_(rows) {
  const order = ['FortiGate', 'Cisco'];
  const m = {};
  rows.forEach(function (r) {
    const k = nwSlackDeviceLabel_(r);
    m[k] = (m[k] || 0) + 1;
  });
  const keys = order.filter(function (k) { return m[k]; }).concat(
    Object.keys(m).filter(function (k) { return order.indexOf(k) === -1; }).sort()
  );
  return keys.map(function (k) { return k + ':' + m[k] + '件'; }).join(' ');
}

function nwSlackDeviceLabel_(r) {
  if ((r.vendor || '') === NW_VENDOR_CISCO) return 'Cisco';
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
function nwFormatSlackItemBlocks_(r) {
  const band = nwSlackCvssBand_(r.cvss);
  const cve = nwSlackCveLink_(r) || '（CVEなし）';
  const cvss = (r.cvss === '' || r.cvss === undefined || r.cvss === null)
    ? 'CVSS — [' + band.label + ']'
    : 'CVSS ' + r.cvss + ' [' + band.label + ']';
  const head = [band.emoji + ' *' + cve + '*', cvss];
  const upd = nwSlackUpdatedLabel_(r);
  if (upd) head.push(upd);
  const lines = [
    head.join('  /  '),
    '機器：' + nwSlackDeviceLabel_(r),
    '内容：' + nwSlackContentsJa_(r),
    '影響：' + nwSlackImpactJa_(r),
    '推奨対応：' + nwSlackActionLine_(r)
  ];

  return [{
    type: 'section',
    text: { type: 'mrkdwn', text: lines.join('\n') }
  }];
}

/** アドバイザリの最終更新日。CVE 行の mm/dd更新 */
function nwSlackUpdatedLabel_(r) {
  const d = r.pubDate instanceof Date ? r.pubDate : (r.pubDate ? new Date(r.pubDate) : null);
  if (!d || isNaN(d.getTime())) return '';
  return Utilities.formatDate(d, 'Asia/Tokyo', 'MM/dd') + '更新';
}

function nwSlackActionLine_(r) {
  // nwFormatOfficialAction_ は空を返さないので、ここで補わない。
  // 補うと台帳（補わない側）と Slack で文言が食い違う。
  const first = String(nwFormatOfficialAction_(r) || '').split(/\n/)[0].trim();
  return first.length > 40 ? first.slice(0, 40) + '…' : first;
}

/** Slack の「内容」。AI の日本語要約。無ければ公式タイトルの日本語訳。 */
function nwSlackContentsJa_(r) {
  // AI の要約が無い/使えない日は、アドバイザリのタイトルをそのまま出す。
  // 以前は英語を正規表現で日本語へ組み直していたが、AI が動く日は 1 行も通らなかった。
  const ai = String(r.cveSummaryJa || '').trim();
  const text = nwIsUsableCveSummary_(ai) ? ai : String(r.title || '').trim();
  return text.length > 30 ? text.slice(0, 30) + '…' : text;
}

function nwIsUsableCveSummary_(s) {
  if (!s) return false;
  if (/認証なし.*機器が(応答停止|再起動)/.test(s)) return false;
  if (/^(サービス停止|遠隔コード実行|権限昇格|情報漏えい|脆弱性)$/.test(s)) return false;
  const letters = (s.match(/[A-Za-z]/g) || []).length;
  const ja = (s.match(/[\u3040-\u30ff\u4e00-\u9faf]/g) || []).length;
  if (ja === 0) return false;
  if (letters >= 8 && ja < 4) return false;
  return true;
}

/** Slack の「影響」。主語は機器。機能名は足さない。 */
function nwSlackImpactJa_(r) {
  const ja = String(r.impactJa || '').trim();
  const text = ja || nwFallbackImpactJa_(r);
  return text.length > 40 ? text.slice(0, 40) + '…' : text;
}

/** CVE 文字列を公式アドバイザリへリンク。無ければ ID だけ。 */
function nwSlackCveLink_(r) {
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
function nwSlackCvssBand_(score) {
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
 * 確認用ファイルの nwTestSlackBlocks() が呼ぶ（同一スコープなので本体側にあってよい）。
 */
function nwSampleSlackRows_() {
  return [
    {
      vendor: NW_VENDOR_FORTINET, verdict: NW_V_ACT, product: 'FortiOS',
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
      vendor: NW_VENDOR_CISCO, verdict: NW_V_INVEST, product: 'IOS-XE',
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
      vendor: NW_VENDOR_FORTINET, verdict: NW_V_INVEST, product: 'FortiOS',
      selfVersion: '7.4.11', cve: 'CVE-2026-0003', cvss: 6.5,
      advisoryUrl: 'https://fortiguard.fortinet.com/psirt/FG-IR-26-003',
      advisoryId: 'FG-IR-26-003', title: 'Information disclosure',
      impactJa: '管理情報や認証情報が外部に漏れる恐れ',
      pubDate: new Date('2026-08-20')
    }
  ];
}

