/**
 * 脆弱性ウォッチャー v7 — 動作確認用の関数だけを集めたファイル。
 *
 * 本体（fortinet_psirt_watcher_v7.gs）とは Apps Script のグローバルスコープを
 * 共有するので、本体の関数も定数もそのまま呼べる。ファイルの並び順は関係ない
 * （このファイルはトップレベルで const/let を宣言しない。宣言すると評価順に
 * 依存するようになり、並び順で壊れる）。
 *
 * ここに置くもの: ログを見て確かめるための関数。判定や取得の本体は置かない。
 * ここに置かないもの: メニューから呼ばれる sendSlackTest_ とその配下、および
 * それが使う sampleSlackRows_()。あれは動作確認ではなく運用の機能なので本体側にある。
 *
 * 分けた理由は本体を短くすること以上に、貼り替えの回数を減らすこと。
 * デプロイは GAS エディタへの手貼りで、確認用の関数はほとんど変わらない。
 * 分けておけば普段は本体だけを貼れば済む。
 *
 * 使い方は GAS実行手順_v7.md の「動作確認」を参照。
 */

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

/**
 * Webhook に送らず、組み立てた payload をログに出す（表示確認用）。
 */
function testSlackBlocks() {
  const payload = buildSlackPayload_(sampleSlackRows_(), 'https://example.com/ledger');
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
  Object.keys(SLACK_TARGETS).forEach(function (k) {
    const t = SLACK_TARGETS[k];
    Logger.log(t.prop + ' : ' + (p.getProperty(t.prop) ? 'OK' : '未設定') +
               '（' + t.label + '）');
  });
  const raw = p.getProperty('SLACK_TARGET');
  Logger.log('SLACK_TARGET : ' + (raw || '(未設定)') +
             ' → 運用宛先は ' + SLACK_TARGETS[operationalSlackTarget_()].label);
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
    // 2026-09-04: 条件4をベクターの C/I/A で判定するようにしたので、想定値を直した。
    // 元は NET（C:H/I:H/A:H）を「軽微」と名付けて V_NONE を期待していたが、
    // 読まれる・書き換えられる・止められるの全部が High なので軽微ではない。
    // 旧ロジックがベクターを見ずタイトルの英文だけで判定していたため通っていた。
    { name: '常時有効だが影響は部分的',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
      feature: 'データプレーン', tech: 'partial',
      title: 'Information disclosure', impact: 'Information disclosure', expect: V_NONE },
    // C:H だけの行は「なし」にしない。漏れるのが管理者の認証情報なら
    // 制御を奪われる入口になるが、CVSS は何が漏れるかを区別しない（社内ルール §条件4の読み方）。
    { name: '常時有効・情報漏えいのみ',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      feature: 'データプレーン', tech: 'partial',
      title: 'Information disclosure', impact: 'Information disclosure', expect: V_INVEST },
    // 書き換えられるだけでも条件4を満たす（制御を奪われる）。
    { name: '常時有効・改ざんのみ',
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
      feature: 'データプレーン', tech: 'partial',
      title: 'Improper input validation', impact: '', expect: V_ACT },

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

/**
 * JPCERT の注意喚起を取得し、どれが自社ベンダー該当になるか見る。
 * 既読は進めない（markJpcertSeen_ を呼ばない）ので何度でも実行できる。
 */
function testJpcertAlerts() {
  const alerts = fetchJpcertAlerts_();
  const assets = readAssets_();
  const words = jpcertKeywords_(assets);
  const seen = jpcertSeenIds_();

  Logger.log('注意喚起（/at/）: ' + alerts.length + ' 件');
  Logger.log('当てる語: ' + words.join(' / '));
  Logger.log('通知済み: ' + Object.keys(seen).length + ' 件');
  Logger.log('---');

  let hit = 0;
  alerts.forEach(function (a) {
    const t = a.title.toLowerCase();
    const match = words.some(function (w) { return t.indexOf(w) !== -1; });
    if (match) hit++;
    Logger.log([
      match ? '該当  ' : '対象外',
      seen[a.id] ? '通知済' : '未通知',
      a.id,
      ymd_(a.date),
      jpcertShortTitle_(a.title)
    ].join(' | '));
  });
  Logger.log('---');
  Logger.log('自社ベンダー該当: ' + hit + ' / ' + alerts.length + ' 件');
}
