/**
 * 週次チーム進捗レポート
 * JIRA REST API → 集計 → HTMLメール（Gmail MailApp）
 *
 * ── セットアップ ──────────────────────────────────
 * GAS エディタ > プロジェクトの設定 > スクリプトプロパティ に以下を登録
 *
 * JIRA_BASE_URL      例: https://yourcompany.atlassian.net
 * JIRA_EMAIL         JIRAログイン用メールアドレス
 * JIRA_API_TOKEN     https://id.atlassian.com/manage-profile/security/api-tokens で発行
 * JIRA_PROJECT_KEY   プロジェクトキー 例: PROJ
 * TEAM_ACCOUNT_IDS   チームメンバーの accountId をカンマ区切り
 *                    ※ accountId の確認方法: JIRAプロフィールURLの末尾、または
 *                       /rest/api/3/user/search?query=名前 で取得
 * STATUS_IN_PROGRESS 進行中に相当するステータス名 例: In Progress,進行中
 * STATUS_TODO        未対応に相当するステータス名 例: To Do,未対応,Backlog
 * STATUS_DONE        完了に相当するステータス名   例: Done,完了,Closed
 * REPORT_TO_EMAIL    レポートの送信先メールアドレス（自分のGmail）
 * SPREADSHEET_ID     データ保存先スプレッドシートのID（任意）
 *                    ※ スプレッドシートのURLの /d/【ここ】/edit の部分
 *
 * ── トリガー設定 ──────────────────────────────────
 * runWeeklyReport を「時間ベース > 毎週 > 月曜日 > 午前9時〜10時」で登録
 * ──────────────────────────────────────────────────
 */

// ─── エントリポイント ────────────────────────────────────────────

function runWeeklyReport() {
  const cfg = getConfig_();
  const issues = fetchAllIssues_(cfg);
  const summary = buildSummary_(issues, cfg);
  const sheetUrls = cfg.spreadsheetId ? writeSpreadsheet_(cfg, issues, summary) : {};
  const html = buildEmailHtml_(summary, cfg, sheetUrls);
  sendReport_(cfg, summary, html);
}

// ─── 設定読み込み ────────────────────────────────────────────────

function getConfig_() {
  const p = PropertiesService.getScriptProperties();
  const required = [
    'JIRA_BASE_URL',
    'JIRA_EMAIL',
    'JIRA_API_TOKEN',
    'JIRA_PROJECT_KEY',
    'REPORT_TO_EMAIL',
  ];
  required.forEach(function(k) {
    if (!p.getProperty(k)) throw new Error('スクリプトプロパティが未設定: ' + k);
  });

  const cfg = {
    jiraBase:       p.getProperty('JIRA_BASE_URL').replace(/\/$/, ''),
    jiraEmail:      p.getProperty('JIRA_EMAIL'),
    jiraToken:      p.getProperty('JIRA_API_TOKEN'),
    projectKey:     p.getProperty('JIRA_PROJECT_KEY'),
    teamIds:        splitCsv_(p.getProperty('TEAM_ACCOUNT_IDS')),
    statusProgress: splitCsv_(p.getProperty('STATUS_IN_PROGRESS')),
    statusTodo:     splitCsv_(p.getProperty('STATUS_TODO')),
    statusDone:     splitCsv_(p.getProperty('STATUS_DONE')),
    reportTo:       p.getProperty('REPORT_TO_EMAIL'),
    spreadsheetId:  p.getProperty('SPREADSHEET_ID') || '',
  };

  if (!cfg.teamIds.length)        console.warn('TEAM_ACCOUNT_IDS が空です。メンバー別集計は空になります。');
  if (!cfg.statusProgress.length) console.warn('STATUS_IN_PROGRESS が空です。進行中の件数は0になります。');
  if (!cfg.statusTodo.length)     console.warn('STATUS_TODO が空です。未対応の件数は0になります。');
  if (!cfg.statusDone.length)     console.warn('STATUS_DONE が空です。完了タスクが集計されません。');

  return cfg;
}

function splitCsv_(s) {
  if (!s) return [];
  return s.split(',').map(function(x) { return x.trim(); }).filter(Boolean);
}

// ─── JIRA データ取得（ページング＋リトライ） ─────────────────────────

function fetchAllIssues_(cfg) {
  const jql = 'project = "' + cfg.projectKey + '" ORDER BY created DESC';
  const fields = 'summary,status,assignee,duedate,resolutiondate,updated,created';
  const max = 100;
  const all = [];
  let nextPageToken = null;

  while (true) {
    let url =
      cfg.jiraBase + '/rest/api/3/search/jql' +
      '?jql=' + encodeURIComponent(jql) +
      '&fields=' + encodeURIComponent(fields) +
      '&maxResults=' + max;

    if (nextPageToken) url += '&nextPageToken=' + encodeURIComponent(nextPageToken);

    const res = jiraGet_(cfg, url);
    const batch = res.issues || [];
    all.push.apply(all, batch);

    if (res.isLast || !res.nextPageToken || !batch.length) break;

    nextPageToken = res.nextPageToken;

    if (all.length > 3000) {
      throw new Error(
        'イシューが10,000件を超えています（取得済み: ' + all.length + '件）。' +
        'JQLで対象範囲を絞り込んでください。'
      );
    }
  }

  console.log('取得完了: ' + all.length + '件');
  return all;
}

function jiraGet_(cfg, url, attempt) {
  attempt = attempt || 0;
  const token = Utilities.base64Encode(cfg.jiraEmail + ':' + cfg.jiraToken);
  const resp = UrlFetchApp.fetch(url, {
    method: 'get',
    headers: { Authorization: 'Basic ' + token, Accept: 'application/json' },
    muteHttpExceptions: true,
  });
  const code = resp.getResponseCode();

  // 429（レート制限）・5xx はリトライ（最大4回、指数バックオフ）
  if ((code === 429 || (code >= 500 && code < 600)) && attempt < 4) {
    Utilities.sleep(Math.pow(2, attempt) * 1000);
    return jiraGet_(cfg, url, attempt + 1);
  }
  if (code < 200 || code >= 300) {
    throw new Error('JIRA API エラー ' + code + ': ' + resp.getContentText());
  }
  return JSON.parse(resp.getContentText());
}

// ─── 集計 ────────────────────────────────────────────────────────

function buildSummary_(issues, cfg) {
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  const teamSet = {};
  cfg.teamIds.forEach(function(id) { teamSet[id] = true; });

  let activeProgress = 0;
  let staleProgress = 0;
  let todo = 0;
  let unassigned = 0;
  const doneThisWeek = [];
  const activeProgressList = [];
  const newIssuesList = [];
  const overdue = [];
  const byMember = {};

  issues.forEach(function(issue) {
    const f = issue.fields || {};
    const statusName = (f.status && f.status.name) || '';
    const assignee = f.assignee;
    const aid = assignee ? assignee.accountId : null;
    const displayName = assignee ? (assignee.displayName || assignee.name || '（不明）') : '（未割当）';
    const tz = Session.getScriptTimeZone();

    if (!assignee) unassigned++;

    const created = f.created ? new Date(f.created) : null;
    const isDone = cfg.statusDone.indexOf(statusName) >= 0;

    // 今週新規（完了済みも含む）
    if (created && created >= weekAgo) {
      newIssuesList.push({
        key:     issue.key,
        summary: f.summary || '（タイトルなし）',
        url:     cfg.jiraBase + '/browse/' + issue.key,
        name:    displayName,
        status:  statusName,
        created: Utilities.formatDate(created, tz, 'M/d'),
      });
    }

    if (isDone) {
      const rd = f.resolutiondate ? new Date(f.resolutiondate) : null;
      if (rd && rd >= weekAgo) {
        doneThisWeek.push({
          key:     issue.key,
          summary: f.summary || '（タイトルなし）',
          url:     cfg.jiraBase + '/browse/' + issue.key,
          name:    displayName,
        });
      }
      return;
    }

    const isProgress = cfg.statusProgress.indexOf(statusName) >= 0;
    const isNewThisWeek = created && created >= weekAgo;
    if (isProgress) {
      const upd = f.updated ? new Date(f.updated) : null;
      if (upd && upd >= weekAgo && !isNewThisWeek) {
        // 今週新規は除外（新規セクションで表示・カウント済み）
        activeProgress++;
        activeProgressList.push({
          key:     issue.key,
          summary: f.summary || '（タイトルなし）',
          url:     cfg.jiraBase + '/browse/' + issue.key,
          name:    displayName,
          updated: Utilities.formatDate(upd, tz, 'M/d HH:mm'),
        });
      } else if (!upd || upd < weekAgo) {
        staleProgress++;
      }
    } else if (cfg.statusTodo.indexOf(statusName) >= 0) {
      todo++;
    }

    if (f.duedate) {
      const due = new Date(f.duedate + 'T23:59:59');
      if (due < now) {
        overdue.push({
          key:     issue.key,
          summary: f.summary || '（タイトルなし）',
          url:     cfg.jiraBase + '/browse/' + issue.key,
          due:     f.duedate,
          name:    displayName,
        });
      }
    }

    if (aid && teamSet[aid]) {
      byMember[displayName] = (byMember[displayName] || 0) + 1;
    }
  });

  const tz = Session.getScriptTimeZone();
  return {
    dateJa:        Utilities.formatDate(now, tz, 'yyyy年M月d日（E）'),
    dateShort:     Utilities.formatDate(now, tz, 'yyyy/M/d（E）'),
    counts: {
      doneWeek:       doneThisWeek.length,
      activeProgress: activeProgress,
      staleProgress:  staleProgress,
      newThisWeek:    newIssuesList.length,
      todo:           todo,
      overdue:        overdue.length,
      unassigned:     unassigned,
    },
    unassignedAlert:     unassigned >= 5,
    doneThisWeek:        doneThisWeek,
    activeProgressList:  activeProgressList,
    newIssuesList:       newIssuesList,
    overdue:             overdue,
    byMember:            byMember,
    jiraBase:            cfg.jiraBase,
    projectKey:          cfg.projectKey,
    statusDoneJql:       cfg.statusDone.map(function(s) { return '"' + s + '"'; }).join(','),
    statusProgressJql:   cfg.statusProgress.map(function(s) { return '"' + s + '"'; }).join(','),
    boardUrl:            cfg.jiraBase + '/jira/software/projects/' + cfg.projectKey + '/list',
  };
}

// ─── HTML メール生成（インラインスタイル・参照デザイン準拠） ──────────

var MEMBER_COLORS = [
  { bg: '#bfdbfe', text: '#1d4ed8', bar: '#3b82f6' },
  { bg: '#bbf7d0', text: '#15803d', bar: '#22c55e' },
  { bg: '#e9d5ff', text: '#7e22ce', bar: '#a855f7' },
  { bg: '#fde68a', text: '#b45309', bar: '#f59e0b' },
  { bg: '#fecdd3', text: '#be185d', bar: '#f43f5e' },
];

function buildEmailHtml_(summary, cfg, sheetUrls) {
  sheetUrls = sheetUrls || {};
  var c = summary.counts;
  var maxMember = Math.max.apply(null, Object.values(summary.byMember).concat([1]));

  // ── セクション：アラートバー（期限切れ or 未割り当てが多い場合） ──
  var alertBar = '';
  var alerts = [];
  var linkStyle = 'color:#b91c1c;text-decoration:none;';
  var proj = '"' + summary.projectKey + '"';
  if (c.overdue > 0) {
    var overdueJql = 'project = ' + proj + ' AND duedate < now() AND statusCategory != Done ORDER BY duedate ASC';
    alerts.push('<a href="' + h_(summary.jiraBase + '/issues/jql?jql=' + encodeURIComponent(overdueJql)) + '" style="' + linkStyle + '">⏰ 期限切れ <b>' + c.overdue + '件</b></a>');
  }
  if (summary.unassignedAlert) {
    var unassignedJql = 'project = ' + proj + ' AND assignee is EMPTY AND statusCategory != Done ORDER BY created DESC';
    alerts.push('<a href="' + h_(summary.jiraBase + '/issues/jql?jql=' + encodeURIComponent(unassignedJql)) + '" style="' + linkStyle + '">👤 未割り当て <b>' + c.unassigned + '件</b></a>');
  }
  if (alerts.length) {
    alertBar =
      '<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:10px 12px;' +
      'font-size:12px;color:#b91c1c;margin-bottom:10px;">' +
      alerts.join('　　') +
      '</div>';
  }

  // ── セクション：サマリ5カード ──
  var summaryGrid =
    '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:separate;border-spacing:4px 0;">' +
    '<tr>' +
    tdCard('#f0fdf4', '#15803d', '#16a34a', c.doneWeek,       '完了') +
    tdCard('#f5f3ff', '#6d28d9', '#7c3aed', c.newThisWeek,    '新規') +
    tdCard('#eff6ff', '#1d4ed8', '#2563eb', c.activeProgress, '更新あり') +
    tdCard('#fefce8', '#92400e', '#d97706', c.staleProgress,  '動きなし') +
    '</tr></table>';

  // ── セクション：JIRAボードリンク ──
  var boardLink =
    '<div style="text-align:right;margin:6px 0 2px;">' +
    '<a href="' + summary.boardUrl + '" style="font-size:11px;color:#3b82f6;text-decoration:underline;">' +
    'JIRAボード全体を確認する →</a></div>';


  // ── JIRA JQL リンク生成 ──
  function jiraJqlUrl_(jql) {
    return summary.jiraBase + '/issues/jql?jql=' + encodeURIComponent(jql);
  }
  var proj = '"' + summary.projectKey + '"';
  var doneJql    = 'project = ' + proj + ' AND status in (' + summary.statusDoneJql + ') AND resolutiondate >= -7d ORDER BY resolutiondate DESC';
  var activeJql  = 'project = ' + proj + ' AND status in (' + summary.statusProgressJql + ') AND updated >= -7d ORDER BY updated DESC';
  var newJql     = 'project = ' + proj + ' AND created >= -7d ORDER BY created DESC';

  // ── セクション①：今週の完了 ──
  var doneRows = summary.doneThisWeek.slice(0, 3).map(function(d) {
    return taskRow_(d.summary, d.url, '担当: ' + h_(d.name));
  });
  var doneMore = summary.doneThisWeek.length > 3
    ? moreRow_(summary.doneThisWeek.length - 5, jiraJqlUrl_(doneJql))
    : jiraLinkRow_(jiraJqlUrl_(doneJql));
  var doneSection = buildSection_(
    '#f0fdf4', '#bbf7d0', '#dcfce7', '#86efac',
    '#15803d', '#16a34a',
    '✅ 今週の完了', c.doneWeek + '件',
    doneRows, doneMore
  );

  // ── セクション②：今週の新規 ──
  var newRows = summary.newIssuesList.slice(0, 3).map(function(d) {
    return taskRow_(d.summary, d.url, d.created + '追加　担当: ' + h_(d.name));
  });
  var newMore = summary.newIssuesList.length > 3
    ? moreRow_(summary.newIssuesList.length - 5, jiraJqlUrl_(newJql))
    : jiraLinkRow_(jiraJqlUrl_(newJql));
  var newSection = buildSection_(
    '#f5f3ff', '#ddd6fe', '#ede9fe', '#c4b5fd',
    '#6d28d9', '#7c3aed',
    '🆕 今週の新規', summary.newIssuesList.length + '件',
    newRows, newMore
  );

  // ── セクション③：進行中・更新あり ──
  var activeRows = summary.activeProgressList.slice(0, 3).map(function(d) {
    return taskRow_(d.summary, d.url, d.updated + '　担当: ' + h_(d.name));
  });
  var activeMore = summary.activeProgressList.length > 3
    ? moreRow_(summary.activeProgressList.length - 5, jiraJqlUrl_(activeJql))
    : jiraLinkRow_(jiraJqlUrl_(activeJql));
  var activeSection = buildSection_(
    '#eff6ff', '#bfdbfe', '#dbeafe', '#93c5fd',
    '#1d4ed8', '#2563eb',
    '🔄 進行中・更新あり', c.activeProgress + '件',
    activeRows, activeMore
  );

  // ── セクション：メンバー別所持タスク ──
  var memberRows = Object.keys(summary.byMember)
    .sort(function(a, b) { return summary.byMember[b] - summary.byMember[a]; })
    .map(function(name, i) {
      var col   = MEMBER_COLORS[i % MEMBER_COLORS.length];
      var cnt   = summary.byMember[name];
      var pct   = Math.round(cnt / maxMember * 100);
      var initial = name.charAt(0);
      return (
        '<tr><td style="padding:6px 12px;border-top:1px solid #f1f5f9;">' +
        '<table width="100%" cellpadding="0" cellspacing="0"><tr>' +
        '<td style="width:24px;vertical-align:middle;">' +
        '<div style="width:24px;height:24px;border-radius:50%;background:' + col.bg + ';' +
        'display:flex;align-items:center;justify-content:center;' +
        'font-size:11px;font-weight:600;color:' + col.text + ';text-align:center;line-height:24px;">' +
        h_(initial) + '</div></td>' +
        '<td style="padding-left:8px;vertical-align:middle;">' +
        '<table width="100%" cellpadding="0" cellspacing="0">' +
        '<tr><td style="font-size:11px;color:#334155;">' + h_(name) + '</td>' +
        '<td style="text-align:right;font-size:11px;font-weight:600;color:#1e293b;">' + cnt + ' 件</td></tr>' +
        '<tr><td colspan="2" style="padding-top:3px;">' +
        '<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;border-radius:4px;height:6px;">' +
        '<tr><td style="width:' + pct + '%;background:' + col.bar + ';border-radius:4px;height:6px;"></td>' +
        '<td></td></tr></table></td></tr>' +
        '</table></td></tr></table></td></tr>'
      );
    }).join('');
  var memberSection =
    '<div style="border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;margin-bottom:10px;">' +
    '<div style="display:flex;align-items:center;padding:8px 12px;background:#f8fafc;border-bottom:1px solid #f1f5f9;">' +
    '<span style="font-size:11px;font-weight:600;color:#334155;">👥 メンバー別 所持タスク数</span>' +
    '</div>' +
    '<table width="100%" cellpadding="0" cellspacing="0">' + memberRows + '</table>' +
    '</div>';

  // ── フッター ──
  var footer =
    '<div style="display:flex;justify-content:space-between;padding-top:4px;">' +
    '<span style="font-size:11px;color:#94a3b8;">毎週月曜 AM9:00 自動生成</span>' +
    '<span style="font-size:11px;color:#94a3b8;">Powered by JIRA + GAS</span>' +
    '</div>';

  // ── 組み立て ──
  return (
    '<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1.0">' +
    '<title>タスレポ</title></head>' +
    '<body style="margin:0;padding:16px;background:#ffffff;' +
    'font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',\'Hiragino Sans\',\'Yu Gothic\',sans-serif;">' +
    '<div style="max-width:420px;margin:0 auto;">' +

    // ヘッダー
    '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">' +
    '<div style="display:flex;align-items:center;gap:8px;">' +
    '<div style="width:32px;height:32px;border-radius:8px;background:#2563eb;' +
    'display:flex;align-items:center;justify-content:center;">' +
    '<svg width="16" height="16" fill="none" stroke="#fff" viewBox="0 0 24 24" stroke-width="2">' +
    '<path stroke-linecap="round" stroke-linejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>' +
    '</svg></div>' +
    '<div><div style="font-size:15px;font-weight:600;color:#0f172a;">タスレポ</div>' +
    '<div style="font-size:11px;color:#64748b;">' + h_(summary.dateJa) + '</div></div>' +
    '</div>' +
    '' +
    '</div>' +

    alertBar +
    summaryGrid +
    boardLink +
    doneSection +
    newSection +
    activeSection +
    memberSection +
    footer +

    '</div></body></html>'
  );
}

function tdCard_(bg, textBig, textSmall, value, label) {
  return (
    '<td style="background:' + bg + ';border-radius:8px;padding:10px 4px;text-align:center;width:25%;">' +
    '<div style="font-size:20px;font-weight:700;color:' + textBig + ';">' + value + '</div>' +
    '<div style="font-size:11px;color:' + textSmall + ';margin-top:2px;">' + label + '</div>' +
    '</td>'
  );
}

// tdCard_ の呼び出し名を揃える
var tdCard = tdCard_;

function buildSection_(bg, border, hdrBg, hdrBorder, hdrText, countColor, title, countLabel, rows, extra) {
  return (
    '<div style="border:1px solid ' + border + ';border-radius:8px;overflow:hidden;margin-bottom:10px;">' +
    '<div style="display:flex;align-items:center;padding:8px 12px;background:' + hdrBg + ';border-bottom:1px solid ' + hdrBorder + ';">' +
    '<span style="font-size:11px;font-weight:600;color:' + hdrText + ';">' + title + '</span>' +
    '<span style="margin-left:auto;font-size:11px;font-weight:700;color:' + countColor + ';">' + countLabel + '</span>' +
    '</div>' +
    rows.join('') +
    (extra || '') +
    '</div>'
  );
}

function moreRow_(n, url) {
  var link = url
    ? '　<a href="' + h_(url) + '" style="color:#3b82f6;text-decoration:underline;">JIRAで全件確認 →</a>'
    : '';
  return '<div style="padding:6px 12px;background:#f8fafc;font-size:11px;color:#94a3b8;">+ 他 ' + n + ' 件' + link + '</div>';
}

function jiraLinkRow_(url) {
  return '<div style="padding:6px 12px;background:#f8fafc;text-align:right;">' +
    '<a href="' + h_(url) + '" style="font-size:11px;color:#3b82f6;text-decoration:underline;">JIRAで確認 →</a>' +
    '</div>';
}

function taskRow_(summary, url, meta) {
  return (
    '<div style="padding:3px 12px;border-top:1px solid #f1f5f9;">' +
    '<a href="' + h_(url) + '" style="font-size:11px;color:#334155;text-decoration:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block;">' + h_(summary) + '</a>' +
    '</div>'
  );
}

function h_(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── メール送信 ──────────────────────────────────────────────────

function sendReport_(cfg, summary, html) {
  var c = summary.counts;
  var subject = '【タスレポ】' + summary.dateShort;

  MailApp.sendEmail({
    to:       cfg.reportTo,
    cc:       'team.rock3110@gmail.com',
    subject:  subject,
    htmlBody: html,
    body:     buildPlainText_(summary),
  });
}

function buildPlainText_(summary) {
  var c = summary.counts;
  var lines = [
    '週次チーム進捗レポート ' + summary.dateJa,
    '',
    '進行中: ' + c.inProgress + '件　未対応: ' + c.todo + '件　今週完了: ' + c.doneWeek + '件',
    '期限切れ: ' + c.overdue + '件　担当未割り当て: ' + c.unassigned + '件' +
      (summary.unassignedAlert ? ' ← 要対応' : ''),
    '',
  ];
  if (summary.overdue.length) {
    lines.push('【期限切れ】');
    summary.overdue.forEach(function(d) {
      lines.push('- ' + d.summary + '（期限: ' + d.due + '）' + d.url);
    });
    lines.push('');
  }
  if (summary.doneThisWeek.length) {
    lines.push('【今週完了】');
    summary.doneThisWeek.forEach(function(d) {
      lines.push('- ' + d.summary + '（' + d.name + '）' + d.url);
    });
    lines.push('');
  }
  return lines.join('\n');
}

// ─── スプレッドシート書き込み（直近1回分を上書き） ────────────────────

function writeSpreadsheet_(cfg, issues, summary) {
  const ss = SpreadsheetApp.openById(cfg.spreadsheetId);
  const baseUrl = 'https://docs.google.com/spreadsheets/d/' + cfg.spreadsheetId + '/edit#gid=';

  function writeSheet_(name, header, dataRows) {
    let sh = ss.getSheetByName(name);
    if (!sh) sh = ss.insertSheet(name);
    sh.clearContents();
    const all = [header].concat(dataRows);
    if (all.length > 1) {
      sh.getRange(1, 1, all.length, header.length).setValues(all);
      sh.getRange(1, 1, 1, header.length).setFontWeight('bold');
    } else {
      sh.getRange(1, 1).setValue('データなし');
    }
    return baseUrl + sh.getSheetId();
  }

  const taskHeader = ['キー', 'タイトル', 'ステータス', '担当者', 'URL'];

  // ── 今週完了シート ──
  const doneUrl = writeSheet_('今週完了', taskHeader,
    summary.doneThisWeek.map(function(d) {
      return [d.key, d.summary, '完了', d.name, d.url];
    })
  );

  // ── 進行中・更新ありシート ──
  const activeUrl = writeSheet_('進行中_更新あり', taskHeader,
    summary.activeProgressList.map(function(d) {
      return [d.key, d.summary, '進行中', d.name, d.url];
    })
  );

  // ── 今週新規シート ──
  const newUrl = writeSheet_('今週新規', taskHeader,
    summary.newIssuesList.map(function(d) {
      return [d.key, d.summary, d.status, d.name, d.url];
    })
  );

  // ── raw シート：全イシュー一覧 ──
  writeSheet_('raw',
    ['キー', 'タイトル', 'ステータス', '担当者', '期限日', '完了日', 'URL'],
    issues.map(function(issue) {
      const f = issue.fields || {};
      return [
        issue.key,
        f.summary || '',
        (f.status && f.status.name) || '',
        (f.assignee && f.assignee.displayName) || '（未割当）',
        f.duedate || '',
        f.resolutiondate || '',
        cfg.jiraBase + '/browse/' + issue.key,
      ];
    })
  );

  console.log('スプレッドシートに書き込み完了: ' + issues.length + '件');
  return { done: doneUrl, active: activeUrl, newIssues: newUrl };
}

// ─── buildSummary_ の overdue 判定をデバッグ（デバッグ専用） ──────────

function debugOverdue() {
  const cfg = getConfig_();
  const issues = fetchAllIssues_(cfg);
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  let overdueCount = 0;
  let duedateNullCount = 0;
  let doneSkipCount = 0;
  const overdueItems = [];

  issues.forEach(function(issue) {
    const f = issue.fields || {};
    const statusName = (f.status && f.status.name) || '';
    const isDone = cfg.statusDone.indexOf(statusName) >= 0;

    if (isDone) {
      doneSkipCount++;
      return;
    }

    if (!f.duedate) {
      duedateNullCount++;
      return;
    }

    const due = new Date(f.duedate + 'T23:59:59');
    if (due < now) {
      overdueCount++;
      overdueItems.push(issue.key + ' | ' + f.duedate + ' | ' + statusName);
    }
  });

  console.log('【全取得件数】: ' + issues.length + '件');
  console.log('【完了ステータスでスキップ】: ' + doneSkipCount + '件');
  console.log('【duedate未設定でスキップ】: ' + duedateNullCount + '件');
  console.log('【期限切れとして検出】: ' + overdueCount + '件');
  overdueItems.forEach(function(s) { console.log('  ' + s); });
  console.log('【cfg.statusDone】: ' + JSON.stringify(cfg.statusDone));
}

// ─── 期限切れタスク確認用（デバッグ専用） ────────────────────────────

function checkOverdueIssues() {
  const cfg = getConfig_();
  const jql = 'project = "' + cfg.projectKey + '" AND duedate < now() AND statusCategory != Done ORDER BY duedate ASC';
  const url = cfg.jiraBase + '/rest/api/3/search/jql' +
    '?jql=' + encodeURIComponent(jql) +
    '&maxResults=20' +
    '&fields=summary,status,duedate,assignee';
  const res = jiraGet_(cfg, url);
  const issues = res.issues || [];
  console.log('【期限切れ件数（JIRA直接）】: ' + issues.length + '件');
  issues.forEach(function(issue) {
    const f = issue.fields || {};
    console.log(
      issue.key + ' | 期限: ' + (f.duedate || 'なし') +
      ' | ステータス: ' + ((f.status && f.status.name) || '?') +
      ' | 担当: ' + ((f.assignee && f.assignee.displayName) || '未割当')
    );
  });
  console.log('JIRAリンク: ' + cfg.jiraBase + '/issues/jql?jql=' + encodeURIComponent(jql));
}

// ─── イシュー総数確認用（一度だけ実行して確認する） ──────────────────

function checkIssueCount() {
  const cfg = getConfig_();
  const url = cfg.jiraBase + '/rest/api/3/search/jql' +
    '?jql=' + encodeURIComponent('project = "' + cfg.projectKey + '"') +
    '&maxResults=1';
  const res = jiraGet_(cfg, url);
  console.log('=== レスポンス全体 ===');
  console.log(JSON.stringify(res).substring(0, 500));
}
