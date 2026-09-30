/**
 * LEAVE BOARD — single-file app, served entirely as HTML from Google Apps
 * Script. One file, one deployment, no Next.js/npm/hosting needed.
 * ----------------------------------------------------------------------
 * Real username/password accounts (not Google Sign-In) — managed entirely
 * from the backend by Team Leads. Two portals in one app: Employees get
 * Apply / Dashboard / Account; Leads additionally get Approvals and Team
 * (create/remove Lead or Employee accounts). Dates are picked from a real
 * visual calendar, not a native browser date input.
 *
 * SETUP:
 * 1. Open your Google Sheet > Extensions > Apps Script.
 * 2. Delete everything in the editor, paste this whole file in, save.
 * 3. In the function dropdown at the top, select "seedFirstLead", click Run,
 *    and authorize when prompted. This creates the first login:
 *      username: admin   password: changeme123
 * 4. Deploy > New deployment > gear icon > Web app.
 *      Execute as: Me
 *      Who has access: Anyone
 *    (Login is now handled by the app itself, not Google accounts, so
 *    "Anyone" is correct here — the app's own login screen is the gate.)
 * 5. Copy the Web app URL — that's the whole app. Share it with your team.
 * 6. Log in as admin / changeme123, go to Account and change the password,
 *    then go to Team and add real Lead/Employee accounts for everyone.
 *
 * If you ever edit this code again: Deploy > Manage deployments > pencil
 * icon > New version > Deploy. Saving alone does not update a live app.
 */

function doGet(e) {
  if (e.parameter && e.parameter.action) {
    return handleEmailDecision(e);
  }
  return HtmlService.createHtmlOutput(HTML_APP)
    .setTitle('Leave Board')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/* ================= PASSWORD HASHING (SHA-256 + per-user salt) ================= */

function hashPassword(password, salt) {
  var raw = salt + '::' + password;
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw, Utilities.Charset.UTF_8);
  return bytes.map(function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

function makeSalt() {
  return Utilities.getUuid();
}

/* ================= USERS (stored once, centrally) ================= */

function getProps() { return PropertiesService.getScriptProperties(); }

function getUsers() {
  var raw = getProps().getProperty('users_v1');
  return raw ? JSON.parse(raw) : [];
}
function saveUsers(list) { getProps().setProperty('users_v1', JSON.stringify(list)); }

function findUserByUsername(username) {
  return getUsers().find(function (u) { return u.username.toLowerCase() === String(username).toLowerCase(); });
}
function findUserById(id) {
  return getUsers().find(function (u) { return u.id === id; });
}

function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role, email: u.email || '' };
}

/**
 * OPTIONAL — run manually from the Apps Script editor's function dropdown,
 * once, to create the very first login. Not callable from the web app.
 */
function seedFirstLead() {
  var users = getUsers();
  if (users.length) {
    Logger.log('Users already exist — skipping seed.');
    return;
  }
  var salt = makeSalt();
  users.push({
    id: Utilities.getUuid(),
    username: 'admin',
    salt: salt,
    passwordHash: hashPassword('changeme123', salt),
    role: 'LEAD',
    email: '',
    createdAt: new Date().toISOString()
  });
  saveUsers(users);
  Logger.log('Seeded first login — username: admin  password: changeme123. Change it after logging in.');
}

/* ================= SESSIONS ================= */

function getSessions() {
  var raw = getProps().getProperty('sessions_v1');
  return raw ? JSON.parse(raw) : {};
}
function saveSessions(map) { getProps().setProperty('sessions_v1', JSON.stringify(map)); }

var SESSION_LIFETIME_MS = 1000 * 60 * 60 * 24; // 24 hours

function createSession(user) {
  var sessions = getSessions();
  var now = Date.now();
  Object.keys(sessions).forEach(function (t) {
    if (now - sessions[t].createdAt > SESSION_LIFETIME_MS) delete sessions[t];
  });
  var token = Utilities.getUuid();
  sessions[token] = { userId: user.id, username: user.username, role: user.role, createdAt: now };
  saveSessions(sessions);
  return token;
}

function getSession(token) {
  if (!token) return null;
  var sessions = getSessions();
  var s = sessions[token];
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_LIFETIME_MS) return null;
  return s;
}

function requireSession(token) {
  var s = getSession(token);
  if (!s) throw new Error('Your session has expired. Please log in again.');
  return s;
}

function requireLead(token) {
  var s = requireSession(token);
  if (s.role !== 'LEAD') throw new Error('Only team leads can do that.');
  return s;
}

/* ================= AUTH API (called from the login screen) ================= */

function login(username, password) {
  var user = findUserByUsername(username);
  if (!user) return { ok: false, error: 'Incorrect username or password.' };
  var hash = hashPassword(password, user.salt);
  if (hash !== user.passwordHash) return { ok: false, error: 'Incorrect username or password.' };
  var token = createSession(user);
  return { ok: true, token: token, user: publicUser(user) };
}

function logout(token) {
  var sessions = getSessions();
  delete sessions[token];
  saveSessions(sessions);
  return { ok: true };
}

function whoAmI(token) {
  var s = getSession(token);
  if (!s) return null;
  var user = findUserById(s.userId);
  return user ? publicUser(user) : null;
}

/* ================= TEAM MANAGEMENT (Lead only) ================= */

function addUser(token, data) {
  requireLead(token);
  var username = String(data.username || '').trim();
  var password = String(data.password || '');
  var role = data.role === 'LEAD' ? 'LEAD' : 'EMPLOYEE';
  if (!username || !password) throw new Error('Username and password are required.');
  if (password.length < 4) throw new Error('Password must be at least 4 characters.');
  if (findUserByUsername(username)) throw new Error('That username is already taken.');

  var salt = makeSalt();
  var users = getUsers();
  users.push({
    id: Utilities.getUuid(),
    username: username,
    salt: salt,
    passwordHash: hashPassword(password, salt),
    role: role,
    email: String(data.email || '').trim(),
    createdAt: new Date().toISOString()
  });
  saveUsers(users);
  return users.map(publicUser);
}

function removeUser(token, id) {
  var session = requireLead(token);
  if (id === session.userId) throw new Error("You can't remove your own account.");
  var users = getUsers();
  var target = users.find(function (u) { return u.id === id; });
  if (!target) throw new Error('Account not found.');
  var leadCount = users.filter(function (u) { return u.role === 'LEAD'; }).length;
  if (target.role === 'LEAD' && leadCount <= 1) throw new Error('At least one team lead account must remain.');
  users = users.filter(function (u) { return u.id !== id; });
  saveUsers(users);
  return users.map(publicUser);
}

function changeOwnPassword(token, currentPassword, newPassword) {
  var session = requireSession(token);
  var user = findUserById(session.userId);
  if (!user) throw new Error('Account not found.');
  var hash = hashPassword(currentPassword, user.salt);
  if (hash !== user.passwordHash) throw new Error('Current password is incorrect.');
  if (!newPassword || String(newPassword).length < 4) throw new Error('New password must be at least 4 characters.');
  var salt = makeSalt();
  var users = getUsers();
  var u = users.find(function (x) { return x.id === user.id; });
  u.salt = salt;
  u.passwordHash = hashPassword(newPassword, salt);
  saveUsers(users);
  return { ok: true };
}

/* ================= LEAVE REQUESTS (stored in the Sheet) ================= */

function getSheet() {
  return SpreadsheetApp.getActiveSpreadsheet().getSheets()[0];
}

function ensureColumns(sheet) {
  var lastCol = Math.max(sheet.getLastColumn(), 1);
  var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
  var required = ['Request ID', 'Name', 'Start', 'End', 'Reason', 'Status', 'Detail', 'Updated At', 'Token'];
  required.forEach(function (col) {
    if (header.indexOf(col) === -1) {
      sheet.getRange(1, header.length + 1).setValue(col);
      header.push(col);
    }
  });
  return header;
}

function fmtInputDate(v) {
  if (Object.prototype.toString.call(v) === '[object Date]') {
    return Utilities.formatDate(v, Session.getScriptTimeZone(), 'yyyy-MM-dd');
  }
  return v;
}

function getAllLeaves() {
  var sheet = getSheet();
  var header = ensureColumns(sheet);
  var values = sheet.getDataRange().getValues();
  var idCol = header.indexOf('Request ID'), nameCol = header.indexOf('Name'),
      startCol = header.indexOf('Start'), endCol = header.indexOf('End'),
      reasonCol = header.indexOf('Reason'), statusCol = header.indexOf('Status'),
      detailCol = header.indexOf('Detail'), updatedCol = header.indexOf('Updated At');
  var out = [];
  for (var i = 1; i < values.length; i++) {
    var row = values[i];
    if (!row[idCol]) continue;
    out.push({
      id: row[idCol], username: row[nameCol],
      start: fmtInputDate(row[startCol]), end: fmtInputDate(row[endCol]),
      reason: row[reasonCol], status: row[statusCol],
      detail: row[detailCol], updatedAt: row[updatedCol]
    });
  }
  return out;
}

function findOrCreateRow(sheet, header, id) {
  var idCol = header.indexOf('Request ID');
  var values = sheet.getDataRange().getValues();
  for (var i = 1; i < values.length; i++) {
    if (String(values[i][idCol]) === String(id)) return i + 1;
  }
  var newRow = sheet.getLastRow() + 1;
  sheet.getRange(newRow, idCol + 1).setValue(id);
  return newRow;
}

function getOrCreateToken(sheet, header, row) {
  var tokenCol = header.indexOf('Token');
  var existing = sheet.getRange(row, tokenCol + 1).getValue();
  if (existing) return existing;
  var token = Utilities.getUuid();
  sheet.getRange(row, tokenCol + 1).setValue(token);
  return token;
}

function writeRow(sheet, header, row, data) {
  function set(col, val) {
    var c = header.indexOf(col);
    if (c > -1 && val !== undefined && val !== null) sheet.getRange(row, c + 1).setValue(val);
  }
  if (data.username !== undefined) set('Name', data.username);
  if (data.start !== undefined) set('Start', data.start);
  if (data.end !== undefined) set('End', data.end);
  if (data.reason !== undefined) set('Reason', data.reason);
  if (data.status !== undefined) set('Status', data.status);
  if (data.detail !== undefined) set('Detail', data.detail);
  set('Updated At', new Date());
}

function submitLeaveRequest(token, data) {
  var session = requireSession(token);
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    if (!data.start || !data.end) throw new Error('Start and end dates are required.');
    if (data.end < data.start) throw new Error("End date can't be before start date.");

    var sheet = getSheet();
    var header = ensureColumns(sheet);
    var id = Utilities.getUuid();
    var row = findOrCreateRow(sheet, header, id);
    var tok = getOrCreateToken(sheet, header, row);

    writeRow(sheet, header, row, {
      username: session.username, start: data.start, end: data.end,
      reason: data.reason, status: 'Pending', detail: 'Awaiting approval'
    });

    sendApprovalEmail({ id: id, username: session.username, start: data.start, end: data.end, reason: data.reason }, tok);

    return { ok: true, id: id };
  } finally {
    lock.releaseLock();
  }
}

function decideLeaveRequest(token, id, action) {
  requireLead(token);
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var sheet = getSheet();
    var header = ensureColumns(sheet);
    var values = sheet.getDataRange().getValues();
    var idCol = header.indexOf('Request ID');
    var rowIndex = -1;
    for (var i = 1; i < values.length; i++) {
      if (String(values[i][idCol]) === String(id)) { rowIndex = i + 1; break; }
    }
    if (rowIndex === -1) throw new Error('Not found');
    var newStatus = action === 'approve' ? 'Approved' : 'Rejected';
    writeRow(sheet, header, rowIndex, { status: newStatus, detail: 'Decided via dashboard' });
    return { ok: true };
  } finally {
    lock.releaseLock();
  }
}

/* ================= EMAIL APPROVAL (click-through links) ================= */

function sendApprovalEmail(data, token) {
  var leads = getUsers().filter(function (u) { return u.role === 'LEAD' && u.email; });
  if (!leads.length) return; // no lead has an email on file yet — skip silently

  var deploymentUrl = ScriptApp.getService().getUrl();
  var approveUrl = deploymentUrl + '?id=' + encodeURIComponent(data.id) + '&action=approve&token=' + token;
  var rejectUrl = deploymentUrl + '?id=' + encodeURIComponent(data.id) + '&action=reject&token=' + token;

  var html =
    '<div style="font-family:sans-serif; max-width:480px; margin:0 auto;">' +
    '<h2 style="color:#c47f1a;">New leave request</h2>' +
    '<p><b>' + esc(data.username) + '</b> requested leave from <b>' + esc(data.start) + '</b> to <b>' + esc(data.end) + '</b>.</p>' +
    (data.reason ? '<p style="color:#555;">Reason: ' + esc(data.reason) + '</p>' : '') +
    '<div style="margin:24px 0;">' +
    '<a href="' + approveUrl + '" style="background:#2E9E82;color:#ffffff;padding:12px 26px;border-radius:6px;text-decoration:none;font-weight:bold;margin-right:12px;display:inline-block;">Approve</a>' +
    '<a href="' + rejectUrl + '" style="background:#E0584D;color:#ffffff;padding:12px 26px;border-radius:6px;text-decoration:none;font-weight:bold;display:inline-block;">Reject</a>' +
    '</div>' +
    '<p style="color:#999; font-size:12px;">One click records your decision directly in the leave sheet.</p>' +
    '</div>';

  leads.forEach(function (lead) {
    MailApp.sendEmail({ to: lead.email, subject: 'Leave request from ' + data.username, htmlBody: html });
  });
}

function handleEmailDecision(e) {
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    var id = e.parameter.id, action = e.parameter.action, token = e.parameter.token;
    if (!id || !action || !token) return HtmlService.createHtmlOutput(page('Missing information', 'This link looks incomplete.', '#E0584D'));

    var sheet = getSheet();
    var header = ensureColumns(sheet);
    var values = sheet.getDataRange().getValues();
    var idCol = header.indexOf('Request ID'), tokenCol = header.indexOf('Token'),
        statusCol = header.indexOf('Status'), nameCol = header.indexOf('Name'),
        startCol = header.indexOf('Start'), endCol = header.indexOf('End');

    var rowIndex = -1;
    for (var i = 1; i < values.length; i++) {
      if (String(values[i][idCol]) === String(id)) { rowIndex = i + 1; break; }
    }
    if (rowIndex === -1) return HtmlService.createHtmlOutput(page('Request not found', 'This link may be out of date.', '#E0584D'));

    var storedToken = sheet.getRange(rowIndex, tokenCol + 1).getValue();
    if (String(storedToken) !== String(token)) return HtmlService.createHtmlOutput(page('Invalid link', 'This approval link is not valid.', '#E0584D'));

    var currentStatus = sheet.getRange(rowIndex, statusCol + 1).getValue();
    if (currentStatus === 'Approved' || currentStatus === 'Rejected') {
      return HtmlService.createHtmlOutput(page('Already decided', 'This request was already marked ' + currentStatus + '.', '#F2A93B'));
    }

    var newStatus = action === 'approve' ? 'Approved' : 'Rejected';
    writeRow(sheet, header, rowIndex, { status: newStatus, detail: 'Decided via email link' });

    var name = sheet.getRange(rowIndex, nameCol + 1).getValue();
    var start = fmtInputDate(sheet.getRange(rowIndex, startCol + 1).getValue());
    var end = fmtInputDate(sheet.getRange(rowIndex, endCol + 1).getValue());
    var color = newStatus === 'Approved' ? '#2E9E82' : '#E0584D';

    return HtmlService.createHtmlOutput(page('Leave ' + newStatus, name + '\u2019s leave from ' + start + ' to ' + end + ' has been marked ' + newStatus + '.', color));
  } finally {
    lock.releaseLock();
  }
}

function page(title, message, color) {
  return '<div style="font-family:sans-serif; max-width:420px; margin:60px auto; text-align:center;">' +
    '<h2 style="color:' + color + ';">' + esc(title) + '</h2>' +
    '<p style="color:#333;">' + esc(message) + '</p>' +
    '<p style="color:#999; font-size:12px;">You can close this tab.</p></div>';
}

function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

/* ================= BOOTSTRAP FOR THE FRONT END ================= */

function getBootstrapData(token) {
  var session = requireSession(token);
  var user = findUserById(session.userId);
  return {
    leaves: getAllLeaves(),
    users: getUsers().map(publicUser),
    currentUser: user ? publicUser(user) : null
  };
}

/* ================= FRONT-END APP (served as the whole page) ================= */

var HTML_APP = '<!DOCTYPE html><html><head><base target="_top">' +
'<meta charset="UTF-8">' +
'<style>' +
"@import url('https://fonts.googleapis.com/css2?family=Oswald:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');" +
':root{--board-bg:#14181F;--panel:#1C222C;--panel-raised:#232B37;--amber:#F2A93B;--amber-dim:#8a6323;--off-white:#EDEAE0;--muted:#8791A0;--teal:#2E9E82;--teal-dim:#163B32;--red:#E0584D;--red-dim:#3A1E1C;--line:#2C3440;font-family:"Inter",sans-serif;}' +
'*{box-sizing:border-box;}' +
'body{margin:0;background:var(--board-bg);color:var(--off-white);min-height:100vh;padding:28px 20px 60px;}' +
'.wrap{max-width:1040px;margin:0 auto;}' +
'.center-wrap{max-width:380px;margin:80px auto;}' +
'.board-header{background:linear-gradient(180deg,#191F28,#12161D);border:1px solid var(--line);border-radius:10px;padding:22px 26px;margin-bottom:22px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;}' +
'.eyebrow{font-family:"Space Mono",monospace;font-size:11px;letter-spacing:2px;color:var(--muted);text-transform:uppercase;margin-bottom:6px;}' +
'h1{font-family:"Oswald",sans-serif;font-weight:700;font-size:36px;letter-spacing:1px;margin:0;color:var(--amber);text-shadow:0 0 18px rgba(242,169,59,0.25);}' +
'.signed-in{font-family:"Space Mono",monospace;font-size:12px;color:var(--muted);text-align:right;}' +
'.signed-in a{color:var(--muted);text-decoration:underline;cursor:pointer;}' +
'.role-toggle{display:flex;gap:2px;background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:4px;width:fit-content;margin:0 auto 24px;}' +
'.role-toggle button{font-family:"Oswald",sans-serif;letter-spacing:0.5px;font-size:14px;padding:9px 20px;border-radius:999px;border:none;background:transparent;color:var(--muted);cursor:pointer;}' +
'.role-toggle button.active{background:var(--amber);color:#14181F;font-weight:600;}' +
'.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:24px;margin-bottom:22px;}' +
'.panel h2{font-family:"Oswald",sans-serif;font-size:20px;letter-spacing:0.5px;margin:0 0 4px;}' +
'.panel .sub{color:var(--muted);font-size:13px;margin:0 0 18px;}' +
'.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}' +
'.form-grid .full{grid-column:1/-1;}' +
'label{display:block;font-size:12px;letter-spacing:0.5px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;font-weight:600;}' +
'input[type=text],input[type=password],textarea,select{width:100%;background:var(--panel-raised);border:1px solid var(--line);border-radius:6px;color:var(--off-white);padding:10px 12px;font-size:14px;font-family:"Inter",sans-serif;outline:none;}' +
'input.error{border-color:var(--red);}' +
'textarea{resize:vertical;min-height:60px;}' +
'.field-err{color:var(--red);font-size:12px;margin-top:5px;display:none;}' +
'.field-err.show{display:block;}' +
'.btn{font-family:"Oswald",sans-serif;letter-spacing:0.5px;font-size:14px;font-weight:600;padding:11px 22px;border-radius:6px;border:none;cursor:pointer;}' +
'.btn-primary{background:var(--amber);color:#14181F;}' +
'.btn-approve{background:var(--teal);color:#fff;}' +
'.btn-reject{background:var(--red);color:#fff;}' +
'.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--line);}' +
'.btn:disabled{opacity:0.4;cursor:not-allowed;}' +
'.btn-block{width:100%;}' +
'.form-actions{grid-column:1/-1;display:flex;align-items:center;gap:14px;margin-top:4px;}' +
'.toast{font-size:13px;color:var(--teal);font-family:"Space Mono",monospace;opacity:0;transition:opacity .25s;}' +
'.toast.show{opacity:1;}' +
'.badge{font-family:"Space Mono",monospace;font-size:11px;letter-spacing:1px;text-transform:uppercase;padding:4px 10px;border-radius:4px;display:inline-block;white-space:nowrap;}' +
'.badge.Pending{background:rgba(242,169,59,0.12);color:var(--amber);border:1px solid var(--amber-dim);}' +
'.badge.Approved{background:var(--teal-dim);color:var(--teal);border:1px solid var(--teal);}' +
'.badge.Rejected{background:var(--red-dim);color:var(--red);border:1px solid var(--red);}' +
'.request-row{display:grid;grid-template-columns:1fr auto auto auto;align-items:center;gap:14px;padding:14px 4px;border-bottom:1px solid var(--line);}' +
'.request-row:last-child{border-bottom:none;}' +
'.req-who{font-weight:600;font-family:"Oswald",sans-serif;}' +
'.req-dates{color:var(--muted);font-size:12.5px;font-family:"Space Mono",monospace;}' +
'.req-reason{color:var(--muted);font-size:13px;margin-top:2px;}' +
'.req-actions{display:flex;gap:8px;}' +
'.req-actions .btn{padding:7px 14px;font-size:12px;}' +
'.empty-state{text-align:center;padding:30px 10px;color:var(--muted);font-size:13.5px;}' +
'.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px;}' +
'.stat-card{background:linear-gradient(180deg,#202834,#171D26);border:1px solid var(--line);border-radius:8px;padding:16px 18px;}' +
'.stat-card.highlight{border-color:var(--amber-dim);background:linear-gradient(180deg,#262014,#1A1610);}' +
'.stat-num{font-family:"Oswald",sans-serif;font-weight:700;font-size:40px;line-height:1;color:var(--amber);}' +
'.stat-card:not(.highlight) .stat-num{color:var(--off-white);}' +
'.stat-label{font-family:"Space Mono",monospace;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-top:4px;}' +
'.flap-table{border:1px solid var(--line);border-radius:8px;overflow:hidden;}' +
'.flap-head{display:grid;grid-template-columns:90px 1.4fr 1fr 1fr;background:#10141B;padding:10px 16px;font-family:"Space Mono",monospace;font-size:11px;letter-spacing:1.5px;color:var(--muted);text-transform:uppercase;border-bottom:1px solid var(--line);}' +
'.flap-row{display:grid;grid-template-columns:90px 1.4fr 1fr 1fr;align-items:center;padding:14px 16px;background:var(--panel-raised);border-bottom:1px solid var(--line);}' +
'.flap-row:last-child{border-bottom:none;}' +
'.flap-status{font-family:"Oswald",sans-serif;font-weight:600;letter-spacing:1px;font-size:13px;}' +
'.flap-status.out{color:var(--red);}' +
'.flap-status.pending{color:var(--amber);}' +
'.flap-status.available{color:var(--teal);}' +
'.flap-user{font-family:"Oswald",sans-serif;font-size:16px;letter-spacing:0.5px;}' +
'.flap-dates,.flap-reason{font-size:13px;color:var(--muted);font-family:"Space Mono",monospace;}' +
'.flap-reason{font-family:"Inter",sans-serif;}' +
'.calendar-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel-raised);}' +
'.cal-table{border-collapse:collapse;width:max-content;}' +
'.cal-table th,.cal-table td{padding:7px 9px;text-align:center;font-family:"Space Mono",monospace;font-size:11px;border-bottom:1px solid var(--line);border-right:1px solid var(--line);white-space:nowrap;}' +
'.cal-table th{background:#10141B;color:var(--muted);font-weight:400;}' +
'.cal-table th.today-col,.cal-table td.today-col{background:rgba(242,169,59,0.08);}' +
'.cal-table .user-col{position:sticky;left:0;background:var(--panel-raised);text-align:left;font-family:"Oswald",sans-serif;font-size:13px;min-width:150px;}' +
'.cal-table th.user-col{background:#10141B;}' +
'.cal-dot{width:9px;height:9px;border-radius:50%;display:inline-block;}' +
'.cal-dot.out{background:var(--red);}' +
'.cal-dot.pending{background:var(--amber);}' +
'.cal-dot.free{background:var(--line);}' +
'.foot-note{text-align:center;color:var(--muted);font-size:12px;margin-top:26px;font-family:"Space Mono",monospace;}' +
'.access-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 4px;border-bottom:1px solid var(--line);}' +
'.access-row:last-child{border-bottom:none;}' +
'.access-name{font-family:"Oswald",sans-serif;font-weight:600;}' +
'.access-meta{font-family:"Space Mono",monospace;font-size:11px;color:var(--muted);}' +
/* --- picker (custom calendar date field) --- */
'.picker-wrap{position:relative;}' +
'.picker-btn{width:100%;text-align:left;background:var(--panel-raised);border:1px solid var(--line);border-radius:6px;color:var(--off-white);padding:10px 12px;font-size:14px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;}' +
'.picker-btn.error{border-color:var(--red);}' +
'.picker-btn.placeholder{color:var(--muted);}' +
'.picker-pop{position:absolute;z-index:30;margin-top:6px;background:var(--panel-raised);border:1px solid var(--line);border-radius:10px;padding:12px;width:270px;font-family:"Space Mono",monospace;}' +
'.picker-pop-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;padding:0 2px;}' +
'.picker-pop-head button{background:none;border:none;color:var(--muted);font-size:15px;cursor:pointer;padding:4px 8px;}' +
'.picker-pop-head button:hover{color:var(--off-white);}' +
'.picker-month{font-family:"Oswald",sans-serif;font-size:13px;color:var(--off-white);}' +
'.picker-grid{display:grid;grid-template-columns:repeat(7,1fr);gap:2px;}' +
'.picker-dow{text-align:center;font-size:10px;color:var(--muted);padding:4px 0;}' +
'.picker-day{text-align:center;font-size:12px;padding:6px 0;border-radius:5px;cursor:pointer;color:var(--off-white);background:none;border:none;font-family:"Space Mono",monospace;}' +
'.picker-day:hover{background:rgba(242,169,59,0.12);}' +
'.picker-day.out-month{color:var(--line);}' +
'.picker-day.disabled{color:var(--line);cursor:not-allowed;pointer-events:none;}' +
'.picker-day.today{box-shadow:inset 0 0 0 1px var(--amber-dim);}' +
'.picker-day.selected{background:var(--amber);color:#14181F;font-weight:700;}' +
'@media (max-width:640px){.form-grid{grid-template-columns:1fr;}.flap-head,.flap-row{grid-template-columns:70px 1fr 1fr;}.flap-head .col-reason,.flap-row .flap-reason{display:none;}h1{font-size:28px;}.request-row{grid-template-columns:1fr;}.picker-pop{width:240px;}}' +
'</style></head><body>' +

'<div class="wrap" id="app-wrap" style="display:none;">' +
'<div class="board-header"><div><div class="eyebrow">Team Attendance · Live</div><h1>LEAVE BOARD</h1></div>' +
'<div class="signed-in" id="signed-in-as"></div></div>' +

'<div class="role-toggle" id="role-toggle"></div>' +

'<div class="panel" id="view-apply" style="display:none;">' +
'<h2>Request time off</h2><p class="sub">Pick your dates from the calendar below.</p>' +
'<div class="form-grid">' +
'<div><label>Start date *</label><div class="picker-wrap" id="picker-start"></div><div class="field-err" id="err-start">Pick a start date.</div></div>' +
'<div><label>End date *</label><div class="picker-wrap" id="picker-end"></div><div class="field-err" id="err-end">End date can\'t be before start date.</div></div>' +
'<div class="full"><label>Reason (optional)</label><textarea id="f-reason"></textarea></div>' +
'<div class="form-actions"><button class="btn btn-primary" id="btn-submit">Submit request</button><span class="toast" id="submit-toast">\u2713 Sent for approval</span></div>' +
'</div></div>' +

'<div class="panel" id="view-approvals" style="display:none;">' +
'<h2>Pending approvals</h2><p class="sub">Leave only appears on the dashboard once approved.</p>' +
'<div id="pending-list"></div></div>' +

'<div class="panel" id="view-team" style="display:none;">' +
'<h2>Team directory</h2><p class="sub">Add Lead or Employee accounts here — this is the only way accounts are created; there\'s no public signup.</p>' +
'<div class="form-grid">' +
'<div><label>Username</label><input type="text" id="team-username"></div>' +
'<div><label>Temporary password</label><input type="text" id="team-password"></div>' +
'<div><label>Role</label><select id="team-role"><option value="EMPLOYEE">Employee</option><option value="LEAD">Lead</option></select></div>' +
'<div><label>Email (for approval emails, Leads only)</label><input type="text" id="team-email"></div>' +
'<div class="form-actions"><button class="btn btn-primary" id="team-add-btn">Add account</button><span class="toast" id="team-toast" style="color:var(--red);"></span></div>' +
'</div>' +
'<div id="team-list" style="margin-top:18px;"></div></div>' +

'<div class="panel" id="view-dashboard" style="display:none;">' +
'<h2>Who\'s out</h2><p class="sub">Pick a date to see everyone with an approved leave covering it.</p>' +
'<div class="stat-row">' +
'<div class="stat-card highlight"><div class="stat-num" id="stat-onleave">0</div><div class="stat-label" id="stat-onleave-label">On leave today</div></div>' +
'<div class="stat-card"><div class="stat-num" id="stat-pending">0</div><div class="stat-label">Pending approval</div></div>' +
'<div class="stat-card"><div class="stat-num" id="stat-total">0</div><div class="stat-label">Total requests logged</div></div>' +
'</div>' +
'<div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;flex-wrap:wrap;">' +
'<div class="picker-wrap" id="picker-dash" style="max-width:220px;"></div>' +
'<button class="btn btn-ghost" id="btn-today" style="padding:9px 14px;font-size:12px;">Today</button>' +
'</div>' +
'<div class="flap-table"><div class="flap-head"><div>Status</div><div>Username</div><div>Leave dates</div><div class="col-reason">Reason</div></div><div id="flap-body"></div></div>' +
'<h2 style="margin-top:28px;">Team status directory</h2><p class="sub">Live status for every teammate.</p>' +
'<div class="flap-table"><div class="flap-head"><div>Status</div><div>Username</div><div>Since</div><div class="col-reason">Detail</div></div><div id="directory-body"></div></div>' +
'<h2 style="margin-top:28px;">30-day leave calendar</h2><p class="sub">Rolling window starting today.</p>' +
'<div class="calendar-wrap" id="calendar-wrap"></div>' +
'</div>' +

'<div class="panel" id="view-account" style="display:none;">' +
'<h2>Account</h2><p class="sub">Change your own password.</p>' +
'<div class="form-grid">' +
'<div><label>Current password</label><input type="password" id="pw-current"></div>' +
'<div><label>New password</label><input type="password" id="pw-new"></div>' +
'<div class="form-actions"><button class="btn btn-primary" id="pw-save">Update password</button><span id="pw-status" style="font-size:12.5px;color:var(--muted);font-family:\'Space Mono\',monospace;"></span></div>' +
'</div></div>' +

'<div class="foot-note">Leave only counts as taken once a team lead approves it.</div>' +
'</div>' +

'<div class="center-wrap" id="login-wrap">' +
'<div style="text-align:center;margin-bottom:28px;"><div class="eyebrow">Team Attendance</div><h1>LEAVE BOARD</h1></div>' +
'<div class="panel">' +
'<div><label>Username</label><input type="text" id="login-username"></div>' +
'<div style="margin-top:14px;"><label>Password</label><input type="password" id="login-password"></div>' +
'<div class="field-err show" id="login-err" style="display:none;margin:10px 0;"></div>' +
'<button class="btn btn-primary btn-block" id="login-btn" style="margin-top:14px;">Sign in</button>' +
'</div>' +
'<p style="text-align:center;color:var(--muted);font-size:12px;margin-top:18px;font-family:\'Space Mono\',monospace;">Accounts are created by your team lead — there\'s no self-signup.</p>' +
'</div>' +

'<script>' +
'var TOKEN=null;var CURRENT_USER=null;var leaves=[];var users=[];' +

'function onError(err){alert("Something went wrong: " + (err && err.message ? err.message : err));}' +
'function escapeHtml(str){var d=document.createElement("div");d.textContent=str;return d.innerHTML;}' +

/* ---- date helpers ---- */
'function pad2(n){return (n<10?"0":"")+n;}' +
'function toISO(y,m,d){return y+"-"+pad2(m+1)+"-"+pad2(d);}' +
'function todayStr(){var d=new Date();return toISO(d.getFullYear(),d.getMonth(),d.getDate());}' +
'function addDays(dateStr,n){var d=new Date(dateStr+"T00:00:00");d.setDate(d.getDate()+n);return toISO(d.getFullYear(),d.getMonth(),d.getDate());}' +
'function fmt(dateStr){if(!dateStr)return"";var d=new Date(dateStr+"T00:00:00");return d.toLocaleDateString("en-US",{month:"short",day:"numeric",year:"numeric"});}' +
'var MONTH_NAMES=["January","February","March","April","May","June","July","August","September","October","November","December"];' +
'var DOW=["S","M","T","W","T","F","S"];' +

/* ---- custom calendar date-picker component ----
   Usage: makeDatePicker(containerEl, { value, onChange, minDate }) */
'function makeDatePicker(container,opts){' +
'var state={value:opts.value||"",minDate:opts.minDate||null,viewYear:0,viewMonth:0,open:false};' +
'var base=opts.value?new Date(opts.value+"T00:00:00"):new Date();' +
'state.viewYear=base.getFullYear();state.viewMonth=base.getMonth();' +

'var btn=document.createElement("button");btn.type="button";btn.className="picker-btn placeholder";btn.textContent="Select a date";' +
'var pop=document.createElement("div");pop.className="picker-pop";pop.style.display="none";' +
'container.innerHTML="";container.appendChild(btn);container.appendChild(pop);' +

'function renderPop(){' +
'var y=state.viewYear,m=state.viewMonth;' +
'var first=new Date(y,m,1);var startDow=first.getDay();' +
'var daysInMonth=new Date(y,m+1,0).getDate();' +
'var daysInPrev=new Date(y,m,0).getDate();' +
'var cells=[];' +
'for(var i=0;i<startDow;i++){cells.push({d:daysInPrev-startDow+1+i,inMonth:false,y:m===0?y-1:y,m:m===0?11:m-1});}' +
'for(var d=1;d<=daysInMonth;d++){cells.push({d:d,inMonth:true,y:y,m:m});}' +
'while(cells.length%7!==0||cells.length<42){var nd=cells.length-(startDow+daysInMonth)+1;cells.push({d:nd,inMonth:false,y:m===11?y+1:y,m:m===11?0:m+1});}' +
'var html="<div class=\\"picker-pop-head\\"><button type=\\"button\\" data-nav=\\"-1\\">\u2039</button><span class=\\"picker-month\\">"+MONTH_NAMES[m]+" "+y+"</span><button type=\\"button\\" data-nav=\\"1\\">\u203a</button></div>";' +
'html+="<div class=\\"picker-grid\\">";' +
'DOW.forEach(function(dw){html+="<div class=\\"picker-dow\\">"+dw+"</div>";});' +
'var today=todayStr();' +
'cells.forEach(function(c){' +
'var iso=toISO(c.y,c.m,c.d);' +
'var cls=["picker-day"];' +
'if(!c.inMonth)cls.push("out-month");' +
'if(state.minDate&&iso<state.minDate)cls.push("disabled");' +
'if(iso===today)cls.push("today");' +
'if(iso===state.value)cls.push("selected");' +
'html+="<button type=\\"button\\" class=\\""+cls.join(" ")+"\\" data-date=\\""+iso+"\\">"+c.d+"</button>";' +
'});' +
'html+="</div>";' +
'pop.innerHTML=html;' +
'pop.querySelectorAll("[data-nav]").forEach(function(b){' +
'b.onclick=function(){var dir=parseInt(b.getAttribute("data-nav"),10);state.viewMonth+=dir;if(state.viewMonth<0){state.viewMonth=11;state.viewYear--;}if(state.viewMonth>11){state.viewMonth=0;state.viewYear++;}renderPop();};' +
'});' +
'pop.querySelectorAll(".picker-day:not(.disabled)").forEach(function(b){' +
'b.onclick=function(){state.value=b.getAttribute("data-date");renderBtn();pop.style.display="none";state.open=false;if(opts.onChange)opts.onChange(state.value);};' +
'});' +
'}' +

'function renderBtn(){' +
'if(state.value){btn.textContent=fmt(state.value);btn.classList.remove("placeholder");}' +
'else{btn.textContent="Select a date";btn.classList.add("placeholder");}' +
'}' +

'btn.onclick=function(e){e.stopPropagation();state.open=!state.open;pop.style.display=state.open?"block":"none";if(state.open)renderPop();};' +
'document.addEventListener("click",function(e){if(!container.contains(e.target)){pop.style.display="none";state.open=false;}});' +

'renderBtn();' +

'return{' +
'getValue:function(){return state.value;},' +
'setValue:function(v){state.value=v;renderBtn();},' +
'setMinDate:function(v){state.minDate=v;},' +
'setError:function(hasError){btn.classList.toggle("error",!!hasError);}' +
'};' +
'}' +
/* ---- login ---- */
'document.getElementById("login-btn").onclick=function(){' +
'var u=document.getElementById("login-username").value.trim();' +
'var p=document.getElementById("login-password").value;' +
'var errEl=document.getElementById("login-err");errEl.style.display="none";' +
'if(!u||!p){errEl.textContent="Enter both a username and password.";errEl.style.display="block";return;}' +
'var btn=document.getElementById("login-btn");btn.disabled=true;btn.textContent="Signing in\u2026";' +
'google.script.run.withSuccessHandler(function(res){' +
'btn.disabled=false;btn.textContent="Sign in";' +
'if(res.ok){TOKEN=res.token;CURRENT_USER=res.user;enterApp();}' +
'else{errEl.textContent=res.error;errEl.style.display="block";}' +
'}).withFailureHandler(function(err){btn.disabled=false;btn.textContent="Sign in";onError(err);}).login(u,p);' +
'};' +
'document.getElementById("login-password").addEventListener("keydown",function(e){if(e.key==="Enter")document.getElementById("login-btn").click();});' +

'function enterApp(){' +
'document.getElementById("login-wrap").style.display="none";' +
'document.getElementById("app-wrap").style.display="block";' +
'buildTabs();' +
'setActiveTab("apply");' +
'refresh();' +
'}' +

'function signOutNow(){' +
'google.script.run.logout(TOKEN);' +
'TOKEN=null;CURRENT_USER=null;' +
'document.getElementById("app-wrap").style.display="none";' +
'document.getElementById("login-wrap").style.display="block";' +
'document.getElementById("login-username").value="";' +
'document.getElementById("login-password").value="";' +
'}' +

/* ---- tabs ---- */
'var TAB_LABELS={apply:"Apply",approvals:"Approvals",team:"Team",dashboard:"Dashboard",account:"Account"};' +
'function buildTabs(){' +
'var isLead=CURRENT_USER.role==="LEAD";' +
'var tabs=isLead?["apply","approvals","team","dashboard","account"]:["apply","dashboard","account"];' +
'var bar=document.getElementById("role-toggle");' +
'bar.innerHTML=tabs.map(function(t){return "<button data-tab=\\""+t+"\\">"+TAB_LABELS[t]+"</button>";}).join("");' +
'bar.querySelectorAll("button").forEach(function(b){b.onclick=function(){setActiveTab(b.getAttribute("data-tab"));};});' +
'document.getElementById("signed-in-as").innerHTML="Signed in as "+escapeHtml(CURRENT_USER.username)+(isLead?" <span style=\\"color:var(--teal);\\">\u00b7 Lead</span>":"")+"<br><a onclick=\\"signOutNow()\\">Sign out</a>";' +
'var picks=["view-apply","view-approvals","view-team","view-dashboard","view-account"];' +
'picks.forEach(function(id){document.getElementById(id).style.display="none";});' +
'}' +

'var pickerStart=null,pickerEnd=null,pickerDash=null;' +

'function setActiveTab(name){' +
'document.querySelectorAll("#role-toggle button").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-tab")===name);});' +
'["view-apply","view-approvals","view-team","view-dashboard","view-account"].forEach(function(id){document.getElementById(id).style.display="none";});' +
'document.getElementById("view-"+name).style.display="block";' +
'if(name==="apply"&&!pickerStart){' +
'pickerStart=makeDatePicker(document.getElementById("picker-start"),{onChange:function(v){if(pickerEnd)pickerEnd.setMinDate(v);}});' +
'pickerEnd=makeDatePicker(document.getElementById("picker-end"),{});' +
'}' +
'if(name==="dashboard"){' +
'if(!pickerDash){pickerDash=makeDatePicker(document.getElementById("picker-dash"),{value:todayStr(),onChange:renderDashboard});pickerDash.setValue(todayStr());}' +
'renderDashboard();' +
'}' +
'if(name==="approvals")renderApprovals();' +
'if(name==="team")renderTeam();' +
'}' +

'function refresh(cb){' +
'google.script.run.withSuccessHandler(function(data){' +
'leaves=data.leaves;users=data.users;CURRENT_USER=data.currentUser;' +
'renderDashboard();renderApprovals();renderTeam();' +
'if(cb)cb();' +
'}).withFailureHandler(function(err){if(err&&err.message&&err.message.indexOf("expired")!==-1){signOutNow();}else{onError(err);}}).getBootstrapData(TOKEN);' +
'}' +
/* ---- apply ---- */
'document.getElementById("btn-submit").onclick=function(){' +
'var start=pickerStart.getValue(),end=pickerEnd.getValue();' +
'var valid=true;' +
'pickerStart.setError(false);pickerEnd.setError(false);' +
'["err-start","err-end"].forEach(function(id){document.getElementById(id).classList.remove("show");});' +
'if(!start){pickerStart.setError(true);document.getElementById("err-start").classList.add("show");valid=false;}' +
'if(!end||(start&&end<start)){pickerEnd.setError(true);document.getElementById("err-end").classList.add("show");valid=false;}' +
'if(!valid)return;' +
'var reason=document.getElementById("f-reason").value.trim();' +
'var btn=document.getElementById("btn-submit");btn.disabled=true;' +
'google.script.run.withSuccessHandler(function(){' +
'btn.disabled=false;' +
'pickerStart.setValue("");pickerEnd.setValue("");document.getElementById("f-reason").value="";' +
'var t=document.getElementById("submit-toast");t.classList.add("show");setTimeout(function(){t.classList.remove("show");},2200);' +
'refresh();' +
'}).withFailureHandler(function(err){btn.disabled=false;onError(err);}).submitLeaveRequest(TOKEN,{start:start,end:end,reason:reason});' +
'};' +

/* ---- approvals ---- */
'function renderApprovals(){' +
'var pendingList=document.getElementById("pending-list");if(!pendingList)return;' +
'var pending=leaves.filter(function(l){return l.status==="Pending";});' +
'pendingList.innerHTML=pending.length?pending.map(function(l){return ' +
'"<div class=\\"request-row\\"><div><div class=\\"req-who\\">"+escapeHtml(l.username)+"</div><div class=\\"req-dates\\">"+fmt(l.start)+" \u2192 "+fmt(l.end)+"</div>"+(l.reason?"<div class=\\"req-reason\\">"+escapeHtml(l.reason)+"</div>":"")+"</div><span class=\\"badge Pending\\">Pending</span><div class=\\"req-actions\\"><button class=\\"btn btn-approve\\" data-action=\\"approve\\" data-id=\\""+l.id+"\\">Approve</button><button class=\\"btn btn-reject\\" data-action=\\"reject\\" data-id=\\""+l.id+"\\">Reject</button></div><div></div></div>";' +
'}).join(""):"<div class=\\"empty-state\\">No pending requests. All caught up.</div>";' +
'pendingList.querySelectorAll("button[data-action]").forEach(function(btn){' +
'btn.onclick=function(){' +
'var id=btn.getAttribute("data-id"),action=btn.getAttribute("data-action");' +
'btn.closest(".request-row").querySelectorAll("button").forEach(function(b){b.disabled=true;});' +
'google.script.run.withSuccessHandler(function(){refresh();}).withFailureHandler(onError).decideLeaveRequest(TOKEN,id,action);' +
'};' +
'});' +
'}' +

/* ---- team ---- */
'function renderTeam(){' +
'var list=document.getElementById("team-list");if(!list)return;' +
'list.innerHTML=users.map(function(u){return ' +
'"<div class=\\"access-row\\"><div><div class=\\"access-name\\">"+escapeHtml(u.username)+(u.id===CURRENT_USER.id?" (you)":"")+"</div><div class=\\"access-meta\\">"+(u.role==="LEAD"?"Team Lead":"Employee")+(u.email?" \u00b7 "+escapeHtml(u.email):"")+"</div></div>"+' +
'(u.id!==CURRENT_USER.id?"<button class=\\"btn btn-ghost\\" style=\\"padding:6px 12px;font-size:11px;\\" data-remove=\\""+u.id+"\\">Remove</button>":"")+' +
'"</div>";' +
'}).join("");' +
'list.querySelectorAll("[data-remove]").forEach(function(btn){' +
'btn.onclick=function(){' +
'var id=btn.getAttribute("data-remove");' +
'google.script.run.withSuccessHandler(function(){refresh();}).withFailureHandler(onError).removeUser(TOKEN,id);' +
'};' +
'});' +
'}' +
'document.getElementById("team-add-btn").onclick=function(){' +
'var username=document.getElementById("team-username").value.trim();' +
'var password=document.getElementById("team-password").value;' +
'var role=document.getElementById("team-role").value;' +
'var email=document.getElementById("team-email").value.trim();' +
'var toast=document.getElementById("team-toast");toast.textContent="";' +
'if(!username||!password){toast.textContent="Username and password are required.";return;}' +
'var btn=document.getElementById("team-add-btn");btn.disabled=true;' +
'google.script.run.withSuccessHandler(function(){' +
'btn.disabled=false;' +
'document.getElementById("team-username").value="";document.getElementById("team-password").value="";document.getElementById("team-email").value="";' +
'refresh();' +
'}).withFailureHandler(function(err){btn.disabled=false;toast.textContent=err&&err.message?err.message:"Something went wrong.";}).addUser(TOKEN,{username:username,password:password,role:role,email:email});' +
'};' +

/* ---- account ---- */
'document.getElementById("pw-save").onclick=function(){' +
'var cur=document.getElementById("pw-current").value,nw=document.getElementById("pw-new").value;' +
'var statusEl=document.getElementById("pw-status");statusEl.textContent="";' +
'google.script.run.withSuccessHandler(function(){' +
'statusEl.style.color="var(--teal)";statusEl.textContent="\u2713 Password updated.";' +
'document.getElementById("pw-current").value="";document.getElementById("pw-new").value="";' +
'}).withFailureHandler(function(err){statusEl.style.color="var(--red)";statusEl.textContent=err&&err.message?err.message:"Something went wrong.";}).changeOwnPassword(TOKEN,cur,nw);' +
'};' +
/* ---- status helpers (client-side, same logic as the sheet) ---- */
'function statusOnDate(username,dateStr){' +
'var mine=leaves.filter(function(l){return l.username.toLowerCase()===username.toLowerCase();});' +
'if(mine.some(function(l){return l.status==="Approved"&&l.start<=dateStr&&dateStr<=l.end;}))return"out";' +
'if(mine.some(function(l){return l.status==="Pending"&&l.start<=dateStr&&dateStr<=l.end;}))return"pending";' +
'return"free";' +
'}' +
'function computeUserStatus(username){' +
'var today=todayStr();' +
'var mine=leaves.filter(function(l){return l.username.toLowerCase()===username.toLowerCase();});' +
'var active=mine.filter(function(l){return l.status==="Approved"&&l.start<=today&&today<=l.end;})[0];' +
'if(active)return{status:"out",label:"On leave",detail:"Back "+fmt(active.end)};' +
'var pending=mine.filter(function(l){return l.status==="Pending";}).sort(function(a,b){return a.start.localeCompare(b.start);})[0];' +
'if(pending)return{status:"pending",label:"Pending",detail:"Awaiting approval"};' +
'var upcoming=mine.filter(function(l){return l.status==="Approved"&&l.start>today;}).sort(function(a,b){return a.start.localeCompare(b.start);})[0];' +
'if(upcoming)return{status:"available",label:"Available",detail:"Leave from "+fmt(upcoming.start)};' +
'return{status:"available",label:"Available",detail:"No leave on record"};' +
'}' +

'function renderDashboard(){' +
'var dashView=document.getElementById("view-dashboard");if(!dashView||dashView.style.display==="none")return;' +
'if(!pickerDash)return;' +
'var target=pickerDash.getValue()||todayStr();' +
'var onLeave=leaves.filter(function(l){return l.status==="Approved"&&l.start<=target&&target<=l.end;});' +
'var pendingCount=leaves.filter(function(l){return l.status==="Pending";}).length;' +
'document.getElementById("stat-onleave").textContent=onLeave.length;' +
'document.getElementById("stat-pending").textContent=pendingCount;' +
'document.getElementById("stat-total").textContent=leaves.length;' +
'var isToday=target===todayStr();' +
'document.getElementById("stat-onleave-label").textContent=isToday?"On leave today":("On leave \u00b7 "+fmt(target));' +

'var body=document.getElementById("flap-body");' +
'body.innerHTML=onLeave.length?onLeave.map(function(l){return ' +
'"<div class=\\"flap-row\\"><div class=\\"flap-status out\\">OUT</div><div class=\\"flap-user\\">"+escapeHtml(l.username)+"</div><div class=\\"flap-dates\\">"+fmt(l.start)+" \u2192 "+fmt(l.end)+"</div><div class=\\"flap-reason\\">"+(l.reason?escapeHtml(l.reason):"\u2014")+"</div></div>";' +
'}).join(""):"<div class=\\"empty-state\\">Nobody\'s on approved leave for this date.</div>";' +

'var dirBody=document.getElementById("directory-body");' +
'dirBody.innerHTML=users.length?users.map(function(u){var s=computeUserStatus(u.username);var t=s.status==="out"?"OUT":s.status==="pending"?"PENDING":"FREE";return ' +
'"<div class=\\"flap-row\\"><div class=\\"flap-status "+s.status+"\\">"+t+"</div><div class=\\"flap-user\\">"+escapeHtml(u.username)+"</div><div class=\\"flap-dates\\">"+escapeHtml(s.detail)+"</div><div class=\\"flap-reason\\"></div></div>";' +
'}).join(""):"<div class=\\"empty-state\\">No teammates yet.</div>";' +

'renderCalendarGrid();' +
'}' +

'function renderCalendarGrid(){' +
'var wrap=document.getElementById("calendar-wrap");' +
'if(!users.length){wrap.innerHTML="<div class=\\"empty-state\\">No teammates yet.</div>";return;}' +
'var start=todayStr();var days=[];for(var i=0;i<30;i++)days.push(addDays(start,i));' +
'var html="<table class=\\"cal-table\\"><thead><tr><th class=\\"user-col\\">Username</th>";' +
'days.forEach(function(d){var dt=new Date(d+"T00:00:00");var label=dt.toLocaleDateString("en-US",{day:"numeric",month:"short"});html+="<th class=\\""+(d===start?"today-col":"")+"\\">"+label+"</th>";});' +
'html+="</tr></thead><tbody>";' +
'users.forEach(function(u){' +
'html+="<tr><td class=\\"user-col\\">"+escapeHtml(u.username)+"</td>";' +
'days.forEach(function(d){var s=statusOnDate(u.username,d);html+="<td class=\\""+(d===start?"today-col":"")+"\\"><span class=\\"cal-dot "+s+"\\" title=\\""+s+"\\"></span></td>";});' +
'html+="</tr>";' +
'});' +
'html+="</tbody></table>";' +
'wrap.innerHTML=html;' +
'}' +
'</script>' +
'</body></html>';
