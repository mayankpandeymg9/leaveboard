/**
 * LEAVE BOARD — Google Apps Script deployment, v3.
 * ----------------------------------------------------------------------
 * Roles:
 *   ADMIN    — the only role that can add/remove accounts (Team tab).
 *   LEAD     — in-app access is read-only: just the Present/Absent
 *              attendance view. Leads approve/reject leave entirely
 *              through the emailed Approve/Reject links, not in the app.
 *   EMPLOYEE — applies for leave, picking a specific Lead from a dropdown
 *              so that Lead (and only that Lead) gets the approval email.
 *
 * SETUP:
 * 1. Open your Google Sheet > Extensions > Apps Script.
 * 2. Delete everything, paste this whole file in, save.
 * 3. Function dropdown at top > select "seedFirstAdmin" > Run > authorize.
 *    Creates the first login: admin@company.com / changeme123
 * 4. Deploy > New deployment > gear icon > Web app.
 *      Execute as: Me
 *      Who has access: Anyone
 * 5. Copy the Web app URL — that's the whole app. Share it with your team.
 * 6. Log in as admin@company.com / changeme123, change that password
 *    (Account tab), then go to Team and add real Lead and Employee
 *    accounts. Employees can't apply for leave meaningfully until at
 *    least one Lead account exists (they need one to pick from).
 *
 * Editing this file later: Deploy > Manage deployments > pencil icon >
 * New version > Deploy. Saving alone does not update the live app.
 */

function doGet(e) {
  if (e.parameter && e.parameter.action) {
    return handleEmailDecision(e);
  }
  return HtmlService.createHtmlOutput(HTML_APP)
    .setTitle('Leave Board')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

/* ================= PASSWORD HASHING ================= */

function hashPassword(password, salt) {
  var raw = salt + '::' + password;
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, raw, Utilities.Charset.UTF_8);
  return bytes.map(function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}
function makeSalt() { return Utilities.getUuid(); }

/* ================= USERS ================= */

function getProps() { return PropertiesService.getScriptProperties(); }

function getUsers() {
  var raw = getProps().getProperty('users_v2');
  return raw ? JSON.parse(raw) : [];
}
function saveUsers(list) { getProps().setProperty('users_v2', JSON.stringify(list)); }

function findUserByEmail(email) {
  return getUsers().find(function (u) { return u.email.toLowerCase() === String(email).toLowerCase(); });
}
function findUserById(id) {
  return getUsers().find(function (u) { return u.id === id; });
}
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role };
}

/**
 * Run manually from the Apps Script editor's function dropdown, once,
 * to create the first login. Not callable from the web app itself.
 */
function seedFirstAdmin() {
  var users = getUsers();
  if (users.length) { Logger.log('Users already exist — skipping seed.'); return; }
  var salt = makeSalt();
  users.push({
    id: Utilities.getUuid(),
    name: 'Admin',
    email: 'admin@company.com',
    salt: salt,
    passwordHash: hashPassword('changeme123', salt),
    role: 'ADMIN',
    createdAt: new Date().toISOString()
  });
  saveUsers(users);
  Logger.log('Seeded first login — admin@company.com / changeme123. Change it after logging in.');
}

/* ================= SESSIONS ================= */

function getSessions() {
  var raw = getProps().getProperty('sessions_v2');
  return raw ? JSON.parse(raw) : {};
}
function saveSessions(map) { getProps().setProperty('sessions_v2', JSON.stringify(map)); }
var SESSION_LIFETIME_MS = 1000 * 60 * 60 * 24;

function createSession(user) {
  var sessions = getSessions();
  var now = Date.now();
  Object.keys(sessions).forEach(function (t) {
    if (now - sessions[t].createdAt > SESSION_LIFETIME_MS) delete sessions[t];
  });
  var token = Utilities.getUuid();
  sessions[token] = { userId: user.id, name: user.name, email: user.email, role: user.role, createdAt: now };
  saveSessions(sessions);
  return token;
}
function getSession(token) {
  if (!token) return null;
  var s = getSessions()[token];
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_LIFETIME_MS) return null;
  return s;
}
function requireSession(token) {
  var s = getSession(token);
  if (!s) throw new Error('Your session has expired. Please log in again.');
  return s;
}
function requireAdmin(token) {
  var s = requireSession(token);
  if (s.role !== 'ADMIN') throw new Error('Only an admin can do that.');
  return s;
}

/* ================= AUTH API ================= */

function login(email, password) {
  var user = findUserByEmail(email);
  if (!user) return { ok: false, error: 'Incorrect email or password.' };
  var hash = hashPassword(password, user.salt);
  if (hash !== user.passwordHash) return { ok: false, error: 'Incorrect email or password.' };
  var token = createSession(user);
  return { ok: true, token: token, user: publicUser(user) };
}
function logout(token) {
  var sessions = getSessions();
  delete sessions[token];
  saveSessions(sessions);
  return { ok: true };
}

/* ================= USER MANAGEMENT (Admin only) ================= */

function addUser(token, data) {
  requireAdmin(token);
  var name = String(data.name || '').trim();
  var email = String(data.email || '').trim();
  var password = String(data.password || '');
  var role = ['ADMIN', 'LEAD', 'EMPLOYEE'].indexOf(data.role) !== -1 ? data.role : 'EMPLOYEE';
  if (!name || !email || !password) throw new Error('Name, email, and password are required.');
  if (password.length < 4) throw new Error('Password must be at least 4 characters.');
  if (findUserByEmail(email)) throw new Error('That email is already registered.');

  var salt = makeSalt();
  var users = getUsers();
  users.push({
    id: Utilities.getUuid(), name: name, email: email, salt: salt,
    passwordHash: hashPassword(password, salt), role: role, createdAt: new Date().toISOString()
  });
  saveUsers(users);
  return users.map(publicUser);
}

function removeUser(token, id) {
  var session = requireAdmin(token);
  if (id === session.userId) throw new Error("You can't remove your own account.");
  var users = getUsers();
  var target = users.find(function (u) { return u.id === id; });
  if (!target) throw new Error('Account not found.');
  var adminCount = users.filter(function (u) { return u.role === 'ADMIN'; }).length;
  if (target.role === 'ADMIN' && adminCount <= 1) throw new Error('At least one admin account must remain.');
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

function getSheet() { return SpreadsheetApp.getActiveSpreadsheet().getSheets()[0]; }

function ensureColumns(sheet) {
  var lastCol = Math.max(sheet.getLastColumn(), 1);
  var header = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
  var required = ['Request ID', 'Name', 'Lead Email', 'Leave Type', 'Duration', 'Session', 'Start', 'End', 'Reason', 'Status', 'Detail', 'Updated At', 'Token'];
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
  var idCol = header.indexOf('Request ID'), nameCol = header.indexOf('Name'), leadCol = header.indexOf('Lead Email'),
      typeCol = header.indexOf('Leave Type'), durCol = header.indexOf('Duration'), sessCol = header.indexOf('Session'),
      startCol = header.indexOf('Start'), endCol = header.indexOf('End'), reasonCol = header.indexOf('Reason'),
      statusCol = header.indexOf('Status'), detailCol = header.indexOf('Detail'), updatedCol = header.indexOf('Updated At');
  var out = [];
  for (var i = 1; i < values.length; i++) {
    var row = values[i];
    if (!row[idCol]) continue;
    out.push({
      id: row[idCol], username: row[nameCol], leadEmail: row[leadCol],
      leaveType: row[typeCol], duration: row[durCol], session: row[sessCol] || null,
      start: fmtInputDate(row[startCol]), end: fmtInputDate(row[endCol]),
      reason: row[reasonCol], status: row[statusCol], detail: row[detailCol], updatedAt: row[updatedCol]
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
  if (data.leadEmail !== undefined) set('Lead Email', data.leadEmail);
  if (data.leaveType !== undefined) set('Leave Type', data.leaveType);
  if (data.duration !== undefined) set('Duration', data.duration);
  if (data.session !== undefined) set('Session', data.session);
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
    if (!data.leadEmail) throw new Error('Please select a team lead.');
    if (!data.start || !data.end) throw new Error('Start and end dates are required.');
    if (data.end < data.start) throw new Error("End date can't be before start date.");
    var lead = findUserByEmail(data.leadEmail);
    if (!lead || lead.role !== 'LEAD') throw new Error('Please select a valid team lead.');

    var sheet = getSheet();
    var header = ensureColumns(sheet);
    var id = Utilities.getUuid();
    var row = findOrCreateRow(sheet, header, id);
    var tok = getOrCreateToken(sheet, header, row);

    writeRow(sheet, header, row, {
      username: session.name, leadEmail: lead.email,
      leaveType: data.leaveType, duration: data.duration, session: data.duration === 'HALF' ? data.session : '',
      start: data.start, end: data.end, reason: data.reason,
      status: 'Pending', detail: 'Awaiting approval'
    });

    sendApprovalEmail({
      id: id, username: session.name, leadEmail: lead.email, leaveType: data.leaveType,
      duration: data.duration, session: data.session, start: data.start, end: data.end, reason: data.reason
    }, tok);

    return { ok: true, id: id };
  } finally {
    lock.releaseLock();
  }
}

/* ================= EMAIL APPROVAL (the only decision path) ================= */

function sendApprovalEmail(data, token) {
  var deploymentUrl = ScriptApp.getService().getUrl();
  var approveUrl = deploymentUrl + '?id=' + encodeURIComponent(data.id) + '&action=approve&token=' + token;
  var rejectUrl = deploymentUrl + '?id=' + encodeURIComponent(data.id) + '&action=reject&token=' + token;
  var dateLine = data.duration === 'HALF'
    ? esc(data.start) + ' (Half day \u2014 ' + esc(data.session) + ')'
    : esc(data.start) + ' to ' + esc(data.end);

  var html =
    '<div style="font-family:sans-serif; max-width:480px; margin:0 auto;">' +
    '<h2 style="color:#c47f1a;">New leave request</h2>' +
    '<p><b>' + esc(data.username) + '</b> requested <b>' + esc(data.leaveType) + '</b> leave for <b>' + dateLine + '</b>.</p>' +
    (data.reason ? '<p style="color:#555;">Reason: ' + esc(data.reason) + '</p>' : '') +
    '<div style="margin:24px 0;">' +
    '<a href="' + approveUrl + '" style="background:#2E9E82;color:#ffffff;padding:12px 26px;border-radius:6px;text-decoration:none;font-weight:bold;margin-right:12px;display:inline-block;">Approve</a>' +
    '<a href="' + rejectUrl + '" style="background:#E0584D;color:#ffffff;padding:12px 26px;border-radius:6px;text-decoration:none;font-weight:bold;display:inline-block;">Reject</a>' +
    '</div>' +
    '<p style="color:#999; font-size:12px;">One click records your decision directly in the leave sheet. This request was sent to you because ' + esc(data.username) + ' selected you as their team lead.</p>' +
    '</div>';

  MailApp.sendEmail({ to: data.leadEmail, subject: 'Leave request from ' + data.username, htmlBody: html });
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
        startCol = header.indexOf('Start'), endCol = header.indexOf('End'), leadCol = header.indexOf('Lead Email');

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
  var users = getUsers();
  return {
    leaves: getAllLeaves(),
    users: users.map(publicUser),
    leads: users.filter(function (u) { return u.role === 'LEAD'; }).map(publicUser),
    currentUser: user ? publicUser(user) : null
  };
}

/* ================= FRONT-END APP (served as the whole page) ================= */

var HTML_APP = '<!DOCTYPE html><html><head><base target="_top">' +
'<meta charset="UTF-8">' +
'<style>' +
"@import url('https://fonts.googleapis.com/css2?family=Oswald:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');" +
':root{--board-bg:#14181F;--panel:#1C222C;--panel-raised:#232B37;--amber:#F2A93B;--amber-dim:#8a6323;--off-white:#EDEAE0;--muted:#8791A0;--teal:#2E9E82;--teal-dim:#163B32;--red:#E0584D;--red-dim:#3A1E1C;--violet:#8A7CDB;--violet-dim:#2A2440;--line:#2C3440;font-family:"Inter",sans-serif;}' +
'*{box-sizing:border-box;}' +
'body{margin:0;background:var(--board-bg);color:var(--off-white);min-height:100vh;padding:28px 20px 60px;}' +
'.wrap{max-width:1120px;margin:0 auto;}' +
'.center-wrap{max-width:380px;margin:90px auto;}' +
'.eyebrow{font-family:"Space Mono",monospace;font-size:11px;letter-spacing:2px;color:var(--muted);text-transform:uppercase;margin-bottom:6px;}' +
'h1{font-family:"Oswald",sans-serif;font-weight:700;font-size:36px;letter-spacing:1px;margin:0;color:var(--amber);text-shadow:0 0 18px rgba(242,169,59,0.25);}' +
'h1.lead-title{color:var(--teal);text-shadow:0 0 18px rgba(46,158,130,0.25);}' +
'h1.admin-title{color:var(--violet);text-shadow:0 0 18px rgba(138,124,219,0.25);}' +
'.board-header{background:linear-gradient(180deg,#191F28,#12161D);border:1px solid var(--line);border-radius:10px;padding:22px 26px;margin-bottom:22px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;}' +
'.board-header.lead{border-color:#1f3d36;background:linear-gradient(180deg,#131c1a,#0f1614);}' +
'.board-header.admin{border-color:#2c2650;background:linear-gradient(180deg,#18142b,#120f20);}' +
'.signed-in{font-family:"Space Mono",monospace;font-size:12px;color:var(--muted);text-align:right;}' +
'.signed-in .who{color:var(--off-white);}' +
'.signed-in a{color:var(--muted);text-decoration:underline;cursor:pointer;}' +
'.role-pill{font-family:"Space Mono",monospace;font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:3px 9px;border-radius:999px;margin-left:6px;}' +
'.role-pill.lead{border:1px solid var(--teal);color:var(--teal);background:var(--teal-dim);}' +
'.role-pill.admin{border:1px solid var(--violet);color:var(--violet);background:var(--violet-dim);}' +
'.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:24px;margin-bottom:22px;}' +
'.panel h2{font-family:"Oswald",sans-serif;font-size:20px;margin:0 0 4px;}' +
'.panel .sub{color:var(--muted);font-size:13px;margin:0 0 18px;}' +
'label{display:block;font-size:12px;letter-spacing:0.5px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;font-weight:600;}' +
'input[type=text],input[type=email],input[type=password],textarea,select{width:100%;background:var(--panel-raised);border:1px solid var(--line);border-radius:6px;color:var(--off-white);padding:10px 12px;font-size:14px;font-family:"Inter",sans-serif;outline:none;}' +
'input:focus,textarea:focus,select:focus{border-color:var(--amber);}' +
'input.error{border-color:var(--red);}' +
'textarea{resize:vertical;min-height:60px;}' +
'.field-err{color:var(--red);font-size:12px;margin-top:5px;display:none;}' +
'.field-err.show{display:block;}' +
'.btn{font-family:"Oswald",sans-serif;letter-spacing:0.5px;font-size:14px;font-weight:600;padding:11px 22px;border-radius:6px;border:none;cursor:pointer;}' +
'.btn-primary{background:var(--amber);color:#14181F;}' +
'.btn-lead{background:var(--teal);color:#fff;}' +
'.btn-admin{background:var(--violet);color:#fff;}' +
'.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--line);}' +
'.btn-ghost:hover{color:var(--off-white);border-color:var(--muted);}' +
'.btn:disabled{opacity:0.4;cursor:not-allowed;}' +
'.btn-block{width:100%;}' +
'.login-hint{text-align:center;color:var(--muted);font-size:12px;margin-top:16px;font-family:"Space Mono",monospace;line-height:1.6;}' +
'.role-toggle{display:flex;gap:2px;background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:4px;width:fit-content;margin:0 auto 24px;}' +
'.role-toggle button{font-family:"Oswald",sans-serif;letter-spacing:0.5px;font-size:14px;padding:9px 22px;border-radius:999px;border:none;background:transparent;color:var(--muted);cursor:pointer;}' +
'.role-toggle button.active{background:var(--amber);color:#14181F;font-weight:600;}' +
'.side-shell{display:flex;gap:20px;align-items:flex-start;}' +
'.sidebar{width:190px;flex-shrink:0;border-radius:10px;padding:14px;position:sticky;top:20px;}' +
'.sidebar.lead{background:var(--panel);border:1px solid #1f3d36;}' +
'.sidebar.admin{background:var(--panel);border:1px solid #2c2650;}' +
'.sidebar button{display:flex;align-items:center;gap:8px;width:100%;text-align:left;padding:11px 12px;margin-bottom:4px;border-radius:8px;background:transparent;border:none;color:var(--muted);font-family:"Oswald",sans-serif;font-size:14px;letter-spacing:0.4px;cursor:pointer;}' +
'.sidebar.lead button.active{background:var(--teal-dim);color:var(--teal);font-weight:600;}' +
'.sidebar.admin button.active{background:var(--violet-dim);color:var(--violet);font-weight:600;}' +
'.sidebar button:hover:not(.active){color:var(--off-white);}' +
'.side-main{flex:1;min-width:0;}' +
'@media (max-width:760px){.side-shell{flex-direction:column;}.sidebar{width:100%;position:static;display:flex;flex-wrap:wrap;gap:4px;}.sidebar button{width:auto;flex:1;justify-content:center;}}' +
'.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}' +
'.form-grid .full{grid-column:1/-1;}' +
'.checkbox-row{display:flex;align-items:center;gap:10px;padding:10px 0 0;}' +
'.checkbox-row input[type=checkbox]{width:16px;height:16px;accent-color:var(--amber);}' +
'.checkbox-row label{margin:0;text-transform:none;font-size:14px;color:var(--off-white);font-weight:500;letter-spacing:0;}' +
'.form-actions{grid-column:1/-1;display:flex;align-items:center;gap:14px;margin-top:4px;}' +
'.toast{font-size:13px;color:var(--teal);font-family:"Space Mono",monospace;opacity:0;transition:opacity .25s;}' +
'.toast.show{opacity:1;}' +
'.badge{font-family:"Space Mono",monospace;font-size:11px;letter-spacing:1px;text-transform:uppercase;padding:4px 10px;border-radius:4px;display:inline-block;white-space:nowrap;}' +
'.badge.Pending{background:rgba(242,169,59,0.12);color:var(--amber);border:1px solid var(--amber-dim);}' +
'.badge.Approved{background:var(--teal-dim);color:var(--teal);border:1px solid var(--teal);}' +
'.badge.Rejected{background:var(--red-dim);color:var(--red);border:1px solid var(--red);}' +
'.leave-tag{font-family:"Space Mono",monospace;font-size:10px;letter-spacing:0.5px;padding:2px 7px;border-radius:3px;border:1px solid var(--line);color:var(--off-white);display:inline-block;margin-left:6px;vertical-align:middle;}' +
'.leave-tag.SL{border-color:#7C6FD9;color:#B7ADF2;}' +
'.leave-tag.CL{border-color:#3E9BD9;color:#9CD3F2;}' +
'.leave-tag.EL{border-color:#4FAE7A;color:#A9E3C4;}' +
'.request-row{display:grid;grid-template-columns:1fr auto;align-items:center;gap:14px;padding:14px 4px;border-bottom:1px solid var(--line);}' +
'.request-row:last-child{border-bottom:none;}' +
'.req-who{font-weight:600;font-family:"Oswald",sans-serif;letter-spacing:0.4px;}' +
'.req-dates{color:var(--muted);font-size:12.5px;font-family:"Space Mono",monospace;}' +
'.req-reason{color:var(--muted);font-size:13px;margin-top:2px;}' +
'.empty-state{text-align:center;padding:30px 10px;color:var(--muted);font-size:13.5px;}' +
'.date-picker-row{display:flex;align-items:center;gap:14px;margin-bottom:20px;flex-wrap:wrap;}' +
'.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px;}' +
'.stat-card{background:linear-gradient(180deg,#202834,#171D26);border:1px solid var(--line);border-radius:8px;padding:16px 18px;}' +
'.stat-card.highlight{border-color:var(--amber-dim);background:linear-gradient(180deg,#262014,#1A1610);}' +
'.stat-num{font-family:"Oswald",sans-serif;font-weight:700;font-size:40px;line-height:1;color:var(--amber);}' +
'.stat-card:not(.highlight) .stat-num{color:var(--off-white);}' +
'.stat-label{font-family:"Space Mono",monospace;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-top:4px;}' +
'.flap-table{border:1px solid var(--line);border-radius:8px;overflow:hidden;}' +
'.flap-head{display:grid;grid-template-columns:110px 1.3fr 1fr 1fr;background:#10141B;padding:10px 16px;font-family:"Space Mono",monospace;font-size:11px;letter-spacing:1.5px;color:var(--muted);text-transform:uppercase;border-bottom:1px solid var(--line);}' +
'.flap-row{display:grid;grid-template-columns:110px 1.3fr 1fr 1fr;align-items:center;padding:14px 16px;background:var(--panel-raised);border-bottom:1px solid var(--line);}' +
'.flap-row:last-child{border-bottom:none;}' +
'.flap-status{font-family:"Oswald",sans-serif;font-weight:600;letter-spacing:1px;font-size:13px;}' +
'.flap-status.absent{color:var(--red);}' +
'.flap-status.half{color:var(--amber);}' +
'.flap-status.pending{color:var(--amber);}' +
'.flap-status.present{color:var(--teal);}' +
'.flap-user{font-family:"Oswald",sans-serif;font-size:16px;letter-spacing:0.5px;}' +
'.flap-dates,.flap-reason{font-size:13px;color:var(--muted);font-family:"Space Mono",monospace;}' +
'.flap-reason{font-family:"Inter",sans-serif;}' +
'.access-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 4px;border-bottom:1px solid var(--line);}' +
'.access-row:last-child{border-bottom:none;}' +
'.access-name{font-family:"Oswald",sans-serif;font-weight:600;}' +
'.access-meta{font-family:"Space Mono",monospace;font-size:11px;color:var(--muted);}' +
'.picker-wrap{position:relative;}' +
'.picker-btn{width:100%;text-align:left;background:var(--panel-raised);border:1px solid var(--line);border-radius:6px;color:var(--off-white);padding:10px 12px;font-size:14px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;}' +
'.picker-btn.error{border-color:var(--red);}' +
'.picker-btn.placeholder{color:var(--muted);}' +
'.picker-btn:disabled{opacity:0.5;cursor:not-allowed;}' +
'.picker-pop{position:absolute;z-index:30;margin-top:6px;background:var(--panel-raised);border:1px solid var(--line);border-radius:10px;padding:12px;width:260px;font-family:"Space Mono",monospace;}' +
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
'.calendar-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel-raised);}' +
'.cal-table{border-collapse:collapse;width:max-content;}' +
'.cal-table th,.cal-table td{padding:7px 9px;text-align:center;font-family:"Space Mono",monospace;font-size:11px;border-bottom:1px solid var(--line);border-right:1px solid var(--line);white-space:nowrap;}' +
'.cal-table th{background:#10141B;color:var(--muted);font-weight:400;}' +
'.cal-table th.today-col,.cal-table td.today-col{background:rgba(242,169,59,0.08);}' +
'.cal-table .user-col{position:sticky;left:0;background:var(--panel-raised);text-align:left;font-family:"Oswald",sans-serif;font-size:13px;min-width:150px;}' +
'.cal-table th.user-col{background:#10141B;}' +
'.cal-dot{width:9px;height:9px;border-radius:50%;display:inline-block;}' +
'.cal-dot.absent{background:var(--red);}' +
'.cal-dot.half{background:var(--amber);}' +
'.cal-dot.pending{background:var(--amber);opacity:0.5;}' +
'.cal-dot.present{background:var(--line);}' +
'.foot-note{text-align:center;color:var(--muted);font-size:12px;margin-top:26px;font-family:"Space Mono",monospace;}' +
'@media (max-width:640px){.form-grid{grid-template-columns:1fr;}.flap-head,.flap-row{grid-template-columns:70px 1fr 1fr;}.flap-head .col-reason,.flap-row .flap-reason{display:none;}h1{font-size:28px;}.request-row{grid-template-columns:1fr;}.picker-pop{width:230px;}}' +
'</style></head><body>' +

'<div class="center-wrap" id="login-screen">' +
'<div style="text-align:center;margin-bottom:26px;"><div class="eyebrow">Team Attendance</div><h1>LEAVE BOARD</h1></div>' +
'<div class="panel">' +
'<div><label>Email</label><input type="email" id="login-email" autocomplete="username"></div>' +
'<div style="margin-top:14px;"><label>Password</label><input type="password" id="login-password" autocomplete="current-password"></div>' +
'<div class="field-err" id="login-err" style="margin-top:10px;"></div>' +
'<button class="btn btn-primary btn-block" id="login-btn" style="margin-top:16px;">Sign in</button>' +
'</div>' +
'<p class="login-hint" id="login-hint"></p>' +
'</div>' +

'<div class="wrap" id="employee-shell" style="display:none;">' +
'<div class="board-header"><div><div class="eyebrow">Team Attendance · Live</div><h1>LEAVE BOARD</h1></div><div class="signed-in" id="emp-signed-in"></div></div>' +
'<div class="role-toggle"><button id="emp-tab-apply" class="active">Apply</button><button id="emp-tab-dashboard">Dashboard</button><button id="emp-tab-account">Account</button></div>' +
'<div class="panel" id="emp-view-apply">' +
'<h2>Request time off</h2><p class="sub">Applying as <span id="emp-apply-name" style="color:var(--off-white);"></span>. Pick your lead, leave type, and dates.</p>' +
'<div class="form-grid">' +
'<div class="full"><label>Send this request to *</label><select id="f-lead"></select><div class="field-err" id="err-lead">Select which team lead should receive this request.</div></div>' +
'<div><label>Leave type *</label><select id="f-leavetype"><option value="SL">SL \u2014 Sick Leave</option><option value="CL">CL \u2014 Casual Leave</option><option value="EL">EL \u2014 Earned Leave</option></select></div>' +
'<div><div class="checkbox-row" style="padding-top:26px;"><input type="checkbox" id="f-halfday"><label for="f-halfday">Half day leave</label></div></div>' +
'<div id="halfday-session-wrap" class="full" style="display:none;"><label>Half day session</label><select id="f-session"><option value="AM">Morning (AM)</option><option value="PM">Afternoon (PM)</option></select></div>' +
'<div><label>Start date *</label><div class="picker-wrap" id="picker-start"></div><div class="field-err" id="err-start">Pick a start date.</div></div>' +
'<div><label>End date *</label><div class="picker-wrap" id="picker-end"></div><div class="field-err" id="err-end">End date can\'t be before the start date.</div></div>' +
'<div class="full"><label>Reason (optional)</label><textarea id="f-reason"></textarea></div>' +
'<div class="form-actions"><button class="btn btn-primary" id="btn-submit">Submit request</button><span class="toast" id="submit-toast">\u2713 Sent to your lead for approval</span></div>' +
'</div></div>' +
'<div class="panel" id="emp-view-myrequests"><h2>My requests</h2><p class="sub">Everything you\'ve submitted and its current status.</p><div id="my-requests-list"></div></div>' +
'<div class="panel" id="emp-view-dashboard" style="display:none;"></div>' +
'<div class="panel" id="emp-view-account" style="display:none;"></div>' +
'<div class="foot-note">Leave only counts as taken once your selected lead approves it via email.</div>' +
'</div>' +

'<div class="wrap" id="lead-shell" style="display:none;">' +
'<div class="board-header lead"><div><div class="eyebrow">Lead Console</div><h1 class="lead-title">LEAVE BOARD</h1></div><div class="signed-in" id="lead-signed-in"></div></div>' +
'<div class="side-shell"><div class="sidebar lead" id="lead-sidebar"><button data-lead-tab="attendance" class="active">\ud83d\udcc5 Attendance</button><button data-lead-tab="account">\u2699\ufe0f Account</button></div>' +
'<div class="side-main"><div class="panel" id="lead-view-attendance"></div><div class="panel" id="lead-view-account" style="display:none;"></div></div></div>' +
'<div class="foot-note">Approvals happen from your email — this view is read-only.</div>' +
'</div>' +

'<div class="wrap" id="admin-shell" style="display:none;">' +
'<div class="board-header admin"><div><div class="eyebrow">Admin Console</div><h1 class="admin-title">LEAVE BOARD</h1></div><div class="signed-in" id="admin-signed-in"></div></div>' +
'<div class="side-shell"><div class="sidebar admin" id="admin-sidebar"><button data-admin-tab="team" class="active">\ud83d\udc65 Team</button><button data-admin-tab="attendance">\ud83d\udcc5 Attendance</button><button data-admin-tab="account">\u2699\ufe0f Account</button></div>' +
'<div class="side-main"><div class="panel" id="admin-view-team"></div><div class="panel" id="admin-view-attendance" style="display:none;"></div><div class="panel" id="admin-view-account" style="display:none;"></div></div></div>' +
'<div class="foot-note">Only admins can add or remove accounts.</div>' +
'</div>' +

'<script>' +
'var TOKEN=null;var CURRENT_USER=null;var leaves=[];var users=[];var leads=[];' +

'function onError(err){alert("Something went wrong: " + (err && err.message ? err.message : err));}' +
'function escapeHtml(str){var d=document.createElement("div");d.textContent=str;return d.innerHTML;}' +

'function pad2(n){return (n<10?"0":"")+n;}' +
'function toISO(y,m,d){return y+"-"+pad2(m+1)+"-"+pad2(d);}' +
'function todayStr(){var d=new Date();return toISO(d.getFullYear(),d.getMonth(),d.getDate());}' +
'function addDays(dateStr,n){var d=new Date(dateStr+"T00:00:00");d.setDate(d.getDate()+n);return toISO(d.getFullYear(),d.getMonth(),d.getDate());}' +
'function fmt(dateStr){if(!dateStr)return"";var d=new Date(dateStr+"T00:00:00");return d.toLocaleDateString("en-US",{month:"short",day:"numeric",year:"numeric"});}' +
'var MONTH_NAMES=["January","February","March","April","May","June","July","August","September","October","November","December"];' +
'var DOW=["S","M","T","W","T","F","S"];' +

'function makeDatePicker(container,opts){' +
'var state={value:opts.value||"",minDate:opts.minDate||null,open:false};' +
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
'b.onclick=function(){state.value=b.getAttribute("data-date");renderBtn();pop.style.display="none";if(opts.onChange)opts.onChange(state.value);};' +
'});' +
'}' +
'function renderBtn(){' +
'if(state.value){btn.textContent=fmt(state.value);btn.classList.remove("placeholder");}' +
'else{btn.textContent="Select a date";btn.classList.add("placeholder");}' +
'}' +
'btn.onclick=function(e){if(btn.disabled)return;e.stopPropagation();var willOpen=pop.style.display!=="block";pop.style.display=willOpen?"block":"none";if(willOpen)renderPop();};' +
'document.addEventListener("click",function(e){if(!container.contains(e.target))pop.style.display="none";});' +
'renderBtn();' +
'return{' +
'getValue:function(){return state.value;},' +
'setValue:function(v){state.value=v;renderBtn();},' +
'setMinDate:function(v){state.minDate=v;},' +
'setError:function(hasError){btn.classList.toggle("error",!!hasError);},' +
'setDisabled:function(d){btn.disabled=d;}' +
'};' +
'}' +
'document.getElementById("login-btn").onclick=function(){' +
'var email=document.getElementById("login-email").value.trim();' +
'var password=document.getElementById("login-password").value;' +
'var errEl=document.getElementById("login-err");errEl.classList.remove("show");errEl.textContent="";' +
'if(!email||!password){errEl.textContent="Enter both an email and password.";errEl.classList.add("show");return;}' +
'var btn=document.getElementById("login-btn");btn.disabled=true;btn.textContent="Signing in\u2026";' +
'google.script.run.withSuccessHandler(function(res){' +
'btn.disabled=false;btn.textContent="Sign in";' +
'if(res.ok){TOKEN=res.token;CURRENT_USER=res.user;enterApp();}' +
'else{errEl.textContent=res.error;errEl.classList.add("show");}' +
'}).withFailureHandler(function(err){btn.disabled=false;btn.textContent="Sign in";onError(err);}).login(email,password);' +
'};' +
'document.getElementById("login-password").addEventListener("keydown",function(e){if(e.key==="Enter")document.getElementById("login-btn").click();});' +

'function signOutNow(){' +
'if(TOKEN)google.script.run.logout(TOKEN);' +
'TOKEN=null;CURRENT_USER=null;' +
'["employee-shell","lead-shell","admin-shell"].forEach(function(id){document.getElementById(id).style.display="none";});' +
'document.getElementById("login-screen").style.display="block";' +
'document.getElementById("login-email").value="";' +
'document.getElementById("login-password").value="";' +
'}' +

'var pickerStart=null,pickerEnd=null;' +

'function enterApp(){' +
'document.getElementById("login-screen").style.display="none";' +
'google.script.run.withSuccessHandler(function(data){' +
'leaves=data.leaves;users=data.users;leads=data.leads;CURRENT_USER=data.currentUser;' +
'if(CURRENT_USER.role==="ADMIN"){showAdminShell();}' +
'else if(CURRENT_USER.role==="LEAD"){showLeadShell();}' +
'else{showEmployeeShell();}' +
'}).withFailureHandler(onError).getBootstrapData(TOKEN);' +
'}' +

'function refresh(cb){' +
'google.script.run.withSuccessHandler(function(data){' +
'leaves=data.leaves;users=data.users;leads=data.leads;CURRENT_USER=data.currentUser;' +
'if(cb)cb();' +
'}).withFailureHandler(function(err){if(err&&err.message&&err.message.indexOf("expired")!==-1){signOutNow();}else{onError(err);}}).getBootstrapData(TOKEN);' +
'}' +

'function showEmployeeShell(){' +
'document.getElementById("lead-shell").style.display="none";' +
'document.getElementById("admin-shell").style.display="none";' +
'document.getElementById("employee-shell").style.display="block";' +
'document.getElementById("emp-signed-in").innerHTML="Signed in as <span class=\\"who\\">"+escapeHtml(CURRENT_USER.name)+"</span><br><a onclick=\\"signOutNow()\\">Sign out</a>";' +
'document.getElementById("emp-apply-name").textContent=CURRENT_USER.name;' +
'populateLeadDropdown();' +
'if(!pickerStart){' +
'pickerStart=makeDatePicker(document.getElementById("picker-start"),{onChange:function(v){if(document.getElementById("f-halfday").checked)pickerEnd.setValue(v);pickerEnd.setMinDate(v);}});' +
'pickerEnd=makeDatePicker(document.getElementById("picker-end"),{});' +
'}' +
'setEmpTab("apply");' +
'}' +
'function showLeadShell(){' +
'document.getElementById("employee-shell").style.display="none";' +
'document.getElementById("admin-shell").style.display="none";' +
'document.getElementById("lead-shell").style.display="block";' +
'document.getElementById("lead-signed-in").innerHTML="<span class=\\"who\\">"+escapeHtml(CURRENT_USER.name)+"</span><span class=\\"role-pill lead\\">Lead</span><br><a onclick=\\"signOutNow()\\">Sign out</a>";' +
'setLeadTab("attendance");' +
'}' +
'function showAdminShell(){' +
'document.getElementById("employee-shell").style.display="none";' +
'document.getElementById("lead-shell").style.display="none";' +
'document.getElementById("admin-shell").style.display="block";' +
'document.getElementById("admin-signed-in").innerHTML="<span class=\\"who\\">"+escapeHtml(CURRENT_USER.name)+"</span><span class=\\"role-pill admin\\">Admin</span><br><a onclick=\\"signOutNow()\\">Sign out</a>";' +
'setAdminTab("team");' +
'}' +

'function populateLeadDropdown(){' +
'var sel=document.getElementById("f-lead");' +
'sel.innerHTML=leads.length?leads.map(function(l){return "<option value=\\""+escapeHtml(l.email)+"\\">"+escapeHtml(l.name)+" ("+escapeHtml(l.email)+")</option>";}).join(""):"<option value=\\"\\">No leads have been added yet</option>";' +
'}' +
'var empTabs={apply:document.getElementById("emp-tab-apply"),dashboard:document.getElementById("emp-tab-dashboard"),account:document.getElementById("emp-tab-account")};' +
'function setEmpTab(name){' +
'Object.keys(empTabs).forEach(function(k){empTabs[k].classList.remove("active");});' +
'empTabs[name].classList.add("active");' +
'document.getElementById("emp-view-apply").style.display=name==="apply"?"block":"none";' +
'document.getElementById("emp-view-myrequests").style.display=name==="apply"?"block":"none";' +
'document.getElementById("emp-view-dashboard").style.display=name==="dashboard"?"block":"none";' +
'document.getElementById("emp-view-account").style.display=name==="account"?"block":"none";' +
'if(name==="apply")renderMyRequests();' +
'if(name==="dashboard")renderAttendancePanel(document.getElementById("emp-view-dashboard"),"emp");' +
'if(name==="account")renderAccountPanel(document.getElementById("emp-view-account"));' +
'}' +
'empTabs.apply.onclick=function(){setEmpTab("apply");};' +
'empTabs.dashboard.onclick=function(){setEmpTab("dashboard");};' +
'empTabs.account.onclick=function(){setEmpTab("account");};' +

'document.getElementById("f-halfday").addEventListener("change",function(){' +
'var isHalf=document.getElementById("f-halfday").checked;' +
'document.getElementById("halfday-session-wrap").style.display=isHalf?"block":"none";' +
'pickerEnd.setDisabled(isHalf);' +
'if(isHalf){var sv=pickerStart.getValue();if(sv)pickerEnd.setValue(sv);}' +
'});' +

'document.getElementById("btn-submit").onclick=function(){' +
'var valid=true;' +
'pickerStart.setError(false);pickerEnd.setError(false);' +
'["err-lead","err-start","err-end"].forEach(function(id){document.getElementById(id).classList.remove("show");});' +
'var leadEmail=document.getElementById("f-lead").value;' +
'var isHalf=document.getElementById("f-halfday").checked;' +
'var start=pickerStart.getValue();' +
'var end=isHalf?start:pickerEnd.getValue();' +
'if(!leadEmail){document.getElementById("err-lead").classList.add("show");valid=false;}' +
'if(!start){pickerStart.setError(true);document.getElementById("err-start").classList.add("show");valid=false;}' +
'if(!end||(start&&end<start)){pickerEnd.setError(true);document.getElementById("err-end").classList.add("show");valid=false;}' +
'if(!valid)return;' +
'var payload={leadEmail:leadEmail,leaveType:document.getElementById("f-leavetype").value,duration:isHalf?"HALF":"FULL",session:isHalf?document.getElementById("f-session").value:null,start:start,end:end,reason:document.getElementById("f-reason").value.trim()};' +
'var btn=document.getElementById("btn-submit");btn.disabled=true;' +
'google.script.run.withSuccessHandler(function(){' +
'btn.disabled=false;' +
'document.getElementById("f-reason").value="";' +
'document.getElementById("f-halfday").checked=false;' +
'document.getElementById("halfday-session-wrap").style.display="none";' +
'pickerStart.setValue("");pickerEnd.setValue("");pickerEnd.setDisabled(false);' +
'var t=document.getElementById("submit-toast");t.classList.add("show");setTimeout(function(){t.classList.remove("show");},2400);' +
'refresh(function(){renderMyRequests();});' +
'}).withFailureHandler(function(err){btn.disabled=false;onError(err);}).submitLeaveRequest(TOKEN,payload);' +
'};' +

'function leaveTagHtml(l){return "<span class=\\"leave-tag "+l.leaveType+"\\">"+l.leaveType+(l.duration==="HALF"?" \u00b7 "+l.session:"")+"</span>";}' +

'function renderMyRequests(){' +
'var list=document.getElementById("my-requests-list");if(!CURRENT_USER)return;' +
'var mine=leaves.filter(function(l){return l.username===CURRENT_USER.name;}).slice().reverse();' +
'list.innerHTML=mine.length?mine.map(function(l){return ' +
'"<div class=\\"request-row\\"><div><div class=\\"req-who\\">"+(l.duration==="HALF"?fmt(l.start)+" (Half Day \u00b7 "+l.session+")":fmt(l.start)+" \u2192 "+fmt(l.end))+" "+leaveTagHtml(l)+"</div><div class=\\"req-dates\\">Sent to "+escapeHtml(l.leadEmail||"")+"</div>"+(l.reason?"<div class=\\"req-reason\\">"+escapeHtml(l.reason)+"</div>":"")+"</div><span class=\\"badge "+l.status+"\\">"+l.status+"</span></div>";' +
'}).join(""):"<div class=\\"empty-state\\">You haven\'t submitted any requests yet.</div>";' +
'}' +
'document.querySelectorAll("#lead-sidebar button").forEach(function(btn){btn.onclick=function(){setLeadTab(btn.getAttribute("data-lead-tab"));};});' +
'function setLeadTab(name){' +
'document.querySelectorAll("#lead-sidebar button").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-lead-tab")===name);});' +
'["attendance","account"].forEach(function(n){document.getElementById("lead-view-"+n).style.display=n===name?"block":"none";});' +
'if(name==="attendance")renderAttendancePanel(document.getElementById("lead-view-attendance"),"lead");' +
'if(name==="account")renderAccountPanel(document.getElementById("lead-view-account"));' +
'}' +

'document.querySelectorAll("#admin-sidebar button").forEach(function(btn){btn.onclick=function(){setAdminTab(btn.getAttribute("data-admin-tab"));};});' +
'function setAdminTab(name){' +
'document.querySelectorAll("#admin-sidebar button").forEach(function(b){b.classList.toggle("active",b.getAttribute("data-admin-tab")===name);});' +
'["team","attendance","account"].forEach(function(n){document.getElementById("admin-view-"+n).style.display=n===name?"block":"none";});' +
'if(name==="team")renderTeamManagement();' +
'if(name==="attendance")renderAttendancePanel(document.getElementById("admin-view-attendance"),"admin");' +
'if(name==="account")renderAccountPanel(document.getElementById("admin-view-account"));' +
'}' +

'function renderTeamManagement(){' +
'var host=document.getElementById("admin-view-team");' +
'host.innerHTML="<h2>Team directory</h2><p class=\\"sub\\">Only admins can add or remove accounts here. Roles: Admin, Lead, Employee.</p>"+' +
'"<div class=\\"form-grid\\">"+' +
'"<div><label>Name</label><input type=\\"text\\" id=\\"team-name\\"></div>"+' +
'"<div><label>Email</label><input type=\\"email\\" id=\\"team-email\\"></div>"+' +
'"<div><label>Temporary password</label><input type=\\"text\\" id=\\"team-password\\"></div>"+' +
'"<div><label>Role</label><select id=\\"team-role\\"><option value=\\"EMPLOYEE\\">Employee</option><option value=\\"LEAD\\">Lead</option><option value=\\"ADMIN\\">Admin</option></select></div>"+' +
'"<div class=\\"form-actions\\"><button class=\\"btn btn-admin\\" id=\\"team-add-btn\\">Add account</button><span class=\\"toast\\" id=\\"team-toast\\" style=\\"color:var(--red);\\"></span></div>"+' +
'"</div><div id=\\"team-list\\" style=\\"margin-top:18px;\\"></div>";' +

'function renderList(){' +
'var list=host.querySelector("#team-list");' +
'list.innerHTML=users.map(function(u){return ' +
'"<div class=\\"access-row\\"><div><div class=\\"access-name\\">"+escapeHtml(u.name)+(u.id===CURRENT_USER.id?" <span style=\\"color:var(--muted);font-size:11px;\\">(you)</span>":"")+"</div><div class=\\"access-meta\\">"+escapeHtml(u.email)+" \u00b7 "+u.role+"</div></div>"+' +
'(u.id!==CURRENT_USER.id?"<button class=\\"btn btn-ghost\\" style=\\"padding:6px 12px;font-size:11px;\\" data-remove=\\""+u.id+"\\">Remove</button>":"")+' +
'"</div>";' +
'}).join("");' +
'list.querySelectorAll("[data-remove]").forEach(function(btn){' +
'btn.onclick=function(){' +
'var id=btn.getAttribute("data-remove");' +
'google.script.run.withSuccessHandler(function(){refresh(function(){renderTeamManagement();});}).withFailureHandler(onError).removeUser(TOKEN,id);' +
'};' +
'});' +
'}' +
'renderList();' +

'host.querySelector("#team-add-btn").onclick=function(){' +
'var name=host.querySelector("#team-name").value.trim();' +
'var email=host.querySelector("#team-email").value.trim();' +
'var password=host.querySelector("#team-password").value;' +
'var role=host.querySelector("#team-role").value;' +
'var toast=host.querySelector("#team-toast");toast.textContent="";' +
'if(!name||!email||!password){toast.textContent="Name, email, and password are required.";return;}' +
'google.script.run.withSuccessHandler(function(){' +
'host.querySelector("#team-name").value="";host.querySelector("#team-email").value="";host.querySelector("#team-password").value="";' +
'refresh(function(){renderTeamManagement();});' +
'}).withFailureHandler(function(err){toast.textContent=err&&err.message?err.message:"Something went wrong.";}).addUser(TOKEN,{name:name,email:email,password:password,role:role});' +
'};' +
'}' +

'function renderAccountPanel(host){' +
'host.innerHTML="<h2>Account</h2><p class=\\"sub\\">Change your own password.</p>"+' +
'"<div class=\\"form-grid\\">"+' +
'"<div><label>Current password</label><input type=\\"password\\" id=\\"pw-current\\"></div>"+' +
'"<div><label>New password</label><input type=\\"password\\" id=\\"pw-new\\"></div>"+' +
'"<div class=\\"form-actions\\"><button class=\\"btn btn-primary\\" id=\\"pw-save\\">Update password</button><span id=\\"pw-status\\" style=\\"font-size:12.5px;color:var(--muted);font-family:\'Space Mono\',monospace;\\"></span></div>"+' +
'"</div>";' +
'host.querySelector("#pw-save").onclick=function(){' +
'var cur=host.querySelector("#pw-current").value,nw=host.querySelector("#pw-new").value;' +
'var statusEl=host.querySelector("#pw-status");' +
'google.script.run.withSuccessHandler(function(){' +
'statusEl.style.color="var(--teal)";statusEl.textContent="\u2713 Password updated.";' +
'host.querySelector("#pw-current").value="";host.querySelector("#pw-new").value="";' +
'}).withFailureHandler(function(err){statusEl.style.color="var(--red)";statusEl.textContent=err&&err.message?err.message:"Something went wrong.";}).changeOwnPassword(TOKEN,cur,nw);' +
'};' +
'}' +
'function statusOnDate(username,dateStr){' +
'var mine=leaves.filter(function(l){return l.username.toLowerCase()===username.toLowerCase();});' +
'if(mine.some(function(l){return l.status==="Approved"&&l.duration==="FULL"&&l.start<=dateStr&&dateStr<=l.end;}))return{state:"absent"};' +
'var half=mine.filter(function(l){return l.status==="Approved"&&l.duration==="HALF"&&l.start===dateStr;})[0];' +
'if(half)return{state:"half",leaveType:half.leaveType,session:half.session};' +
'var pend=mine.filter(function(l){return l.status==="Pending"&&l.start<=dateStr&&dateStr<=l.end;})[0];' +
'if(pend)return{state:"pending",leaveType:pend.leaveType};' +
'return{state:"present"};' +
'}' +
'function computeUserStatus(username){' +
'var today=todayStr();' +
'var s=statusOnDate(username,today);' +
'var mine=leaves.filter(function(l){return l.username.toLowerCase()===username.toLowerCase();});' +
'if(s.state==="absent"){' +
'var active=mine.filter(function(l){return l.status==="Approved"&&l.duration==="FULL"&&l.start<=today&&today<=l.end;})[0];' +
'return{badge:"rejected",label:"Absent",detail:(active?active.leaveType:"")+" \u00b7 back "+fmt(active?active.end:"")};' +
'}' +
'if(s.state==="half")return{badge:"pending",label:"Half Day",detail:s.leaveType+" \u00b7 "+s.session};' +
'if(s.state==="pending")return{badge:"pending",label:"Pending",detail:s.leaveType+" request awaiting approval"};' +
'var upcoming=mine.filter(function(l){return l.status==="Approved"&&l.start>today;}).sort(function(a,b){return a.start.localeCompare(b.start);})[0];' +
'if(upcoming)return{badge:"approved",label:"Present",detail:"Leave from "+fmt(upcoming.start)};' +
'return{badge:"approved",label:"Present",detail:"No leave on record"};' +
'}' +
'function teamNames(){' +
'var names={};' +
'users.forEach(function(u){names[u.name]=true;});' +
'leaves.forEach(function(l){names[l.username]=true;});' +
'return Object.keys(names).sort(function(a,b){return a.localeCompare(b);});' +
'}' +

'function renderAttendancePanel(host,scope){' +
'var pickerId="picker-dash-"+scope;' +
'host.innerHTML="<h2>Attendance \u2014 Present / Absent</h2><p class=\\"sub\\">Pick a date to see who\'s present, absent, or out on a half day.</p>"+' +
'"<div class=\\"stat-row\\"><div class=\\"stat-card highlight\\"><div class=\\"stat-num\\" id=\\"stat-absent-"+scope+"\\">0</div><div class=\\"stat-label\\" id=\\"stat-absent-label-"+scope+"\\">Absent today</div></div>"+' +
'"<div class=\\"stat-card\\"><div class=\\"stat-num\\" id=\\"stat-present-"+scope+"\\">0</div><div class=\\"stat-label\\">Present</div></div>"+' +
'"<div class=\\"stat-card\\"><div class=\\"stat-num\\" id=\\"stat-pending-"+scope+"\\">0</div><div class=\\"stat-label\\">Pending approval</div></div></div>"+' +
'"<div class=\\"date-picker-row\\"><div class=\\"picker-wrap\\" id=\\""+pickerId+"\\" style=\\"max-width:220px;\\"></div><button class=\\"btn btn-ghost\\" id=\\"btn-today-"+scope+"\\">Today</button></div>"+' +
'"<div class=\\"flap-table\\"><div class=\\"flap-head\\"><div>Status</div><div>Username</div><div>Leave dates</div><div class=\\"col-reason\\">Reason</div></div><div id=\\"flap-body-"+scope+"\\"></div></div>"+' +
'"<h2 style=\\"margin-top:28px;\\">Team status directory</h2><p class=\\"sub\\">Every teammate, present or absent right now.</p>"+' +
'"<div class=\\"flap-table\\"><div class=\\"flap-head\\"><div>Status</div><div>Username</div><div>Since</div><div class=\\"col-reason\\">Detail</div></div><div id=\\"directory-body-"+scope+"\\"></div></div>"+' +
'"<h2 style=\\"margin-top:28px;\\">30-day attendance calendar</h2><p class=\\"sub\\">Rolling window starting today.</p>"+' +
'"<div class=\\"calendar-wrap\\" id=\\"calendar-wrap-"+scope+"\\"></div>";' +

'var picker=makeDatePicker(host.querySelector("#"+pickerId),{value:todayStr(),onChange:function(){renderAttendanceData(host,scope,picker);}});' +
'picker.setValue(todayStr());' +
'host.querySelector("#btn-today-"+scope).onclick=function(){picker.setValue(todayStr());renderAttendanceData(host,scope,picker);};' +
'renderAttendanceData(host,scope,picker);' +
'}' +

'function renderAttendanceData(host,scope,picker){' +
'var target=picker.getValue()||todayStr();' +
'var isToday=target===todayStr();' +
'var names=teamNames();' +
'var onLeaveEntries=leaves.filter(function(l){return l.status==="Approved"&&((l.duration==="FULL"&&l.start<=target&&target<=l.end)||(l.duration==="HALF"&&l.start===target));});' +
'var pendingCount=leaves.filter(function(l){return l.status==="Pending";}).length;' +
'var presentCount=Math.max(names.length-onLeaveEntries.length,0);' +

'host.querySelector("#stat-absent-"+scope).textContent=onLeaveEntries.length;' +
'host.querySelector("#stat-absent-label-"+scope).textContent=isToday?"Absent today":("Absent \u00b7 "+fmt(target));' +
'host.querySelector("#stat-present-"+scope).textContent=presentCount;' +
'host.querySelector("#stat-pending-"+scope).textContent=pendingCount;' +

'var body=host.querySelector("#flap-body-"+scope);' +
'body.innerHTML=onLeaveEntries.length?onLeaveEntries.map(function(l){return ' +
'"<div class=\\"flap-row\\"><div class=\\"flap-status "+(l.duration==="HALF"?"half":"absent")+"\\">"+(l.duration==="HALF"?"HALF":"ABSENT")+"</div><div class=\\"flap-user\\">"+escapeHtml(l.username)+" "+leaveTagHtml(l)+"</div><div class=\\"flap-dates\\">"+(l.duration==="HALF"?fmt(l.start)+" ("+l.session+")":fmt(l.start)+" \u2192 "+fmt(l.end))+"</div><div class=\\"flap-reason\\">"+(l.reason?escapeHtml(l.reason):"\u2014")+"</div></div>";' +
'}).join(""):"<div class=\\"empty-state\\">Nobody\'s absent on this date.</div>";' +

'var dirBody=host.querySelector("#directory-body-"+scope);' +
'dirBody.innerHTML=names.length?names.map(function(name){var s=computeUserStatus(name);var cls=s.label==="Absent"?"absent":s.label==="Half Day"?"half":s.label==="Pending"?"pending":"present";var text=s.label==="Absent"?"ABSENT":s.label==="Half Day"?"HALF":s.label==="Pending"?"PENDING":"PRESENT";return ' +
'"<div class=\\"flap-row\\"><div class=\\"flap-status "+cls+"\\">"+text+"</div><div class=\\"flap-user\\">"+escapeHtml(name)+"</div><div class=\\"flap-dates\\"></div><div class=\\"flap-reason\\">"+escapeHtml(s.detail)+"</div></div>";' +
'}).join(""):"<div class=\\"empty-state\\">No teammates yet.</div>";' +

'var calWrap=host.querySelector("#calendar-wrap-"+scope);' +
'if(!names.length){calWrap.innerHTML="<div class=\\"empty-state\\">No teammates yet.</div>";return;}' +
'var start=todayStr();var days=[];for(var i=0;i<30;i++)days.push(addDays(start,i));' +
'var html="<table class=\\"cal-table\\"><thead><tr><th class=\\"user-col\\">Username</th>";' +
'days.forEach(function(d){var dt=new Date(d+"T00:00:00");var label=dt.toLocaleDateString("en-US",{day:"numeric",month:"short"});html+="<th class=\\""+(d===start?"today-col":"")+"\\">"+label+"</th>";});' +
'html+="</tr></thead><tbody>";' +
'names.forEach(function(name){' +
'html+="<tr><td class=\\"user-col\\">"+escapeHtml(name)+"</td>";' +
'days.forEach(function(d){var s=statusOnDate(name,d);var dotClass=s.state;html+="<td class=\\""+(d===start?"today-col":"")+"\\"><span class=\\"cal-dot "+dotClass+"\\" title=\\""+dotClass+"\\"></span></td>";});' +
'html+="</tr>";' +
'});' +
'html+="</tbody></table>";' +
'calWrap.innerHTML=html;' +
'}' +

'(function(){' +
'document.getElementById("login-hint").textContent="Accounts are created by your admin \u2014 there\'s no self-signup.";' +
'})();' +
'</script>' +
'</body></html>';
