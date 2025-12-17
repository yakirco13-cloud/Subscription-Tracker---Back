const express = require('express');
const cors = require('cors');
const session = require('express-session');
const { google } = require('googleapis');
const msal = require('@azure/msal-node');
const initSqlJs = require('sql.js');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// PDF generation library
let PDFDocument;
try {
  PDFDocument = require('pdfkit');
} catch (e) {
  console.log('pdfkit not installed, run: npm install pdfkit');
  PDFDocument = null;
}

const app = express();
const PORT = 3001;

// ============================================
// CONFIGURATION - Uses environment variables
// ============================================
const BASE_URL = process.env.BASE_URL || 'http://localhost:3001';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

const config = {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: `${BASE_URL}/auth/google/callback`,
  },
  microsoft: {
    clientId: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    redirectUri: `${BASE_URL}/auth/microsoft/callback`,
    authority: 'https://login.microsoftonline.com/common',
  },
  session: {
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  }
};

// ============================================
// DATABASE SETUP (sql.js - pure JS SQLite)
// ============================================
let db;
const DB_PATH = path.join(__dirname, 'subscriptions.db');

async function initDatabase() {
  const SQL = await initSqlJs();
  
  // Load existing database or create new one
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      provider TEXT NOT NULL,
      access_token TEXT,
      refresh_token TEXT,
      token_expiry INTEGER,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      last_synced INTEGER
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL,
      name TEXT NOT NULL,
      price REAL,
      currency TEXT DEFAULT 'USD',
      billing_cycle TEXT,
      category TEXT,
      last_charge_date TEXT,
      next_charge_date TEXT,
      sender_email TEXT,
      detected_from_subject TEXT,
      confidence REAL DEFAULT 1.0,
      is_active INTEGER DEFAULT 1,
      created_at INTEGER DEFAULT (strftime('%s', 'now')),
      updated_at INTEGER DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
    )
  `);

  saveDatabase();
  console.log('Database initialized');
}

function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// Helper functions for sql.js
function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

function dbGet(sql, params = []) {
  const results = dbAll(sql, params);
  return results[0] || null;
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDatabase();
}

// ============================================
// MIDDLEWARE
// ============================================
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());
app.use(session({
  secret: config.session.secret,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ============================================
// GOOGLE OAUTH
// ============================================
const googleOAuth2Client = new google.auth.OAuth2(
  config.google.clientId,
  config.google.clientSecret,
  config.google.redirectUri
);

app.get('/auth/google', (req, res) => {
  const authUrl = googleOAuth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.email'],
  });
  res.redirect(authUrl);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  
  try {
    const { tokens } = await googleOAuth2Client.getToken(code);
    googleOAuth2Client.setCredentials(tokens);
    
    // Get user email
    const oauth2 = google.oauth2({ version: 'v2', auth: googleOAuth2Client });
    const userInfo = await oauth2.userinfo.get();
    const email = userInfo.data.email;
    
    // Check if account already exists
    const existing = dbGet('SELECT id FROM accounts WHERE email = ? AND provider = ?', [email, 'google']);
    
    if (existing) {
      dbRun(
        `UPDATE accounts SET access_token = ?, refresh_token = COALESCE(?, refresh_token), token_expiry = ? WHERE id = ?`,
        [tokens.access_token, tokens.refresh_token, tokens.expiry_date, existing.id]
      );
    } else {
      const accountId = crypto.randomUUID();
      dbRun(
        `INSERT INTO accounts (id, email, provider, access_token, refresh_token, token_expiry) VALUES (?, ?, 'google', ?, ?, ?)`,
        [accountId, email, tokens.access_token, tokens.refresh_token, tokens.expiry_date]
      );
    }
    
    res.redirect(FRONTEND_URL + '?connected=google&email=' + encodeURIComponent(email));
  } catch (error) {
    console.error('Google OAuth error:', error);
    res.redirect(FRONTEND_URL + '?error=google_auth_failed');
  }
});

// ============================================
// MICROSOFT OAUTH
// ============================================
const msalConfig = {
  auth: {
    clientId: config.microsoft.clientId,
    clientSecret: config.microsoft.clientSecret,
    authority: config.microsoft.authority,
  }
};

const msalClient = new msal.ConfidentialClientApplication(msalConfig);

app.get('/auth/microsoft', async (req, res) => {
  try {
    const authUrl = await msalClient.getAuthCodeUrl({
      scopes: ['Mail.Read', 'User.Read', 'offline_access'],
      redirectUri: config.microsoft.redirectUri,
    });
    res.redirect(authUrl);
  } catch (error) {
    console.error('Microsoft auth URL error:', error);
    res.redirect(FRONTEND_URL + '?error=microsoft_auth_failed');
  }
});

app.get('/auth/microsoft/callback', async (req, res) => {
  const { code, error, error_description } = req.query;
  
  // Check if Microsoft returned an error
  if (error) {
    console.error('Microsoft auth error:', error, error_description);
    return res.redirect(FRONTEND_URL + '?error=microsoft_auth_failed&reason=' + encodeURIComponent(error_description || error));
  }
  
  // Check if we got a code
  if (!code) {
    console.error('Microsoft callback: No code received. Query params:', req.query);
    return res.redirect(FRONTEND_URL + '?error=microsoft_no_code');
  }
  
  try {
    console.log('Microsoft callback: Got code, requesting token...');
    const tokenResponse = await msalClient.acquireTokenByCode({
      code,
      scopes: ['Mail.Read', 'User.Read', 'offline_access'],
      redirectUri: config.microsoft.redirectUri,
    });
    
    console.log('Microsoft callback: Got token, fetching user info...');
    
    // Get user email from Microsoft Graph
    const graphResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${tokenResponse.accessToken}` }
    });
    const userData = await graphResponse.json();
    const email = userData.mail || userData.userPrincipalName;
    
    console.log('Microsoft callback: Connected account:', email);
    
    // Check if account already exists
    const existing = dbGet('SELECT id FROM accounts WHERE email = ? AND provider = ?', [email, 'microsoft']);
    
    if (existing) {
      dbRun(
        `UPDATE accounts SET access_token = ?, token_expiry = ? WHERE id = ?`,
        [tokenResponse.accessToken, tokenResponse.expiresOn?.getTime(), existing.id]
      );
    } else {
      const accountId = crypto.randomUUID();
      dbRun(
        `INSERT INTO accounts (id, email, provider, access_token, token_expiry) VALUES (?, ?, 'microsoft', ?, ?)`,
        [accountId, email, tokenResponse.accessToken, tokenResponse.expiresOn?.getTime()]
      );
    }
    
    res.redirect(FRONTEND_URL + '?connected=microsoft&email=' + encodeURIComponent(email));
  } catch (error) {
    console.error('Microsoft OAuth error:', error);
    res.redirect(FRONTEND_URL + '?error=microsoft_auth_failed');
  }
});

// ============================================
// API ENDPOINTS
// ============================================

// Get all connected accounts
app.get('/api/accounts', (req, res) => {
  const accounts = dbAll(`
    SELECT id, email, provider, last_synced, created_at
    FROM accounts
    ORDER BY created_at DESC
  `);
  res.json(accounts);
});

// Remove an account
app.delete('/api/accounts/:id', (req, res) => {
  const { id } = req.params;
  dbRun('DELETE FROM subscriptions WHERE account_id = ?', [id]);
  dbRun('DELETE FROM accounts WHERE id = ?', [id]);
  res.json({ success: true });
});

// Get all subscriptions
app.get('/api/subscriptions', (req, res) => {
  const subscriptions = dbAll(`
    SELECT s.*, a.email as account_email, a.provider as account_provider
    FROM subscriptions s
    JOIN accounts a ON s.account_id = a.id
    WHERE s.is_active = 1
    ORDER BY s.price DESC
  `);
  res.json(subscriptions);
});

// Manually add a subscription
app.post('/api/subscriptions', (req, res) => {
  const { name, price, currency, billing_cycle, category, account_id } = req.body;
  const id = crypto.randomUUID();
  
  dbRun(
    `INSERT INTO subscriptions (id, account_id, name, price, currency, billing_cycle, category) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [id, account_id || 'manual', name, price, currency || 'USD', billing_cycle, category]
  );
  
  res.json({ id, success: true });
});

// Update a subscription
app.patch('/api/subscriptions/:id', (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  
  const allowedFields = ['name', 'price', 'currency', 'billing_cycle', 'category', 'is_active'];
  const fields = Object.keys(updates).filter(k => allowedFields.includes(k));
  
  if (fields.length > 0) {
    const setClause = fields.map(k => `${k} = ?`).join(', ');
    const values = fields.map(k => updates[k]);
    dbRun(`UPDATE subscriptions SET ${setClause}, updated_at = strftime('%s', 'now') WHERE id = ?`, [...values, id]);
  }
  
  res.json({ success: true });
});

// Delete a subscription
app.delete('/api/subscriptions/:id', (req, res) => {
  const { id } = req.params;
  dbRun('DELETE FROM subscriptions WHERE id = ?', [id]);
  res.json({ success: true });
});

// Clear all subscriptions (for re-syncing)
app.delete('/api/subscriptions', (req, res) => {
  dbRun('DELETE FROM subscriptions');
  res.json({ success: true, message: 'All subscriptions cleared' });
});

// Sync emails for all accounts
app.post('/api/sync', async (req, res) => {
  const accounts = dbAll('SELECT * FROM accounts');
  const results = { synced: 0, subscriptions_found: 0, errors: [] };
  
  for (const account of accounts) {
    try {
      let emails = [];
      
      if (account.provider === 'google') {
        emails = await fetchGmailEmails(account);
      } else if (account.provider === 'microsoft') {
        emails = await fetchOutlookEmails(account);
      }
      
      const subscriptions = await parseSubscriptionEmails(emails, account.email);
      
      for (const sub of subscriptions) {
        saveSubscription(account.id, sub);
        results.subscriptions_found++;
      }
      
      dbRun("UPDATE accounts SET last_synced = strftime('%s', 'now') WHERE id = ?", [account.id]);
      results.synced++;
    } catch (error) {
      console.error(`Sync error for ${account.email}:`, error);
      results.errors.push({ account: account.email, error: error.message });
    }
  }
  
  res.json(results);
});

// Sync all accounts and return PDF report
app.post('/api/sync-and-report', async (req, res) => {
  const accounts = dbAll('SELECT * FROM accounts');
  
  if (accounts.length === 0) {
    return res.status(400).json({ error: 'No email accounts connected. Please connect Gmail or Outlook first.' });
  }
  
  console.log(`\n🔄 Starting sync for ${accounts.length} account(s)...`);
  
  for (const account of accounts) {
    try {
      let emails = [];
      
      if (account.provider === 'google') {
        emails = await fetchGmailEmails(account);
      } else if (account.provider === 'microsoft') {
        emails = await fetchOutlookEmails(account);
      }
      
      const subscriptions = await parseSubscriptionEmails(emails, account.email);
      
      for (const sub of subscriptions) {
        saveSubscription(account.id, sub);
      }
      
      dbRun("UPDATE accounts SET last_synced = strftime('%s', 'now') WHERE id = ?", [account.id]);
    } catch (error) {
      console.error(`Sync error for ${account.email}:`, error);
    }
  }
  
  // Generate and return PDF
  try {
    const pdfBuffer = await generateSubscriptionReport();
    const filename = `subscription-report-${new Date().toISOString().split('T')[0]}.pdf`;
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    
    res.send(pdfBuffer);
  } catch (error) {
    console.error('PDF generation error:', error);
    res.status(500).json({ error: 'Sync completed but PDF generation failed', message: error.message });
  }
});

// Sync single account
app.post('/api/accounts/:id/sync', async (req, res) => {
  const { id } = req.params;
  const account = dbGet('SELECT * FROM accounts WHERE id = ?', [id]);
  
  if (!account) {
    return res.status(404).json({ error: 'Account not found' });
  }
  
  try {
    let emails = [];
    
    if (account.provider === 'google') {
      emails = await fetchGmailEmails(account);
    } else if (account.provider === 'microsoft') {
      emails = await fetchOutlookEmails(account);
    }
    
    const subscriptions = await parseSubscriptionEmails(emails, account.email);
    let newCount = 0;
    
    for (const sub of subscriptions) {
      const isNew = saveSubscription(account.id, sub);
      if (isNew) newCount++;
    }
    
    dbRun("UPDATE accounts SET last_synced = strftime('%s', 'now') WHERE id = ?", [id]);
    
    res.json({ 
      success: true, 
      emails_scanned: emails.length,
      subscriptions_found: subscriptions.length,
      new_subscriptions: newCount
    });
  } catch (error) {
    console.error(`Sync error for ${account.email}:`, error);
    res.status(500).json({ error: error.message });
  }
});

// Dashboard stats
app.get('/api/stats', (req, res) => {
  const monthlyResult = dbGet(`
    SELECT COALESCE(SUM(CASE 
      WHEN billing_cycle = 'yearly' THEN price / 12 
      ELSE price 
    END), 0) as total
    FROM subscriptions WHERE is_active = 1
  `);
  
  const yearlyResult = dbGet(`
    SELECT COALESCE(SUM(CASE 
      WHEN billing_cycle = 'monthly' THEN price * 12 
      ELSE price 
    END), 0) as total
    FROM subscriptions WHERE is_active = 1
  `);
  
  const countResult = dbGet('SELECT COUNT(*) as count FROM subscriptions WHERE is_active = 1');
  const accountsResult = dbGet('SELECT COUNT(*) as count FROM accounts');
  
  const stats = {
    total_monthly: monthlyResult?.total || 0,
    total_yearly: yearlyResult?.total || 0,
    active_count: countResult?.count || 0,
    accounts_count: accountsResult?.count || 0,
    
    by_category: dbAll(`
      SELECT category, SUM(CASE 
        WHEN billing_cycle = 'yearly' THEN price / 12 
        ELSE price 
      END) as total
      FROM subscriptions 
      WHERE is_active = 1 AND category IS NOT NULL
      GROUP BY category
      ORDER BY total DESC
    `),
    
    by_account: dbAll(`
      SELECT a.email, a.provider, SUM(CASE 
        WHEN s.billing_cycle = 'yearly' THEN s.price / 12 
        ELSE s.price 
      END) as total
      FROM subscriptions s
      JOIN accounts a ON s.account_id = a.id
      WHERE s.is_active = 1
      GROUP BY a.id
      ORDER BY total DESC
    `),
  };
  
  res.json(stats);
});

// ============================================
// PDF REPORT GENERATION
// ============================================

function generateSubscriptionReport() {
  return new Promise((resolve, reject) => {
    if (!PDFDocument) {
      return reject(new Error('pdfkit not installed'));
    }
    
    // Get all data
    const subscriptions = dbAll(`
      SELECT s.*, a.email as account_email, a.provider
      FROM subscriptions s
      JOIN accounts a ON s.account_id = a.id
      WHERE s.is_active = 1
      ORDER BY 
        CASE WHEN s.billing_cycle = 'yearly' THEN s.price / 12 ELSE s.price END DESC
    `);
    
    const monthlyTotal = dbGet(`
      SELECT COALESCE(SUM(CASE 
        WHEN billing_cycle = 'yearly' THEN price / 12 
        ELSE price 
      END), 0) as total
      FROM subscriptions WHERE is_active = 1
    `)?.total || 0;
    
    const yearlyTotal = monthlyTotal * 12;
    
    const byCategory = dbAll(`
      SELECT category, 
        COUNT(*) as count,
        SUM(CASE WHEN billing_cycle = 'yearly' THEN price / 12 ELSE price END) as monthly_total
      FROM subscriptions 
      WHERE is_active = 1 AND category IS NOT NULL
      GROUP BY category
      ORDER BY monthly_total DESC
    `);
    
    // Create PDF
    const doc = new PDFDocument({ 
      margin: 50,
      size: 'A4'
    });
    
    const chunks = [];
    doc.on('data', chunk => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    
    // Colors
    const primaryColor = '#2563eb';
    const textColor = '#1f2937';
    const lightGray = '#f3f4f6';
    const mediumGray = '#9ca3af';
    
    // Helper: Format currency
    const formatCurrency = (amount, currency = 'USD') => {
      const symbols = { USD: '$', EUR: '€', GBP: '£', ILS: '₪' };
      const symbol = symbols[currency] || '$';
      return `${symbol}${amount?.toFixed(2) || '0.00'}`;
    };
    
    // Helper: Draw table row
    let tableY = 0;
    const drawTableRow = (cols, y, isHeader = false, widths = [200, 80, 80, 100]) => {
      const startX = 50;
      let x = startX;
      
      if (isHeader) {
        doc.fillColor(primaryColor).fontSize(10).font('Helvetica-Bold');
      } else {
        doc.fillColor(textColor).fontSize(10).font('Helvetica');
      }
      
      cols.forEach((col, i) => {
        doc.text(col, x, y, { width: widths[i], align: i === 0 ? 'left' : 'right' });
        x += widths[i];
      });
      
      return y + 20;
    };
    
    // ─────────────────────────────────────────────
    // HEADER
    // ─────────────────────────────────────────────
    doc.fillColor(primaryColor)
       .fontSize(28)
       .font('Helvetica-Bold')
       .text('Subscription Report', 50, 50);
    
    doc.fillColor(mediumGray)
       .fontSize(12)
       .font('Helvetica')
       .text(`Generated on ${new Date().toLocaleDateString('en-US', { 
         year: 'numeric', 
         month: 'long', 
         day: 'numeric' 
       })}`, 50, 85);
    
    // ─────────────────────────────────────────────
    // SUMMARY BOX
    // ─────────────────────────────────────────────
    const summaryY = 120;
    
    // Background box
    doc.fillColor(lightGray)
       .roundedRect(50, summaryY, 495, 80, 8)
       .fill();
    
    // Monthly cost
    doc.fillColor(textColor)
       .fontSize(12)
       .font('Helvetica')
       .text('Monthly Cost', 70, summaryY + 15);
    
    doc.fillColor(primaryColor)
       .fontSize(24)
       .font('Helvetica-Bold')
       .text(formatCurrency(monthlyTotal), 70, summaryY + 35);
    
    // Yearly cost
    doc.fillColor(textColor)
       .fontSize(12)
       .font('Helvetica')
       .text('Yearly Cost', 250, summaryY + 15);
    
    doc.fillColor(primaryColor)
       .fontSize(24)
       .font('Helvetica-Bold')
       .text(formatCurrency(yearlyTotal), 250, summaryY + 35);
    
    // Subscription count
    doc.fillColor(textColor)
       .fontSize(12)
       .font('Helvetica')
       .text('Active Subscriptions', 430, summaryY + 15);
    
    doc.fillColor(primaryColor)
       .fontSize(24)
       .font('Helvetica-Bold')
       .text(subscriptions.length.toString(), 430, summaryY + 35);
    
    // ─────────────────────────────────────────────
    // SUBSCRIPTIONS TABLE
    // ─────────────────────────────────────────────
    let y = summaryY + 110;
    
    doc.fillColor(textColor)
       .fontSize(16)
       .font('Helvetica-Bold')
       .text('Your Subscriptions', 50, y);
    
    y += 30;
    
    // Table header
    y = drawTableRow(['Service', 'Price', 'Cycle', 'Category'], y, true);
    
    // Divider
    doc.strokeColor(mediumGray)
       .lineWidth(0.5)
       .moveTo(50, y)
       .lineTo(545, y)
       .stroke();
    
    y += 10;
    
    // Table rows
    for (const sub of subscriptions) {
      // Check if we need a new page
      if (y > 750) {
        doc.addPage();
        y = 50;
      }
      
      const priceStr = formatCurrency(sub.price, sub.currency);
      const cycle = sub.billing_cycle || 'monthly';
      const category = sub.category || 'Other';
      
      y = drawTableRow([sub.name, priceStr, cycle, category], y, false);
    }
    
    // ─────────────────────────────────────────────
    // CATEGORY BREAKDOWN
    // ─────────────────────────────────────────────
    if (byCategory.length > 0) {
      y += 30;
      
      // Check if we need a new page
      if (y > 650) {
        doc.addPage();
        y = 50;
      }
      
      doc.fillColor(textColor)
         .fontSize(16)
         .font('Helvetica-Bold')
         .text('Spending by Category', 50, y);
      
      y += 30;
      
      // Category bars
      const maxTotal = Math.max(...byCategory.map(c => c.monthly_total));
      
      for (const cat of byCategory) {
        if (y > 750) {
          doc.addPage();
          y = 50;
        }
        
        const barWidth = (cat.monthly_total / maxTotal) * 300;
        
        // Category name
        doc.fillColor(textColor)
           .fontSize(10)
           .font('Helvetica')
           .text(cat.category, 50, y, { width: 120 });
        
        // Bar
        doc.fillColor(primaryColor)
           .roundedRect(180, y, barWidth, 15, 3)
           .fill();
        
        // Amount
        doc.fillColor(textColor)
           .fontSize(10)
           .font('Helvetica')
           .text(`${formatCurrency(cat.monthly_total)}/mo (${cat.count})`, 490, y, { 
             width: 80, 
             align: 'right' 
           });
        
        y += 25;
      }
    }
    
    // ─────────────────────────────────────────────
    // FOOTER
    // ─────────────────────────────────────────────
    const pageCount = doc.bufferedPageRange().count;
    for (let i = 0; i < pageCount; i++) {
      doc.switchToPage(i);
      
      doc.fillColor(mediumGray)
         .fontSize(9)
         .font('Helvetica')
         .text(
           'Generated by Subscription Tracker',
           50,
           doc.page.height - 30,
           { align: 'center', width: doc.page.width - 100 }
         );
    }
    
    // Finalize
    doc.end();
  });
}

// PDF download endpoint
app.get('/api/report/pdf', async (req, res) => {
  try {
    const pdfBuffer = await generateSubscriptionReport();
    
    const filename = `subscription-report-${new Date().toISOString().split('T')[0]}.pdf`;
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    
    res.send(pdfBuffer);
  } catch (error) {
    console.error('PDF generation error:', error);
    res.status(500).json({ error: 'Failed to generate PDF', message: error.message });
  }
});

// ============================================
// EMAIL FETCHING FUNCTIONS
// ============================================

async function fetchGmailEmails(account) {
  const oauth2Client = new google.auth.OAuth2(
    config.google.clientId,
    config.google.clientSecret,
    config.google.redirectUri
  );
  
  oauth2Client.setCredentials({
    access_token: account.access_token,
    refresh_token: account.refresh_token,
  });
  
  // Refresh token if needed
  if (account.token_expiry && Date.now() > account.token_expiry) {
    const { credentials } = await oauth2Client.refreshAccessToken();
    dbRun('UPDATE accounts SET access_token = ?, token_expiry = ? WHERE id = ?',
      [credentials.access_token, credentials.expiry_date, account.id]);
    oauth2Client.setCredentials(credentials);
  }
  
  const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
  
  // Search for subscription-related emails - broad search for receipts and invoices
  const searchQueries = [
    'subject:(receipt OR invoice OR "your payment" OR "payment confirmation" OR "you were charged" OR חשבונית OR קבלה)',
    'from:(billing OR receipt OR payments OR invoice OR paypal OR stripe) (receipt OR invoice OR payment OR charged)',
  ];
  
  const emails = [];
  
  for (const query of searchQueries) {
    try {
      const response = await gmail.users.messages.list({
        userId: 'me',
        q: query,
        maxResults: 100,
      });
      
      if (response.data.messages) {
        for (const msg of response.data.messages.slice(0, 50)) {
          try {
            const email = await gmail.users.messages.get({
              userId: 'me',
              id: msg.id,
              format: 'full',
            });
            
            const headers = email.data.payload.headers;
            
            // Extract body text from all parts
            let bodyText = email.data.snippet || '';
            
            // Recursively extract text from email parts
            function extractTextFromParts(parts) {
              if (!parts) return '';
              let text = '';
              for (const part of parts) {
                if (part.parts) {
                  // Nested multipart
                  text += extractTextFromParts(part.parts);
                } else if (part.body?.data) {
                  const content = Buffer.from(part.body.data, 'base64').toString('utf-8');
                  if (part.mimeType === 'text/plain') {
                    text += ' ' + content;
                  } else if (part.mimeType === 'text/html') {
                    // Strip HTML tags but keep the text
                    const stripped = content
                      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
                      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                      .replace(/<[^>]+>/g, ' ')
                      .replace(/&nbsp;/g, ' ')
                      .replace(/&amp;/g, '&')
                      .replace(/&lt;/g, '<')
                      .replace(/&gt;/g, '>')
                      .replace(/&quot;/g, '"')
                      .replace(/&#?\w+;/g, ' ')
                      .replace(/\s+/g, ' ');
                    text += ' ' + stripped;
                  }
                } else if (part.mimeType === 'application/pdf' && part.body?.attachmentId) {
                  // Store PDF attachment ID for lazy extraction
                  pdfAttachmentIds.push(part.body.attachmentId);
                }
              }
              return text;
            }
            
            // Collect PDF attachment IDs
            let pdfAttachmentIds = [];
            
            // Try to get body from parts
            if (email.data.payload.parts) {
              bodyText += extractTextFromParts(email.data.payload.parts);
            } else if (email.data.payload.body?.data) {
              const content = Buffer.from(email.data.payload.body.data, 'base64').toString('utf-8');
              if (email.data.payload.mimeType === 'text/html') {
                // Strip HTML tags
                const stripped = content
                  .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
                  .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                  .replace(/<[^>]+>/g, ' ')
                  .replace(/&nbsp;/g, ' ')
                  .replace(/\s+/g, ' ');
                bodyText += ' ' + stripped;
              } else {
                bodyText += ' ' + content;
              }
            }
            
            emails.push({
              id: msg.id,
              from: headers.find(h => h.name === 'From')?.value || '',
              subject: headers.find(h => h.name === 'Subject')?.value || '',
              date: headers.find(h => h.name === 'Date')?.value || '',
              snippet: bodyText.substring(0, 5000),
              pdfAttachmentIds: pdfAttachmentIds, // For lazy PDF extraction
              provider: 'gmail',
              accountId: account.id,
            });
          } catch (emailError) {
            console.error('Error fetching email:', emailError.message);
          }
        }
      }
    } catch (error) {
      console.error('Gmail fetch error:', error.message);
    }
  }
  
  return emails;
}

async function fetchOutlookEmails(account) {
  const emails = [];
  
  try {
    // First, get the list of messages
    const listResponse = await fetch(
      `https://graph.microsoft.com/v1.0/me/messages?$search="receipt OR invoice OR payment OR חשבונית OR קבלה"&$top=100&$select=id,from,subject,receivedDateTime`,
      {
        headers: { Authorization: `Bearer ${account.access_token}` }
      }
    );
    
    if (!listResponse.ok) {
      throw new Error(`Outlook API error: ${listResponse.status}`);
    }
    
    const listData = await listResponse.json();
    
    if (listData.value) {
      // Fetch full body for each message (limit to 50 to avoid rate limits)
      for (const msg of listData.value.slice(0, 50)) {
        try {
          const msgResponse = await fetch(
            `https://graph.microsoft.com/v1.0/me/messages/${msg.id}?$select=id,from,subject,receivedDateTime,body`,
            {
              headers: { Authorization: `Bearer ${account.access_token}` }
            }
          );
          
          if (msgResponse.ok) {
            const msgData = await msgResponse.json();
            
            // Extract text from body (could be HTML)
            let bodyText = '';
            if (msgData.body?.content) {
              if (msgData.body.contentType === 'html') {
                // Strip HTML tags
                bodyText = msgData.body.content
                  .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
                  .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                  .replace(/<[^>]+>/g, ' ')
                  .replace(/&nbsp;/g, ' ')
                  .replace(/&amp;/g, '&')
                  .replace(/&lt;/g, '<')
                  .replace(/&gt;/g, '>')
                  .replace(/&quot;/g, '"')
                  .replace(/&#?\w+;/g, ' ')
                  .replace(/\s+/g, ' ')
                  .trim();
              } else {
                bodyText = msgData.body.content;
              }
            }
            
            emails.push({
              id: msg.id,
              from: msgData.from?.emailAddress?.name 
                ? `${msgData.from.emailAddress.name} <${msgData.from.emailAddress.address}>`
                : msgData.from?.emailAddress?.address || '',
              subject: msgData.subject || '',
              date: msgData.receivedDateTime || '',
              snippet: bodyText.substring(0, 5000),
              pdfAttachmentIds: [], // Will check lazily if needed
              provider: 'outlook',
              accountId: account.id,
            });
          }
        } catch (msgError) {
          console.error('Error fetching Outlook message:', msgError.message);
        }
      }
    }
  } catch (error) {
    console.error('Outlook fetch error:', error.message);
  }
  
  return emails;
}

// ============================================
// PDF EXTRACTION (Lazy - only when needed)
// ============================================

// Extract price from PDF buffer - specialized for Hebrew invoices
// Extract price from PDF text (after parsing with pdf-parse)
function extractPriceFromPdfText(text) {
  if (!text) return { price: null, currency: 'ILS' };
  
  // Hebrew total keywords - look for these followed by a number
  const totalPatterns = [
    // "סה"כ" or variations followed by number
    /סה["״'׳]?כ\s*[:\-]?\s*(\d+(?:[.,]\d{2})?)/g,
    /סהכ\s*[:\-]?\s*(\d+(?:[.,]\d{2})?)/g,
    /סך הכל\s*[:\-]?\s*(\d+(?:[.,]\d{2})?)/g,
    // "לתשלום" followed by number
    /לתשלום\s*[:\-]?\s*(\d+(?:[.,]\d{2})?)/g,
    // "סכום" followed by number  
    /סכום\s*[:\-]?\s*(\d+(?:[.,]\d{2})?)/g,
    // Currency symbol followed by number
    /₪\s*(\d+(?:[.,]\d{2})?)/g,
    // Number followed by currency
    /(\d+(?:[.,]\d{2})?)\s*₪/g,
    /(\d+(?:[.,]\d{2})?)\s*ש["״'׳]?ח/g,
  ];
  
  const foundPrices = [];
  
  for (const pattern of totalPatterns) {
    let match;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(text)) !== null) {
      const priceStr = match[1].replace(',', '.');
      const price = parseFloat(priceStr);
      if (price >= 1 && price <= 1000) {
        // Higher priority for prices found with total keywords
        const isTotal = /סה|לתשלום|סכום/.test(pattern.source);
        foundPrices.push({ price, priority: isTotal ? 2 : 1 });
      }
    }
  }
  
  if (foundPrices.length === 0) {
    return { price: null, currency: 'ILS' };
  }
  
  // Sort by priority desc, then by price desc (totals are usually larger)
  foundPrices.sort((a, b) => b.priority - a.priority || b.price - a.price);
  
  return { price: foundPrices[0].price, currency: 'ILS' };
}

// Parse PDF buffer to text using pdf-parse library
async function parsePdfBuffer(buffer) {
  if (!pdfParse) {
    return null;
  }
  
  try {
    const data = await pdfParse(buffer);
    return data.text;
  } catch (e) {
    console.log('    PDF parse error:', e.message);
    return null;
  }
}

// Extract price from PDF in Gmail email
async function extractPdfPriceFromGmail(email) {
  if (!pdfParse) {
    return { price: null, currency: 'ILS' };
  }
  
  if (!email.pdfAttachmentIds || email.pdfAttachmentIds.length === 0) {
    return { price: null, currency: 'ILS' };
  }
  
  try {
    const account = dbGet('SELECT * FROM accounts WHERE id = ?', [email.accountId]);
    if (!account) return { price: null, currency: 'ILS' };
    
    const oauth2Client = new google.auth.OAuth2(
      config.google.clientId,
      config.google.clientSecret,
      config.google.redirectUri
    );
    oauth2Client.setCredentials({
      access_token: account.access_token,
      refresh_token: account.refresh_token,
    });
    
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    
    // Just get the first PDF
    const attachmentId = email.pdfAttachmentIds[0];
    const attachment = await gmail.users.messages.attachments.get({
      userId: 'me',
      messageId: email.id,
      id: attachmentId,
    });
    
    if (attachment.data?.data) {
      const pdfBuffer = Buffer.from(attachment.data.data, 'base64');
      const pdfText = await parsePdfBuffer(pdfBuffer);
      if (pdfText) {
        return extractPriceFromPdfText(pdfText);
      }
    }
  } catch (e) {
    // Ignore errors
  }
  
  return { price: null, currency: 'ILS' };
}

// Extract price from PDF in Outlook email
async function extractPdfPriceFromOutlook(email) {
  if (!pdfParse) {
    return { price: null, currency: 'ILS' };
  }
  
  try {
    const account = dbGet('SELECT * FROM accounts WHERE id = ?', [email.accountId]);
    if (!account) return { price: null, currency: 'ILS' };
    
    const attachResponse = await fetch(
      `https://graph.microsoft.com/v1.0/me/messages/${email.id}/attachments?$filter=contentType eq 'application/pdf'&$top=1`,
      {
        headers: { Authorization: `Bearer ${account.access_token}` }
      }
    );
    
    if (attachResponse.ok) {
      const attachData = await attachResponse.json();
      if (attachData.value && attachData.value.length > 0) {
        const attach = attachData.value[0];
        if (attach.contentBytes) {
          const pdfBuffer = Buffer.from(attach.contentBytes, 'base64');
          const pdfText = await parsePdfBuffer(pdfBuffer);
          if (pdfText) {
            return extractPriceFromPdfText(pdfText);
          }
        }
      }
    }
  } catch (e) {
    // Ignore errors
  }
  
  return { price: null, currency: 'ILS' };
}

// ============================================
// RECURRING PAYMENT DETECTION SYSTEM
// ============================================
// Goal: Detect ANY recurring financial commitment
// Including: SaaS, utilities, toll roads, gym, phone bills, etc.
// Excluding: One-time purchases, irregular visits, flights/hotels/events

// ══════════════════════════════════════════════════════════════════
// ONE-TIME EVENT INDICATORS (These suggest NOT a subscription)
// Only reject if the pattern is clearly one-time/event-based
// ══════════════════════════════════════════════════════════════════
const ONE_TIME_EVENT_PATTERNS = [
  // Travel/Events (inherently one-time) - must be specific
  /flight\s+(confirmation|itinerary|booking)/i,
  /טיסה.*אישור/,
  /boarding pass/i,
  /כרטיס עלייה למטוס/,
  /hotel\s+(reservation|booking|confirmation)/i,
  /הזמנת מלון/,
  /event ticket/i,
  /כרטיס לאירוע/,
  /concert ticket/i,
  /כרטיס להופעה/,
  
  // One-time purchases with shipping - must have explicit shipping
  /your order has shipped/i,
  /ההזמנה שלך נשלחה/,
  /shipping confirmation/i,
  /אישור משלוח/,
  /package delivered/i,
  /החבילה נמסרה/,
];

// ══════════════════════════════════════════════════════════════════
// NON-SUBSCRIPTION RECURRING PATTERNS
// These send recurring emails but are NOT subscriptions
// ══════════════════════════════════════════════════════════════════
const NON_SUBSCRIPTION_PATTERNS = [
  // Airline loyalty programs / promotional emails (generic patterns)
  /airline|חברת תעופה|frequent flyer|מועדון נוסע|מיילים|miles program|flight points/i,
  
  // Crypto/trading platforms (deposits, not subscriptions)
  /crypto|bitcoin|ethereum|blockchain|trading platform|exchange|deposit|withdraw|digital assets|wallet/i,
  
  // Banking transactions (not subscriptions)
  /bank statement|דף חשבון|wire transfer|העברה בנקאית/i,
  
  // Loyalty/rewards programs
  /loyalty program|תכנית נאמנות|reward points|נקודות|מועדון לקוחות/i,
];

function isNonSubscriptionService(name, emailContent) {
  const combined = `${name} ${emailContent}`;
  return NON_SUBSCRIPTION_PATTERNS.some(p => p.test(combined));
}

// Check if email is clearly a one-time event (NOT a subscription)
function isOneTimeEvent(subject, body) {
  const combined = `${subject} ${body}`;
  
  for (const pattern of ONE_TIME_EVENT_PATTERNS) {
    if (pattern.test(combined)) {
      return true;
    }
  }
  return false;
}

// ══════════════════════════════════════════════════════════════════
// IRREGULAR VISIT INDICATORS (Medical/Vet - need consistent cadence)
// ══════════════════════════════════════════════════════════════════
const IRREGULAR_SERVICE_PATTERNS = [
  // Medical/Veterinary (often irregular visits, not subscriptions)
  /מרפאה/,
  /וטרינר/,
  /veterinar/i,
  /clinic/i,
  /קליניקה/,
  /רופא/,
  /doctor/i,
  /דר\s/,
  /ד"ר/,
  /טיפול/,
  /treatment/i,
];

// Check if this looks like an irregular service (needs extra validation)
function isIrregularServiceType(name) {
  for (const pattern of IRREGULAR_SERVICE_PATTERNS) {
    if (pattern.test(name)) {
      return true;
    }
  }
  return false;
}
const SUBSCRIPTION_LANGUAGE = {
  // English
  'subscription': 2,
  'monthly': 2,
  'yearly': 3,
  'annual': 3,
  'annually': 3,
  'billing cycle': 2,
  'billing period': 2,
  'recurring': 2,
  'renewal': 2,
  'renews': 2,
  'auto-renew': 3,
  'membership': 2,
  'plan': 1,
  
  // Hebrew
  'מנוי': 2,
  'חודשי': 2,
  'שנתי': 3,
  'לשנה': 3,
  'חיוב חודשי': 3,
  'חידוש': 2,
  'חידוש אוטומטי': 3,
  'מנוי שנתי': 4,
  'מנוי חודשי': 3,
  'תשלום חודשי': 2,
};

// Check for explicit yearly subscription language (Rule 2.2)
function hasExplicitYearlyLanguage(subject, body) {
  const combined = `${subject} ${body}`.toLowerCase();
  const yearlyPatterns = [
    /yearly\s+(subscription|plan|membership|fee)/i,
    /annual\s+(subscription|plan|membership|fee)/i,
    /per\s+year/i,
    /\/year\b/i,
    /billed\s+(yearly|annually)/i,
    /מנוי\s+שנתי/,
    /חיוב\s+שנתי/,
    /תשלום\s+שנתי/,
    /לשנה\b/,
  ];
  
  return yearlyPatterns.some(p => p.test(combined));
}

// Calculate subscription language bonus score
function calculateLanguageBonus(subject, body) {
  const combined = `${subject} ${body}`.toLowerCase();
  let bonus = 0;
  
  for (const [phrase, points] of Object.entries(SUBSCRIPTION_LANGUAGE)) {
    if (combined.includes(phrase.toLowerCase())) {
      bonus += points;
    }
  }
  
  return Math.min(bonus, 10); // Cap at 10
}

// ══════════════════════════════════════════════════════════════════
// AMOUNT CONSISTENCY CHECK (Rule 3 - Supporting, not required)
// ══════════════════════════════════════════════════════════════════
function checkAmountConsistency(prices) {
  if (prices.length < 2) return { consistent: true, confidence: 0.5 };
  
  const validPrices = prices.filter(p => p > 0);
  if (validPrices.length < 2) return { consistent: true, confidence: 0.5 };
  
  const mean = validPrices.reduce((a, b) => a + b, 0) / validPrices.length;
  const min = Math.min(...validPrices);
  const max = Math.max(...validPrices);
  
  // Check for extreme spikes (order of magnitude difference)
  if (max > min * 10) {
    return { consistent: false, confidence: 0.3, reason: 'extreme_spike' };
  }
  
  // Calculate coefficient of variation
  const variance = validPrices.reduce((sum, p) => sum + Math.pow(p - mean, 2), 0) / validPrices.length;
  const cv = Math.sqrt(variance) / mean;
  
  if (cv < 0.15) {
    // Very consistent (fixed subscription)
    return { consistent: true, confidence: 0.9, reason: 'fixed' };
  } else if (cv < 0.5) {
    // Moderately consistent (usage-based but reasonable)
    return { consistent: true, confidence: 0.7, reason: 'usage_based' };
  } else {
    // Inconsistent but not extreme
    return { consistent: false, confidence: 0.5, reason: 'variable' };
  }
}

// ══════════════════════════════════════════════════════════════════
// CADENCE CONSISTENCY CHECK (Rule 4 - Supporting)
// ══════════════════════════════════════════════════════════════════
function checkCadenceConsistency(dates) {
  if (dates.length < 2) return { valid: true, cycle: 'monthly', confidence: 0.5 };
  
  const sortedDates = [...dates].sort((a, b) => a.getTime() - b.getTime());
  
  // Calculate total span from first to last
  const firstDate = sortedDates[0];
  const lastDate = sortedDates[sortedDates.length - 1];
  const totalSpanDays = (lastDate.getTime() - firstDate.getTime()) / (1000 * 60 * 60 * 24);
  
  // If total span is very short (less than 14 days), assume monthly
  if (totalSpanDays < 14) {
    return { valid: true, cycle: 'monthly', confidence: 0.5, avgInterval: totalSpanDays / Math.max(dates.length - 1, 1) };
  }
  
  // Calculate intervals between consecutive dates
  const intervals = [];
  for (let i = 1; i < sortedDates.length; i++) {
    const days = (sortedDates[i].getTime() - sortedDates[i-1].getTime()) / (1000 * 60 * 60 * 24);
    // Skip very short intervals (same day duplicates, retries)
    if (days >= 3) {
      intervals.push(days);
    }
  }
  
  // If no valid intervals, estimate from total span
  if (intervals.length === 0) {
    const estimatedInterval = totalSpanDays / (dates.length - 1);
    return { 
      valid: true, 
      cycle: estimatedInterval > 200 ? 'yearly' : 'monthly', 
      confidence: 0.5,
      avgInterval: estimatedInterval
    };
  }
  
  // Classify each interval into a cycle type
  const cycleCounts = { monthly: 0, quarterly: 0, yearly: 0 };
  for (const interval of intervals) {
    if (interval >= 300) {
      cycleCounts.yearly++;
    } else if (interval >= 70) {
      cycleCounts.quarterly++;
    } else {
      cycleCounts.monthly++;
    }
  }
  
  // Use the most common cycle (mode), with preference for monthly
  let cycle = 'monthly';
  let expectedInterval = 30;
  
  // Only switch to quarterly/yearly if majority of intervals match
  const totalIntervals = intervals.length;
  if (cycleCounts.yearly > totalIntervals * 0.5) {
    cycle = 'yearly';
    expectedInterval = 365;
  } else if (cycleCounts.quarterly > totalIntervals * 0.5) {
    cycle = 'quarterly';
    expectedInterval = 90;
  } else {
    // Default to monthly - most subscriptions are monthly
    cycle = 'monthly';
    expectedInterval = 30;
  }
  
  const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  
  // Check consistency of intervals
  const tolerance = expectedInterval * 0.5;
  const consistentIntervals = intervals.filter(i => 
    Math.abs(i - expectedInterval) <= tolerance
  ).length;
  
  const consistency = intervals.length > 0 ? consistentIntervals / intervals.length : 0.5;
  
  return {
    valid: consistency >= 0.3 || intervals.length === 1,
    cycle,
    avgInterval,
    confidence: consistency >= 0.6 ? 0.9 : (consistency >= 0.3 ? 0.7 : 0.5)
  };
}

// Payment-related phrases that indicate a real receipt/invoice
const PAYMENT_INDICATORS = [
  'your payment',
  'payment received',
  'payment confirmed',
  'payment confirmation',
  'you were charged',
  'we charged',
  'has been charged',
  'successfully charged',
  'receipt for',
  'your receipt',
  'invoice for',
  'new invoice',
  'subscription renewed',
  'renewal confirmation',
  'thank you for your payment',
  'amount paid',
  'amount charged',
  'transaction completed',
  'order confirmed',
  'billing statement',
  'monthly charge',
  'annual charge',
  'your subscription',
  'membership renewed',
  'payment processed',
  'charge of',
  'paid',
  'total:',
  'amount:',
  'שילמת', // Hebrew: "you paid"
  'קבלה', // Hebrew: "receipt"
  'חשבונית', // Hebrew: "invoice"
  'תשלום', // Hebrew: "payment"
];

// Phrases that indicate this is NOT a payment email
const EXCLUDE_INDICATORS = [
  'try premium',
  'upgrade to',
  'get premium',
  'start your free',
  'free trial',
  'special offer',
  'discount code',
  '% off',
  'limited time',
  'subscribe now',
  'join premium',
  'unlock premium',
  'go premium',
  'promotional',
  'unsubscribe from',
  'email preferences',
  'verify your email',
  'confirm your email',
  'reset password',
  'security alert',
  'sign in attempt',
  'new sign-in',
];

// Junk patterns - general patterns that are definitely NOT subscription names
const JUNK_PATTERNS = [
  // Phrases that aren't company names
  /^your\s/i,
  /^our\s/i,
  /^the\s/i,
  /^see\s/i,
  /^appear\s/i,
  /^include\s/i,
  /^click\s/i,
  /^view\s/i,
  /^this\s/i,
  /^out$/i,
  /^notifications?$/i,
  /legal agreements/i,
  /full transaction/i,
  /transaction details/i,
  /uppercase.*lowercase/i,
  /your account/i,
  /my account/i,
  /בדיקה/, // "test" in Hebrew
  
  // Email addresses (not company names)
  /^service@/i,
  /^noreply@/i,
  /^no-reply@/i,
  /@.*>?$/i,
  /^[a-z0-9._%+-]+@/i,
  
  // Transaction phrases
  /payment received/i,
  /payment sent/i,
];

// Known SaaS/subscription companies - these are definitely subscriptions
// No hardcoded company names - we rely purely on SaaS scoring signals

// Trusted sender patterns for billing
const TRUSTED_SENDER_PATTERNS = [
  'invoice',
  'billing',
  'receipt',
  'receipts',
  'payments',
  'payment',
  'statements',
  'noreply',
  'no-reply',
  'notify',
  'notification',
  'support',
  'orders',
  'order',
  'purchase',
  'subscriptions',
  'paypal',
  'stripe',
];

// Category detection based on keywords
function detectCategory(serviceName, emailContent) {
  const combined = `${serviceName} ${emailContent}`.toLowerCase();
  
  // ═══════════════════════════════════════════════════════════════
  // Generic pattern-based category detection - NO hardcoded names!
  // ═══════════════════════════════════════════════════════════════
  
  // Transportation (toll roads, vehicle tracking, roads)
  if (/toll|כביש|אגרה|כביש אגרה|מעקב רכב|vehicle track|highway|road charge/i.test(combined)) return 'Transportation';
  
  // Insurance
  if (/insurance|ביטוח|פוליסה|policy/i.test(combined)) return 'Insurance';
  
  // AI/ML Tools
  if (/\bai\b|artificial intelligence|machine learning|neural|llm|gpt|language model/i.test(combined)) return 'AI Tools';
  
  // Cloud Storage
  if (/cloud storage|storage plan|icloud|גיבוי ענן|backup|sync|gb plan|tb plan/i.test(combined)) return 'Cloud Storage';
  
  // Developer Tools
  if (/api|sdk|developer|deploy|database|hosting|server|git|code|dev tools|cli|backend|frontend/i.test(combined)) return 'Developer';
  
  // Web Hosting
  if (/domain|dns|web hosting|אחסון אתר|ssl|certificate|website hosting/i.test(combined)) return 'Web Hosting';
  
  // Communication
  if (/sms|telephony|voice api|messaging api|phone number|וויס|הודעות/i.test(combined)) return 'Communication';
  
  // Web Services / Website builders
  if (/website builder|בניית אתר|landing page|ecommerce|online store|חנות אונליין/i.test(combined)) return 'Web Services';
  
  // Productivity
  if (/workspace|collaboration|project management|ניהול פרויקטים|team|צוות/i.test(combined)) return 'Productivity';
  
  // Business Tools (invoicing, accounting)
  if (/invoice|חשבונית|קבלה|receipt|accounting|הנהלת חשבונות|billing system/i.test(combined)) return 'Business Tools';
  
  // Streaming
  if (/stream|video on demand|watch|צפייה|סרטים|movies|tv show/i.test(combined)) return 'Streaming';
  
  // Music
  if (/music|מוזיקה|playlist|audio streaming|podcast/i.test(combined)) return 'Music';
  
  // Gaming
  if (/game|gaming|משחק|play|esport/i.test(combined)) return 'Gaming';
  
  // Design
  if (/design|עיצוב|creative|graphic|photo edit|image edit/i.test(combined)) return 'Design';
  
  // Security
  if (/vpn|antivirus|password manager|security|אבטחה|encrypt/i.test(combined)) return 'Security';
  
  // Education
  if (/course|קורס|learn|למידה|tutorial|education|training/i.test(combined)) return 'Education';
  
  // Fitness
  if (/gym|fitness|כושר|workout|אימון/i.test(combined)) return 'Fitness';
  
  // Telecom
  if (/cellular|סלולר|mobile plan|data plan|גלישה|דקות/i.test(combined)) return 'Telecom';
  
  // Utilities
  if (/electricity|חשמל|water|מים|gas|גז|utility|ארנונה/i.test(combined)) return 'Utilities';
  
  return 'Other';
}

// Normalize company name to merge duplicates
function normalizeCompanyName(name) {
  if (!name) return '';
  
  let normalized = name.trim();
  
  // Remove common business suffixes (universal patterns)
  const suffixesToRemove = [
    // Legal entity suffixes (worldwide)
    /\s*(Inc\.?|LLC|Ltd\.?|Pte\.?\s*Ltd\.?|Corp\.?|GmbH|B\.?V\.?|Limited|Corporation|Company|Co\.?|PBC|S\.?A\.?|בע"?מ)\s*$/i,
    // Common department/team suffixes
    /\s*(Billing|Support|Payments?|Receipts?|Notifications?|Team|Service|Services)\s*$/i,
  ];
  
  for (const suffix of suffixesToRemove) {
    normalized = normalized.replace(suffix, '').trim();
  }
  
  // Remove trailing punctuation
  normalized = normalized.replace(/[,.\-:]+$/, '').trim();
  
  // Remove domain extensions from names like "Wix.com"
  normalized = normalized.replace(/\.(com|io|ai|co|net|org)$/i, '').trim();
  
  return normalized;
}

// Generate a key for deduplication (more aggressive normalization)
function getDeduplicationKey(name) {
  if (!name) return '';
  
  let normalized = normalizeCompanyName(name);
  
  // Additional aggressive normalization for deduplication
  // Remove common product/service words that might cause duplicates
  normalized = normalized
    .replace(/\s*(billing|support|payments?|receipts?|team|service|services|platform|power|365|pro|premium|plus|enterprise)\s*/gi, ' ')
    .trim();
  
  // Remove all non-alphanumeric characters and lowercase
  // Keep Hebrew chars for Hebrew company names
  return normalized
    .toLowerCase()
    .replace(/[^a-z0-9\u0590-\u05FF]/g, '');
}

// Check if company name is junk
function isJunkName(name) {
  if (!name) return true;
  if (name.length < 2 || name.length > 60) return true;
  
  // Check against junk patterns
  for (const pattern of JUNK_PATTERNS) {
    if (pattern.test(name)) return true;
  }
  
  // Too many spaces = likely a phrase, not a company
  if ((name.match(/\s/g) || []).length > 5) return true;
  
  return false;
}

// Extract company name from sender
function extractCompanyFromSender(fromHeader) {
  // Format: "Company Name" <email@domain.com> or Company Name <email@domain.com>
  
  // Try to get the display name first
  let match = fromHeader.match(/^"?([^"<]+)"?\s*</);
  if (match) {
    let name = match[1].trim();
    // Clean up common suffixes
    name = name.replace(/\s*(Inc\.?|LLC|Ltd\.?|Pte\.?\s*Ltd\.?|Corp\.?|GmbH|B\.?V\.?|Limited|Corporation)\s*$/i, '').trim();
    name = name.replace(/\s*(Customer Service|Support|Billing|Payments|Invoice|Receipts|No-?Reply|Notification|Notifications)\s*$/i, '').trim();
    name = name.replace(/,\s*$/, '').trim();
    
    if (!isJunkName(name)) {
      return name;
    }
  }
  
  // Fall back to domain name
  match = fromHeader.match(/@([a-zA-Z0-9-]+)\./);
  if (match) {
    let domain = match[1].toLowerCase();
    // Skip generic domains
    if (['gmail', 'yahoo', 'hotmail', 'outlook', 'mail', 'email', 'paypal', 'stripe'].includes(domain)) {
      return null;
    }
    // Capitalize first letter
    return domain.charAt(0).toUpperCase() + domain.slice(1);
  }
  
  return null;
}

// Extract company name from PayPal emails
function extractCompanyFromPayPal(subject, body) {
  const combined = `${subject} ${body}`;
  
  // Skip if this is a RECEIVED payment (not a subscription)
  const receivedPatterns = [
    /קיבלת\s+כסף/i,           // Hebrew: "you received money"
    /received\s+money/i,       // English
    /sent you money/i,         // "Someone sent you money"
    /שלח לך כסף/i,            // Hebrew: "sent you money"
    /העביר לך כסף/i,          // Hebrew: "transferred you money"
    /קיבלת תשלום מ/i,         // Hebrew: "you received payment from"
  ];
  
  for (const pattern of receivedPatterns) {
    if (pattern.test(combined)) {
      return null; // This is a received payment, not a subscription
    }
  }
  
  // BEST: Extract from subject "התשלום אל [Company]" (payment to Company)
  let match = subject.match(/(?:התשלום|הקבלה).*?אל\s+([A-Za-z][A-Za-z0-9\s&.,'-]{1,50}?)(?:\s*[-–]|$)/);
  if (match && !isJunkName(match[1].trim())) {
    return match[1].trim();
  }
  
  // Hebrew pattern in body: "שילמת $XX.XX USD ל-CompanyName"
  match = combined.match(/ל-([A-Za-z][A-Za-z0-9\s&.-]{1,40}?)(?:\s|$|,|\.|<|!)/);
  if (match && !isJunkName(match[1].trim())) {
    return match[1].trim();
  }
  
  // Look for "בעל עסק" (business owner in Hebrew) followed by company name
  match = combined.match(/בעל עסק[:\s]*([A-Za-z][A-Za-z0-9\s&.-]{1,40}?)(?:\s|$|,|\.|<)/);
  if (match && !isJunkName(match[1].trim())) {
    return match[1].trim();
  }
  
  // English pattern: "Payment to CompanyName" or "paid ... to CompanyName"
  match = combined.match(/(?:payment to|paid to|paid\s+)([A-Za-z][A-Za-z0-9\s&.-]{1,40}?)(?:\s+\$|\s+for|\s+on|\s*$|,|\.|!|<)/i);
  if (match && !isJunkName(match[1].trim())) {
    return match[1].trim();
  }
  
  return null;
}

// Extract price and currency from text - supports multiple currencies and Hebrew
function extractPrice(text) {
  const priceMatches = [];
  
  // Normalize the text - handle Hebrew and various formats
  const normalizedText = text
    .replace(/&nbsp;/g, ' ')                    // HTML non-breaking spaces
    .replace(/&#?\w+;/g, ' ')                   // Other HTML entities
    .replace(/,(\d{2})(?!\d)/g, '.$1')          // Convert ,XX at end to .XX (European decimals)
    .replace(/(\d),(\d{3})/g, '$1$2')           // Remove thousands separators
    .replace(/(\d)\.(\d{3})(?!\d)/g, '$1$2');   // Remove European thousands separators (1.000 -> 1000)
  
  // Price keywords in English and Hebrew
  const priceKeywords = [
    'total', 'amount', 'paid', 'charged', 'price', 'cost', 'payment', 'sum',
    'subtotal', 'grand total', 'amount paid', 'amount due', 'balance', 'charge',
    'סה״כ', 'סהכ', 'סך הכל', 'סכום', 'לתשלום', 'שולם', 'חיוב', 'מחיר',
    'סה"כ', 'סה\'\'כ', 'סה׳׳כ', 'לשלם', 'תשלום', 'עלות', 'סכום לתשלום',
    'סך', 'חויב', 'חויבת', 'נגבה', 'סכום החיוב',
  ];
  
  const keywordPattern = priceKeywords.join('|');
  
  // Patterns with currency detection: [regex, currencyIfMatched]
  const patterns = [
    // Dollar patterns
    { regex: /\$\s*(\d+(?:[.,]\d{1,2})?)/g, currency: 'USD' },
    { regex: /(\d+(?:[.,]\d{1,2})?)\s*USD/gi, currency: 'USD' },
    { regex: /USD\s*(\d+(?:[.,]\d{1,2})?)/gi, currency: 'USD' },
    
    // Euro patterns
    { regex: /€\s*(\d+(?:[.,]\d{1,2})?)/g, currency: 'EUR' },
    { regex: /(\d+(?:[.,]\d{1,2})?)\s*EUR/gi, currency: 'EUR' },
    
    // Shekel patterns - multiple formats
    { regex: /₪\s*(\d+(?:[.,]\d{1,2})?)/g, currency: 'ILS' },
    { regex: /(\d+(?:[.,]\d{1,2})?)\s*₪/g, currency: 'ILS' },
    { regex: /(\d+(?:[.,]\d{1,2})?)\s*(?:ILS|NIS)/gi, currency: 'ILS' },
    { regex: /(\d+(?:[.,]\d{1,2})?)\s*ש["״'׳]?ח/g, currency: 'ILS' },
    { regex: /ש["״'׳]?ח\s*(\d+(?:[.,]\d{1,2})?)/g, currency: 'ILS' },
    { regex: /(\d+(?:[.,]\d{1,2})?)\s*שקל/g, currency: 'ILS' },
    
    // Pound patterns
    { regex: /£\s*(\d+(?:[.,]\d{1,2})?)/g, currency: 'GBP' },
    { regex: /(\d+(?:[.,]\d{1,2})?)\s*GBP/gi, currency: 'GBP' },
  ];
  
  // Also look for prices near keywords (higher priority)
  const keywordPatterns = [
    { regex: new RegExp(`(?:${keywordPattern})[:\\s]*\\$\\s*(\\d+(?:[.,]\\d{1,2})?)`, 'gi'), currency: 'USD' },
    { regex: new RegExp(`(?:${keywordPattern})[:\\s]*€\\s*(\\d+(?:[.,]\\d{1,2})?)`, 'gi'), currency: 'EUR' },
    { regex: new RegExp(`(?:${keywordPattern})[:\\s]*₪\\s*(\\d+(?:[.,]\\d{1,2})?)`, 'gi'), currency: 'ILS' },
    { regex: new RegExp(`(?:${keywordPattern})[:\\s]*£\\s*(\\d+(?:[.,]\\d{1,2})?)`, 'gi'), currency: 'GBP' },
    { regex: new RegExp(`(?:${keywordPattern})[:\\s]*(\\d+(?:[.,]\\d{1,2})?)\\s*(?:₪|ILS|NIS|ש["״'׳]?ח|שקל)`, 'gi'), currency: 'ILS' },
    { regex: new RegExp(`(?:${keywordPattern})[:\\s]*(\\d+(?:[.,]\\d{1,2})?)\\s*USD`, 'gi'), currency: 'USD' },
    // Hebrew keyword followed by number (assume ILS)
    { regex: new RegExp(`(?:סה״כ|סהכ|סך הכל|סכום|לתשלום|חיוב)[:\\s]*(\\d+(?:[.,]\\d{1,2})?)`, 'gi'), currency: 'ILS' },
  ];
  
  // Run keyword patterns first (higher priority)
  for (const { regex, currency } of keywordPatterns) {
    let match;
    regex.lastIndex = 0;
    while ((match = regex.exec(normalizedText)) !== null) {
      const priceStr = match[1].replace(',', '.');
      const price = parseFloat(priceStr);
      if (price >= 0.50 && price <= 10000) {
        priceMatches.push({ price, currency, priority: 2 });
      }
    }
  }
  
  // Then run regular patterns
  for (const { regex, currency } of patterns) {
    let match;
    regex.lastIndex = 0;
    while ((match = regex.exec(normalizedText)) !== null) {
      const priceStr = match[1].replace(',', '.');
      const price = parseFloat(priceStr);
      if (price >= 0.50 && price <= 10000) {
        // Check if we already have this price
        const exists = priceMatches.some(p => p.price === price && p.currency === currency);
        if (!exists) {
          priceMatches.push({ price, currency, priority: 1 });
        }
      }
    }
  }
  
  if (priceMatches.length === 0) return { price: null, currency: 'USD' };
  
  // Score prices by likelihood of being a subscription amount
  const scoredPrices = priceMatches.map(({ price, currency, priority }) => {
    let score = priority * 10; // Base score from priority
    
    // Common subscription price ranges get higher scores
    if (price >= 5 && price <= 30) score += 3;
    else if (price >= 30 && price <= 100) score += 2;
    else if (price >= 1 && price <= 5) score += 1;
    else if (price > 500) score -= 2;
    
    // Round numbers are more likely
    if (price % 1 === 0) score += 1;
    if (price % 5 === 0) score += 1;
    if ([9.99, 19.99, 29.99, 49.99, 4.99, 14.99, 24.99].includes(price)) score += 2;
    
    return { price, currency, score };
  });
  
  // Sort by score descending
  scoredPrices.sort((a, b) => b.score - a.score);
  
  return { price: scoredPrices[0].price, currency: scoredPrices[0].currency };
}

// Parse date from email
function parseEmailDate(dateStr) {
  if (!dateStr) return null;
  try {
    return new Date(dateStr);
  } catch (e) {
    return null;
  }
}

// Check if email looks like a payment/invoice
function isPaymentEmail(from, subject, body) {
  const combined = `${from} ${subject} ${body}`.toLowerCase();
  
  for (const exclude of EXCLUDE_INDICATORS) {
    if (combined.includes(exclude.toLowerCase())) {
      return false;
    }
  }
  
  const fromLower = from.toLowerCase();
  const hasTrustedSender = TRUSTED_SENDER_PATTERNS.some(pattern => fromLower.includes(pattern));
  const hasPaymentIndicator = PAYMENT_INDICATORS.some(indicator => combined.includes(indicator.toLowerCase()));
  
  return hasTrustedSender || hasPaymentIndicator;
}

// Main parsing function
async function parseSubscriptionEmails(emails, accountEmail = '') {
  // Track all occurrences with dates and prices
  const occurrences = new Map(); // key -> { name, dates: [], prices: [], ... }
  
  // Extract user's name from email for filtering
  const userNameFromEmail = accountEmail.split('@')[0]
    .replace(/[._]/g, ' ')
    .replace(/\d+/g, '')
    .trim()
    .toLowerCase();
  
  // Also try to extract user's name from email greetings
  const userNames = new Set();
  if (userNameFromEmail) {
    userNames.add(userNameFromEmail);
  }
  
  // First pass: find user's name from greetings in emails
  for (const email of emails) {
    const body = email.snippet || '';
    
    // Look for greeting patterns - capture the name after greeting words
    const greetingPatterns = [
      /היי[,\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)[,!\s]/,  // Hebrew "Hi" + Capitalized English name
      /שלום[,\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)[,!\s]/, // Hebrew "Hello" + Capitalized English name
      /\bHi[,\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)[,!\s]/,
      /\bHello[,\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)[,!\s]/,
      /\bDear[,\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)[,!\s]/,
    ];
    
    for (const pattern of greetingPatterns) {
      const match = body.match(pattern);
      if (match) {
        const name = match[1].trim().toLowerCase();
        // Only add if it looks like a real name (3-15 chars per word, max 2 words)
        const parts = name.split(/\s+/);
        if (parts.length <= 2 && parts.every(p => p.length >= 3 && p.length <= 15)) {
          userNames.add(name);
          parts.forEach(part => userNames.add(part));
        }
      }
    }
  }
  
  console.log(`\n📧 Analyzing ${emails.length} emails for subscriptions...`);
  if (userNames.size > 0) {
    console.log(`  👤 User names to filter: ${[...userNames].join(', ')}\n`);
  } else {
    console.log('');
  }
  
  for (const email of emails) {
    const from = email.from || '';
    const subject = email.subject || '';
    const body = email.snippet || '';
    const combined = `${subject} ${body}`;
    const emailDate = parseEmailDate(email.date);
    
    if (!isPaymentEmail(from, subject, body)) {
      continue;
    }
    
    // Extract company name
    let companyName = null;
    const fromLower = from.toLowerCase();
    
    // Special handling for PayPal
    if (fromLower.includes('paypal')) {
      companyName = extractCompanyFromPayPal(subject, body);
      if (companyName) {
        console.log(`  📍 PayPal payment → ${companyName}`);
      }
    }
    
    // Special handling for Stripe
    if (!companyName && fromLower.includes('stripe')) {
      const match = combined.match(/(?:payment to|from|for)\s+([A-Za-z][A-Za-z0-9\s&.-]{1,40}?)(?:\s|$|,|\.|<)/i);
      if (match && !isJunkName(match[1].trim())) {
        companyName = match[1].trim();
        console.log(`  📍 Stripe payment → ${companyName}`);
      }
    }
    
    // Fall back to extracting from sender
    if (!companyName) {
      companyName = extractCompanyFromSender(from);
    }
    
    // Skip junk
    if (!companyName || isJunkName(companyName)) {
      if (fromLower.includes('paypal') || fromLower.includes('stripe')) {
        console.log(`  ⚠️  Skipped: Couldn't identify merchant from PayPal/Stripe email`);
      }
      continue;
    }
    
    // Check if this is clearly a one-time event (flight, hotel, shipping)
    if (isOneTimeEvent(subject, body)) {
      console.log(`  ⏭️  Skipped ${companyName}: One-time event (flight/hotel/shipping)`);
      continue;
    }
    
    // Check if this is a non-subscription recurring service (airline loyalty, crypto, etc.)
    if (isNonSubscriptionService(companyName, combined)) {
      console.log(`  ⏭️  Skipped ${companyName}: Non-subscription service (loyalty/crypto/banking)`);
      continue;
    }
    
    // Extract price and currency
    const { price, currency } = extractPrice(combined);
    
    // Debug: Log potential prices when none extracted
    if (!price) {
      const possiblePrices = combined.match(/[\$₪€£]\s*\d+(?:[.,]\d{2})?|\d+(?:[.,]\d{2})?\s*(?:USD|ILS|NIS|EUR|GBP)/gi);
      if (possiblePrices && possiblePrices.length > 0) {
        console.log(`  💰 ${companyName}: Found numbers but no price extracted: ${possiblePrices.slice(0, 3).join(', ')}`);
      }
    }
    
    // Normalize company name and generate dedup key
    const normalizedName = normalizeCompanyName(companyName);
    const key = getDeduplicationKey(companyName);
    
    // Skip if this looks like the user's own name
    const normalizedLower = normalizedName.toLowerCase();
    const isUserName = [...userNames].some(userName => {
      // Only match if userName is at least 4 chars to avoid false positives
      if (userName.length < 4) return false;
      
      // Check for full match or significant overlap
      return normalizedLower === userName ||
        (normalizedLower.includes(userName) && userName.length >= normalizedLower.length * 0.5) ||
        (userName.includes(normalizedLower) && normalizedLower.length >= userName.length * 0.5);
    });
    
    // Check if it looks like a personal name (general rules):
    // - Two short Hebrew words (2-10 chars each) = likely FirstName LastName
    // - But NOT if it contains business indicators
    const hebrewPersonNamePattern = /^[\u0590-\u05FF]{2,10}\s+[\u0590-\u05FF]{2,10}$/;
    const hasBusinessIndicators = /\d|@|ltd|inc|llc|בע"מ|בעמ|חברה|רשת|מערכת|שירות|ביטוח|בנק|כביש|נתיב|מסלול|מרפאה|קליניקה|סוכנות|משרד|קופת|חולים|דר\s|ד"ר/i.test(normalizedName);
    const looksLikeHebrewPersonName = hebrewPersonNamePattern.test(normalizedName) && !hasBusinessIndicators;
    
    if (isUserName || looksLikeHebrewPersonName) {
      console.log(`  ⏭️  Skipped ${normalizedName}: Looks like a personal name`);
      continue;
    }
    
    if (!occurrences.has(key)) {
      occurrences.set(key, {
        name: normalizedName,
        dates: [],
        prices: [],
        currencies: [],
        languageBonuses: [],
        hasYearlyLanguage: false,
        sender_email: from,
        detected_from_subject: subject,
        category: detectCategory(normalizedName, combined),
      });
    }
    
    // Calculate language bonus for this email
    const languageBonus = calculateLanguageBonus(subject, body);
    const yearlyLanguage = hasExplicitYearlyLanguage(subject, body);
    
    const occ = occurrences.get(key);
    if (emailDate) {
      occ.dates.push(emailDate);
    }
    if (price) {
      occ.prices.push(price);
      occ.currencies.push(currency);
    }
    occ.languageBonuses.push(languageBonus);
    if (yearlyLanguage) {
      occ.hasYearlyLanguage = true;
    }
  }
  
  // ══════════════════════════════════════════════════════════════════
  // FINAL DECISION: Is this a recurring payment/subscription?
  // ══════════════════════════════════════════════════════════════════
  
  const now = new Date();
  const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
  const fourHundredDaysAgo = new Date(now.getTime() - 400 * 24 * 60 * 60 * 1000);
  
  const activeSubscriptions = [];
  
  for (const [key, occ] of occurrences) {
    const count = occ.dates.length;
    const mostRecentDate = count > 0 ? new Date(Math.max(...occ.dates.map(d => d.getTime()))) : null;
    
    // Skip if no dates could be extracted
    if (count === 0) {
      console.log(`  ⏭️  Skipped ${occ.name}: No payment dates found`);
      continue;
    }
    
    // ─────────────────────────────────────────────────────────────────
    // Rule 2: Check recurrence (MANDATORY)
    // 2.1: At least 2 charges, OR
    // 2.2: 1 charge + explicit yearly language
    // ─────────────────────────────────────────────────────────────────
    const hasRepeatedCharges = count >= 2;
    const hasExplicitYearly = count === 1 && occ.hasYearlyLanguage;
    const isValidSubscription = hasRepeatedCharges || hasExplicitYearly;
    
    if (!isValidSubscription) {
      console.log(`  ⏭️  Skipped ${occ.name}: One-time payment (${count}x, no yearly language)`);
      continue;
    }
    
    // ─────────────────────────────────────────────────────────────────
    // Rule 1: Check recency (MANDATORY)
    // - Monthly/quarterly: 90 days
    // - Yearly: 400 days
    // ─────────────────────────────────────────────────────────────────
    const cadence = checkCadenceConsistency(occ.dates);
    const isYearly = cadence.cycle === 'yearly' || hasExplicitYearly;
    const recencyThreshold = isYearly ? fourHundredDaysAgo : ninetyDaysAgo;
    
    if (!mostRecentDate || mostRecentDate < recencyThreshold) {
      const daysAgo = mostRecentDate ? Math.floor((now - mostRecentDate) / (1000 * 60 * 60 * 24)) : 'unknown';
      console.log(`  ⏭️  Skipped ${occ.name}: Inactive (last: ${daysAgo} days ago, cycle: ${cadence.cycle})`);
      continue;
    }
    
    // ─────────────────────────────────────────────────────────────────
    // Rule 3 & 4: Check consistency (SUPPORTING - improves confidence)
    // ─────────────────────────────────────────────────────────────────
    const amountCheck = checkAmountConsistency(occ.prices);
    
    // Reject only if there's an extreme spike in pricing (likely error or different service)
    if (amountCheck.reason === 'extreme_spike') {
      console.log(`  ⏭️  Skipped ${occ.name}: Extreme price variance (likely different services)`);
      continue;
    }
    
    // ─────────────────────────────────────────────────────────────────
    // Special handling for medical/vet services (often irregular visits)
    // These need consistent cadence to be considered subscriptions
    // ─────────────────────────────────────────────────────────────────
    if (isIrregularServiceType(occ.name)) {
      // For medical/vet, require good cadence consistency
      if (cadence.confidence < 0.7 || !cadence.valid) {
        console.log(`  ⏭️  Skipped ${occ.name}: Irregular visits (not a subscription)`);
        continue;
      }
    }
    
    // ─────────────────────────────────────────────────────────────────
    // Rule 5: Calculate language bonus (SUPPORTING)
    // ─────────────────────────────────────────────────────────────────
    const avgLanguageBonus = occ.languageBonuses.length > 0
      ? occ.languageBonuses.reduce((a, b) => a + b, 0) / occ.languageBonuses.length
      : 0;
    
    // ─────────────────────────────────────────────────────────────────
    // Calculate overall confidence
    // ─────────────────────────────────────────────────────────────────
    let confidence = 0.5; // Base confidence
    
    // Recurrence boosts confidence
    if (count >= 3) confidence += 0.2;
    else if (count >= 2) confidence += 0.1;
    
    // Amount consistency boosts confidence
    confidence += (amountCheck.confidence - 0.5) * 0.3;
    
    // Cadence consistency boosts confidence
    confidence += (cadence.confidence - 0.5) * 0.2;
    
    // Language bonus boosts confidence
    confidence += Math.min(avgLanguageBonus * 0.02, 0.1);
    
    // Cap confidence
    confidence = Math.min(Math.max(confidence, 0.3), 0.95);
    
    // ─────────────────────────────────────────────────────────────────
    // ACCEPTED! Prepare output
    // ─────────────────────────────────────────────────────────────────
    const price = occ.prices.length > 0 ? occ.prices[occ.prices.length - 1] : null;
    const currency = occ.currencies && occ.currencies.length > 0 ? occ.currencies[occ.currencies.length - 1] : 'USD';
    
    const currencySymbols = { USD: '$', EUR: '€', GBP: '£', ILS: '₪' };
    const symbol = currencySymbols[currency] || '$';
    
    // Confidence indicator
    const confIndicator = confidence >= 0.8 ? '💎' : (confidence >= 0.6 ? '✅' : '⚠️');
    const status = `🔄 ${count}x`;
    
    if (price) {
      console.log(`  ${confIndicator} ${status} ${occ.name} - ${symbol}${price} (${occ.category}) [${cadence.cycle}, conf: ${(confidence * 100).toFixed(0)}%]`);
    } else {
      console.log(`  ${confIndicator} ${status} ${occ.name} - no price (${occ.category}) [${cadence.cycle}, conf: ${(confidence * 100).toFixed(0)}%]`);
    }
    
    activeSubscriptions.push({
      name: occ.name,
      category: occ.category,
      price: price,
      currency: currency,
      billing_cycle: cadence.cycle,
      sender_email: occ.sender_email,
      detected_from_subject: occ.detected_from_subject,
      last_seen_date: mostRecentDate?.toISOString(),
      occurrence_count: count,
      confidence: confidence,
      is_yearly: isYearly,
      amount_consistency: amountCheck.reason,
    });
  }
  
  // Filter out subscriptions with no price
  const subsWithPrice = activeSubscriptions.filter(s => s.price !== null);
  const filteredCount = activeSubscriptions.length - subsWithPrice.length;
  
  if (filteredCount > 0) {
    console.log(`  ⏭️  Filtered out ${filteredCount} subscription(s) with no price`);
  }
  
  console.log(`\n📊 Found ${subsWithPrice.length} active subscriptions (filtered from ${occurrences.size} detected)\n`);
  
  return subsWithPrice;
}

function saveSubscription(accountId, sub) {
  // Normalize the subscription name
  const normalizedName = normalizeCompanyName(sub.name);
  const dedupKey = getDeduplicationKey(sub.name);
  
  // Check if already exists (using normalized comparison)
  const existing = dbGet(
    `SELECT id, name FROM subscriptions WHERE account_id = ?`, 
    [accountId]
  );
  
  // Check all existing subscriptions for this account
  const allExisting = dbAll(`SELECT id, name FROM subscriptions WHERE account_id = ?`, [accountId]);
  
  for (const row of allExisting) {
    const existingKey = getDeduplicationKey(row.name);
    if (existingKey === dedupKey) {
      // Found a match - update if we have new price info
      if (sub.price) {
        dbRun(`UPDATE subscriptions SET price = ?, currency = ?, updated_at = strftime('%s', 'now') WHERE id = ?`, [sub.price, sub.currency || 'USD', row.id]);
      }
      return false;
    }
  }
  
  // Insert new
  const id = crypto.randomUUID();
  dbRun(
    `INSERT INTO subscriptions (id, account_id, name, price, currency, billing_cycle, category, sender_email, detected_from_subject, confidence, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
    [id, accountId, normalizedName, sub.price, sub.currency || 'USD', sub.billing_cycle, sub.category, sub.sender_email, sub.detected_from_subject, sub.confidence]
  );
  
  return true;
}

// ============================================
// START SERVER
// ============================================
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║         Subscription Tracker API Server                   ║
╠═══════════════════════════════════════════════════════════╣
║  Server running at: http://localhost:${PORT}                 ║
║                                                           ║
║  Endpoints:                                               ║
║  • GET  /auth/google        - Connect Gmail account       ║
║  • GET  /auth/microsoft     - Connect Outlook account     ║
║  • GET  /api/accounts       - List connected accounts     ║
║  • DELETE /api/accounts/:id - Remove an account           ║
║  • GET  /api/subscriptions  - List all subscriptions      ║
║  • POST /api/subscriptions  - Add subscription manually   ║
║  • POST /api/sync           - Sync all accounts           ║
║  • POST /api/accounts/:id/sync - Sync single account      ║
║  • GET  /api/stats          - Dashboard statistics        ║
╚═══════════════════════════════════════════════════════════╝
    `);
  });
});

module.exports = app;