const nodemailer = require('nodemailer');
const config = require('./config');
const logger = require('./logger');
const fs = require('fs');
const path = require('path');

let transporter = null;
if (config.SMTP_HOST && config.SMTP_PORT) {
  transporter = nodemailer.createTransport({
    host: config.SMTP_HOST,
    port: Number(config.SMTP_PORT),
    secure: false,
    auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASS } : undefined,
  });
}

async function sendMail(opts) {
  if (!transporter) {
    logger.info('mailer disabled - would send', opts);
    return;
  }
  return transporter.sendMail(opts);
}

function renderTemplate(templateName, vars) {
  const base = path.join(__dirname, 'emails', 'templates');
  const txtPath = path.join(base, `${templateName}.txt`);
  const htmlPath = path.join(base, `${templateName}.html`);
  let text = '';
  let html = '';
  try {
    if (fs.existsSync(txtPath)) text = fs.readFileSync(txtPath, 'utf8');
    if (fs.existsSync(htmlPath)) html = fs.readFileSync(htmlPath, 'utf8');
  } catch (e) {
    logger.error('error reading email template %s: %o', templateName, e);
  }
  Object.keys(vars || {}).forEach((k) => {
    const re = new RegExp(`{{\\s*${k}\\s*}}`, 'g');
    text = text.replace(re, String(vars[k]));
    html = html.replace(re, String(vars[k]));
  });
  return { text, html };
}

async function sendTemplate({ to, subject, template, vars }) {
  const { text, html } = renderTemplate(template, vars);
  if (!transporter) {
    logger.info('mailer disabled - would send template %s to %s', template, to);
    logger.info('rendered text: %s', text);
    return;
  }
  return transporter.sendMail({ to, subject, text, html });
}

module.exports = { sendMail, sendTemplate, renderTemplate };

