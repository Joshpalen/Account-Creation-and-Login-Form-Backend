const nodemailer = require('nodemailer');
const config = require('./config');
const logger = require('./logger');

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
    logger.info('mailer disabled — would send', opts);
    return;
  }
  return transporter.sendMail(opts);
}

module.exports = { sendMail };
