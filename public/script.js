document.addEventListener('DOMContentLoaded', () => {
  // Base API URLs (support separate frontend hosting)
  const API_BASE_URL = (window.API_BASE_URL || location.origin);
  const AUTH_BASE = API_BASE_URL + '/auth';
  const TOTP_BASE = API_BASE_URL + '/totp';

  // Form switching
  const switchBtns = document.querySelectorAll('.switch-btn');
  const forms = document.querySelectorAll('.form');
  switchBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      switchBtns.forEach((b) => b.classList.remove('active'));
      forms.forEach((f) => f.classList.remove('active'));
      btn.classList.add('active');
      const formToShow = btn.dataset.form === 'login' ? 'loginForm' : 'signupForm';
      document.getElementById(formToShow).classList.add('active');
    });
  });

  // Password strength check
  function checkPasswordStrength(password) {
    return {
      length: password.length >= 12,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /\d/.test(password),
      special: /[@$!%*?&]/.test(password),
    };
  }

  // Login
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('loginEmail').value;
      const password = document.getElementById('loginPassword').value;
      if (!email || !password) return showError('Please fill in all fields');
      try {
        const resp = await fetch(AUTH_BASE + '/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        const data = await resp.json();
        if (!resp.ok) return showError(data.error || 'Login failed');
        localStorage.setItem('token', data.token);
        populateUserInfoFromToken(data.token);
        showForm('userInfo');
      } catch (err) {
        showError('Login failed: ' + err.message);
      }
    });
  }

  // Signup
  const signupForm = document.getElementById('signupForm');
  if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('signupName').value;
      const email = document.getElementById('signupEmail').value;
      const password = document.getElementById('signupPassword').value;
      const confirmPassword = document.getElementById('confirmPassword').value;
      if (!name || !email || !password || !confirmPassword) return showError('Please fill in all fields');
      if (password !== confirmPassword) return showError('Passwords do not match');
      const strength = checkPasswordStrength(password);
      if (!Object.values(strength).every(Boolean)) return showError('Password does not meet security requirements');
      try {
        const resp = await fetch(AUTH_BASE + '/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        const data = await resp.json();
        if (!resp.ok) return showError(data.error || 'Signup failed');
        if (data.token) {
          localStorage.setItem('token', data.token);
          populateUserInfoFromToken(data.token);
          showForm('userInfo');
        } else {
          showSuccess('Signup successful — check your email to verify.');
        }
      } catch (err) {
        showError('Signup failed: ' + err.message);
      }
    });
  }

  // Email verification (paste link or token)
  const emailVerificationForm = document.getElementById('emailVerificationForm');
  if (emailVerificationForm) {
    emailVerificationForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const raw = document.getElementById('verificationCode').value.trim();
      let token = raw;
      try {
        if (raw.includes('http')) {
          const u = new URL(raw);
          token = u.searchParams.get('token') || raw;
        }
      } catch {}
      try {
        const resp = await fetch(AUTH_BASE + '/verify?token=' + encodeURIComponent(token));
        const data = await resp.json();
        if (!resp.ok) return showError(data.error || 'Verification failed');
        showSuccess('Email verified');
        showForm('loginForm');
      } catch (err) {
        showError('Verification failed: ' + err.message);
      }
    });
  }

  // Password reset request
  const recoverBtn = document.querySelector('.recover-btn');
  if (recoverBtn) recoverBtn.addEventListener('click', () => showForm('resetPasswordForm'));
  const resetPasswordForm = document.getElementById('resetPasswordForm');
  if (resetPasswordForm) {
    resetPasswordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('resetEmail').value;
      try {
        const resp = await fetch(AUTH_BASE + '/password-reset', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        const data = await resp.json();
        if (!resp.ok) return showError(data.error || 'Password reset failed');
        showSuccess('Reset link sent — check your email');
      } catch (err) {
        showError('Password reset failed: ' + err.message);
      }
    });
  }

  // 2FA: setup, verify, disable
  let currentTotp = null;
  const setup2faBtn = document.getElementById('setup2faBtn');
  const disable2faBtn = document.getElementById('disable2faBtn');
  const twoFactorSetupForm = document.getElementById('2faSetupForm');

  if (setup2faBtn) {
    setup2faBtn.addEventListener('click', async () => {
      const token = localStorage.getItem('token');
      if (!token) return showError('You must be logged in');
      try {
        const resp = await fetch(TOTP_BASE + '/setup', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + token },
        });
        const data = await resp.json();
        if (!resp.ok) return showError(data.error || 'Failed to start 2FA');
        currentTotp = data; // { otpauth_url, base32 }
        const qrContainer = document.getElementById('qrCode');
        if (qrContainer) {
          qrContainer.innerHTML = '';
          new QRCode(qrContainer, { text: data.otpauth_url, width: 200, height: 200 });
        }
        showForm('2faSetupForm');
      } catch (err) {
        showError('Failed to start 2FA: ' + err.message);
      }
    });
  }

  if (twoFactorSetupForm) {
    twoFactorSetupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('2faCode').value;
      const token = localStorage.getItem('token');
      if (!token) return showError('You must be logged in');
      try {
        const resp = await fetch(TOTP_BASE + '/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
          body: JSON.stringify({ token: code }),
        });
        const data = await resp.json();
        if (!resp.ok) return showError(data.error || '2FA verification failed');
        showSuccess('2FA enabled');
        showForm('userInfo');
      } catch (err) {
        showError('2FA verification failed: ' + err.message);
      }
    });
  }

  if (disable2faBtn) {
    disable2faBtn.addEventListener('click', async () => {
      const token = localStorage.getItem('token');
      if (!token) return showError('You must be logged in');
      try {
        const resp = await fetch(TOTP_BASE + '/disable', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + token },
        });
        const data = await resp.json();
        if (!resp.ok) return showError(data.error || 'Failed to disable 2FA');
        showSuccess('2FA disabled');
      } catch (err) {
        showError('Failed to disable 2FA: ' + err.message);
      }
    });
  }

  // Helpers
  function showError(message) {
    const existing = document.querySelector('.error');
    if (existing) existing.remove();
    const div = document.createElement('div');
    div.className = 'error';
    div.textContent = message;
    const active = document.querySelector('.form.active');
    active && active.appendChild(div);
  }

  function showSuccess(message) {
    const div = document.createElement('div');
    div.className = 'verification-success';
    div.textContent = message;
    const active = document.querySelector('.form.active');
    active && active.appendChild(div);
  }

  function showForm(formId) {
    forms.forEach((f) => f.classList.remove('active'));
    document.getElementById(formId).classList.add('active');
  }

  function parseJwt(token) {
    try {
      const payload = token.split('.')[1];
      return JSON.parse(atob(payload));
    } catch (e) {
      return null;
    }
  }

  function populateUserInfoFromToken(token) {
    const p = parseJwt(token);
    if (!p) return;
    document.getElementById('userEmail').textContent = p.email || '';
    document.getElementById('userRole').textContent = p.role || '';
    document.getElementById('userPerms').textContent = p.permissions || '';
    if ((p.role || '').includes('admin')) document.getElementById('adminLink').style.display = 'inline';
  }

  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      localStorage.removeItem('token');
      location.reload();
    });
  }
});

