document.addEventListener('DOMContentLoaded', () => {
    // Helper: base API URL
    const API_BASE = location.origin + '/auth';
    
    // Form switching functionality
    const switchBtns = document.querySelectorAll('.switch-btn');
    const forms = document.querySelectorAll('.form');

    switchBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all buttons and forms
            switchBtns.forEach(b => b.classList.remove('active'));
            forms.forEach(f => f.classList.remove('active'));

            // Add active class to clicked button and corresponding form
            btn.classList.add('active');
            const formToShow = btn.dataset.form === 'login' ? 'loginForm' : 'signupForm';
            document.getElementById(formToShow).classList.add('active');
        });
    });

    // Password strength checker
    function checkPasswordStrength(password) {
        const requirements = {
            length: password.length >= 12,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /\d/.test(password),
            special: /[@$!%*?&]/.test(password)
        };
        return requirements;
    }

    // Login form submission
    const loginForm = document.getElementById('loginForm');
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        const twoFactorCode = document.getElementById('login2FACode').value;

        // Basic validation
        if (!email || !password) {
            showError('Please fill in all fields');
            return;
        }

        try {
            // Call backend login
            const resp = await fetch(API_BASE + '/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            const data = await resp.json();
            if (!resp.ok) return showError(data.error || 'Login failed');
            // Save token and show user info
            localStorage.setItem('token', data.token);
            populateUserInfoFromToken(data.token);
            showForm('userInfo');
        } catch (error) {
            showError('Login failed: ' + error.message);
        }
    });

    // Sign up form submission
    const signupForm = document.getElementById('signupForm');
    signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('signupName').value;
        const email = document.getElementById('signupEmail').value;
        const password = document.getElementById('signupPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        // Enhanced validation
        if (!name || !email || !password || !confirmPassword) {
            showError('Please fill in all fields');
            return;
        }

        if (password !== confirmPassword) {
            showError('Passwords do not match');
            return;
        }

        const passwordStrength = checkPasswordStrength(password);
        if (!Object.values(passwordStrength).every(Boolean)) {
            showError('Password does not meet security requirements');
            return;
        }

        try {
            const resp = await fetch(API_BASE + '/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            const data = await resp.json();
            if (!resp.ok) return showError(data.error || 'Signup failed');
            // save token returned on register
            if (data.token) {
                localStorage.setItem('token', data.token);
                populateUserInfoFromToken(data.token);
                showForm('userInfo');
            } else {
                showSuccess('Signup successful — check your email to verify.');
            }
        } catch (error) {
            showError('Signup failed: ' + error.message);
        }
    });

    // Email verification form submission
    const emailVerificationForm = document.getElementById('emailVerificationForm');
    emailVerificationForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = document.getElementById('verificationCode').value;

        try {
            const resp = await fetch(API_BASE + '/verify?token=' + encodeURIComponent(code));
            const data = await resp.json();
            if (!resp.ok) return showError(data.error || 'Verification failed');
            showSuccess('Email verified');
            showForm('loginForm');
        } catch (error) {
            showError('Verification failed: ' + error.message);
        }
    });

    // 2FA setup form submission
    const twoFactorSetupForm = document.getElementById('2faSetupForm');
    twoFactorSetupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = document.getElementById('2faCode').value;

        try {
            // 2FA setup should be handled via backend; show success placeholder
            showSuccess('2FA setup flow not implemented in demo frontend');
        } catch (error) {
            showError('2FA setup failed: ' + error.message);
        }
    });

    // Helper functions
    function showError(message) {
        const existingError = document.querySelector('.error');
        if (existingError) {
            existingError.remove();
        }

        const errorDiv = document.createElement('div');
        errorDiv.className = 'error';
        errorDiv.textContent = message;
        
        const activeForm = document.querySelector('.form.active');
        activeForm.appendChild(errorDiv);
    }

    function showSuccess(message) {
        const successDiv = document.createElement('div');
        successDiv.className = 'verification-success';
        successDiv.textContent = message;
        
        const activeForm = document.querySelector('.form.active');
        activeForm.appendChild(successDiv);
    }

    function showForm(formId) {
        forms.forEach(f => f.classList.remove('active'));
        document.getElementById(formId).classList.add('active');
    }

    function generateQRCode() {
        const qrContainer = document.getElementById('qrCode');
        qrContainer.innerHTML = '';
        
        new QRCode(qrContainer, {
            text: secret.otpauth_url,
            width: 200,
            height: 200
        });
    }

    function generateBackupCodes() {
        const codes = [];
        for (let i = 0; i < 8; i++) {
            codes.push(Math.random().toString(36).substr(2, 8).toUpperCase());
        }
        return codes;
    }

    function parseJwt(token) {
        try {
            const payload = token.split('.')[1];
            return JSON.parse(atob(payload));
        } catch (e) { return null; }
    }

    function populateUserInfoFromToken(token) {
        const p = parseJwt(token);
        if (!p) return;
        document.getElementById('userEmail').textContent = p.email || '';
        document.getElementById('userRole').textContent = p.role || '';
        document.getElementById('userPerms').textContent = p.permissions || '';
        if ((p.role || '').includes('admin')) document.getElementById('adminLink').style.display = 'inline';
    }

    // Logout
    document.getElementById('logoutBtn').addEventListener('click', () => {
        localStorage.removeItem('token');
        location.reload();
    });
});