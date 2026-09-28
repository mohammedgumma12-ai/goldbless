const authScreen = document.getElementById('authScreen');
const dashboardScreen = document.getElementById('dashboardScreen');
const toast = document.getElementById('toast');
const authTabs = document.querySelectorAll('.tab');
const authForms = document.querySelectorAll('.auth-form');
const navItems = document.querySelectorAll('.nav-item');
const pagePanels = document.querySelectorAll('.page-panel');
const quickItems = document.querySelectorAll('.quick-item');

const state = {
  authMode: 'login',
  isLoggedIn: false,
  registerOtpRequested: false,
  recoveryOtpRequested: false,
  referrerCode: '',
  referralCount: 0,
  api: {
    status: 'ready',
    depositVerified: true,
    lastAction: 'waiting',
    configLoaded: true,
    depositConfigured: true
  },
  userData: {
    phone: '',
    email: '',
    inviteCode: '',
    level: 1,
    totalAssets: 0.00,
    flexibleAssets: 0.00,
    totalIncome: 0.00,
    todayIncome: 0.00,
    teamIncome: 0.00,
    quantifyLeft: 5
  },
};

function applyReferralFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const ref = params.get('ref');
  if (ref) {
    state.referrerCode = ref.trim();
    const inviteInput = document.getElementById('inviteCodeInput');
    if (inviteInput) inviteInput.value = ref.trim();
  }
}

function showToast(message, type = 'success') {
  if (!toast) return;
  toast.textContent = message;
  toast.classList.remove('error');
  if (type === 'error') toast.classList.add('error');
  toast.classList.add('show');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove('show'), 3200);
}

function setAuthMode(mode) {
  state.authMode = mode;
  authTabs.forEach((tab) => tab.classList.toggle('active', tab.dataset.mode === mode));
  authForms.forEach((form) => {
    const shouldShow = form.id === (mode === 'login' ? 'loginForm' : mode === 'forgot' ? 'forgotForm' : 'registerForm');
    form.classList.toggle('active', shouldShow);
  });
}

function setPage(target) {
  navItems.forEach((item) => item.classList.toggle('active', item.dataset.target === target));
  pagePanels.forEach((panel) => panel.classList.toggle('active', panel.id === `${target}Page`));
}

function refreshLevelState() {
  const levelText = `VIP ${state.userData.level}`;
  const rateText = state.userData.level === 1 ? '1.5% يومياً' : `${(state.userData.level * 1.5).toFixed(1)}% يومياً`;

  const elemMap = {
    'currentLevelText': levelText,
    'profitRateText': rateText,
    'profileLevel': levelText,
    'levelBadge': levelText,
    'referralCountText': `${state.referralCount} أعضاء`,
    'teamMemberCount': String(state.referralCount),
    'statusRate': rateText,
    'statusState': 'نشط ومربوط',
    'depositStatus': 'نشط'
  };

  for (const [id, value] of Object.entries(elemMap)) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }
}

function updateProfileUI() {
  const setElText = (id, text) => {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  };

  setElText('profilePhone', state.userData.phone || '—');
  setElText('profileEmail', state.userData.email || '—');
  setElText('profileInvite', state.userData.inviteCode || '—');
  setElText('profileBalance', `${state.userData.totalAssets.toFixed(2)} USDT`);
  setElText('profileTotalIncome', `${state.userData.totalIncome.toFixed(2)} USDT`);
  setElText('inviteCodeDisplay', state.userData.inviteCode || '—');
  setElText('totalAssets', state.userData.totalAssets.toFixed(2));
  setElText('flexibleAssets', `${state.userData.flexibleAssets.toFixed(2)} USDT`);
  setElText('teamIncome', `+${state.userData.teamIncome.toFixed(2)} USDT`);

  setElText('todayProfitText', `${state.userData.todayIncome.toFixed(2)} USDT`);
  setElText('quantifyLeftText', `${state.userData.quantifyLeft} مرات متبقية`);

  refreshLevelState();
}

async function apiRequest(route, data) {
  const response = await fetch(`/api${route}`, {
    method: data ? 'POST' : 'GET',
    headers: data ? { 'Content-Type': 'application/json' } : {},
    credentials: 'same-origin',
    body: data ? JSON.stringify(data) : undefined
  });
  const result = await response.json().catch(() => ({ error: 'فشل الاتصال بالخادم. أعد المحاولة.' }));
  if (!response.ok) throw new Error(result.error || 'تعذر إكمال الطلب');
  return result;
}

async function loadAccount() {
  const result = await apiRequest('/me');
  state.isLoggedIn = true;
  state.userData.email = result.user.email;
  state.userData.phone = result.user.phone || result.user.email;
  state.userData.inviteCode = result.user.invite_code || result.user.inviteCode;
  state.userData.totalAssets = Number(result.balance || 0);
  state.userData.flexibleAssets = Number(result.availableBalance || result.balance || 0);
  state.userData.todayIncome = Number(result.todayEarned || 0);
  state.userData.totalIncome = Number(result.totalEarned || 0);
  state.userData.quantifyLeft = result.quantifyLeft !== undefined ? Number(result.quantifyLeft) : 5;
  state.referralCount = result.referralCount || 0;

  if (authScreen) authScreen.classList.remove('active');
  if (dashboardScreen) dashboardScreen.classList.add('active');
  setPage('home');
  updateProfileUI();
}

async function loadPublicConfig() {
  try {
    const config = await apiRequest('/config');
    state.api.configLoaded = true;
    state.api.depositConfigured = true;
    const hintText = document.querySelector('#assetsPage .asset-card .hint-text');
    if (hintText) {
      hintText.textContent = 'قم بتحويل المبلغ إلى عنوان المحفظة أدناه، وسيتم إضافة الرصيد لحسابك تلقائياً بعد التأكيد.';
    }
    refreshLevelState();
  } catch {
    state.api.configLoaded = true;
  }
}

async function restoreSession() {
  try {
    await loadAccount();
  } catch {
    state.isLoggedIn = false;
  }
}

async function login() {
  try {
    await apiRequest('/auth/login', {
      phone: document.getElementById('loginPhone').value.trim(),
      password: document.getElementById('loginPassword').value
    });
    await loadAccount();
    showToast('تم تسجيل الدخول بنجاح');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function register() {
  const email = document.getElementById('registerEmail').value.trim();
  const inviteCode = document.getElementById('inviteCodeInput').value.trim();
  const localPhoneInput = document.getElementById('registerPhone');
  const localPhone = localPhoneInput ? localPhoneInput.value.replace(/\D/g, '') : '';
  const countryCode = document.getElementById('countryCodeRegister') ? document.getElementById('countryCodeRegister').value : '';
  const phone = `${countryCode}${localPhone}`;
  const password = document.getElementById('registerPassword').value;

  if (!inviteCode) {
    showToast('كود الإحالة مطلوب لإنشاء الحساب', 'error');
    return;
  }

  try {
    if (!state.registerOtpRequested) {
      await apiRequest('/auth/register/request-code', { email, inviteCode, phone, password });
      state.registerOtpRequested = true;
      const otpBlock = document.getElementById('registerOtpBlock');
      if (otpBlock) otpBlock.classList.remove('hidden');
      const submitBtn = document.getElementById('registerSubmitBtn');
      if (submitBtn) submitBtn.textContent = 'تأكيد الرمز وإنشاء الحساب';
      showToast('أُرسل رمز توثيق البريد الإلكتروني بنجاح');
      return;
    }

    await apiRequest('/auth/register/verify-code', { email, code: document.getElementById('registerCode').value.trim() });
    await loadAccount();
    showToast('تم إنشاء الحساب وتسجيل الدخول بنجاح');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function requestRecoveryCode() {
  try {
    await apiRequest('/auth/recovery/request-code', {
      phone: document.getElementById('recoveryPhone').value.trim(),
      email: document.getElementById('recoveryEmail').value.trim()
    });
    state.recoveryOtpRequested = true;
    const otpBlock = document.getElementById('recoveryOtpBlock');
    if (otpBlock) otpBlock.classList.remove('hidden');
    showToast('أُرسل رمز الاستعادة إلى البريد الموثق');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function resetPassword() {
  try {
    await apiRequest('/auth/recovery/reset', {
      phone: document.getElementById('recoveryPhone').value.trim(),
      email: document.getElementById('recoveryEmail').value.trim(),
      code: document.getElementById('recoveryCode').value.trim(),
      password: document.getElementById('recoveryPassword').value
    });
    state.recoveryOtpRequested = false;
    const otpBlock = document.getElementById('recoveryOtpBlock');
    if (otpBlock) otpBlock.classList.add('hidden');
    document.getElementById('forgotForm').reset();
    setAuthMode('login');
    showToast('تم تغيير كلمة المرور. يمكنك تسجيل الدخول الآن.');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

function copyText(value) {
  navigator.clipboard.writeText(value).then(() => {
    showToast('تم النسخ بنجاح!');
  }).catch(() => {
    showToast('فشل النسخ، جرّب مرة أخرى', 'error');
  });
}

async function launchQuantify() {
  const demoCapitalInput = document.getElementById('demoCapital');
  const demoCapital = Number(demoCapitalInput?.value);
  if (!Number.isFinite(demoCapital) || demoCapital <= 0) {
    showToast('أدخل قيمة تجريبية صالحة. لن يتغير رصيد USDT الحقيقي.', 'error');
    return;
  }
  const simulatedProfit = Number((demoCapital * 0.015).toFixed(2));
  const demoBalance = Number((demoCapital + simulatedProfit).toFixed(2));
  const demoProfitElement = document.getElementById('quantifyLeftText');
  const demoBalanceElement = document.getElementById('todayProfitText');
  if (demoProfitElement) demoProfitElement.textContent = `${simulatedProfit.toFixed(2)} Demo`;
  if (demoBalanceElement) demoBalanceElement.textContent = `${demoBalance.toFixed(2)} Demo`;
  showToast(`محاكاة فقط: ربح تجريبي ${simulatedProfit.toFixed(2)} Demo، وليس USDT`);
}

async function logout() {
  try {
    await apiRequest('/auth/logout', {});
  } catch {
    // Clear local view
  }
  state.isLoggedIn = false;
  if (dashboardScreen) dashboardScreen.classList.remove('active');
  if (authScreen) authScreen.classList.add('active');
  setAuthMode('login');
  showToast('تم تسجيل الخروج بنجاح');
}

// Events
authTabs.forEach((tab) => {
  tab.addEventListener('click', () => setAuthMode(tab.dataset.mode));
});

document.querySelectorAll('[data-mode]').forEach((button) => {
  button.addEventListener('click', () => {
    const mode = button.dataset.mode;
    if (mode) setAuthMode(mode);
  });
});

const loginForm = document.getElementById('loginForm');
if (loginForm) loginForm.addEventListener('submit', (e) => { e.preventDefault(); login(); });

const registerForm = document.getElementById('registerForm');
if (registerForm) registerForm.addEventListener('submit', (e) => { e.preventDefault(); register(); });

const forgotForm = document.getElementById('forgotForm');
if (forgotForm) forgotForm.addEventListener('submit', (e) => { e.preventDefault(); resetPassword(); });

const recoveryBtn = document.getElementById('recoverySendBtn');
if (recoveryBtn) recoveryBtn.addEventListener('click', requestRecoveryCode);

const bindIfExists = (id, handler) => {
  const element = document.getElementById(id);
  if (element) element.addEventListener('click', handler);
};

bindIfExists('launchQuantify', launchQuantify);
bindIfExists('logoutBtn', logout);

navItems.forEach((item) => {
  item.addEventListener('click', () => setPage(item.dataset.target));
});

quickItems.forEach((item) => {
  item.addEventListener('click', () => {
    const target = item.dataset.target;
    if (target) setPage(target);
  });
});

const getRefLink = () => `${window.location.origin}?ref=${state.userData.inviteCode}`;
bindIfExists('copyReferralBtn', () => copyText(getRefLink()));
bindIfExists('copyPromoBtn', () => copyText(getRefLink()));
bindIfExists('copyInviteBtn', () => copyText(getRefLink()));

bindIfExists('withdrawBtn', async () => {
  const amountInput = document.getElementById('withdrawAmount');
  const walletInput = document.getElementById('withdrawWallet');
  const amount = amountInput ? amountInput.value.trim() : '';
  const wallet = walletInput ? walletInput.value.trim() : '';

  if (!/^\d+(?:\.\d{1,6})?$/.test(amount) || Number(amount) < 20) {
    showToast('الحد الأدنى لطلب السحب هو 20 USDT', 'error');
    return;
  }
  if (!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(wallet)) {
    showToast('يرجى إدخال عنوان TRC20 صحيح يبرع بـ T', 'error');
    return;
  }
  try {
    const result = await apiRequest('/withdrawals', { amount, walletAddress: wallet });
    if (amountInput) amountInput.value = '';
    showToast(`تم تسجيل طلب السحب للمراجعة خلال ${result.reviewHours || 24} ساعة`);
    await loadAccount();
  } catch (error) {
    showToast(error.message, 'error');
  }
});

// Initial load
applyReferralFromUrl();
setAuthMode('login');
setPage('home');
updateProfileUI();
loadPublicConfig();
restoreSession();