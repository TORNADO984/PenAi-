document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('login-form');
  if (!loginForm) return;

  const emailInput = document.getElementById('login-email');
  const passwordInput = document.getElementById('login-password');
  const errorDiv = document.getElementById('login-error');
  const successDiv = document.getElementById('login-success');
  const submitBtn = document.getElementById('login-btn');
  const spinner = document.getElementById('login-spinner');
  const btnText = submitBtn.querySelector('span');

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    // Reset messages
    errorDiv.classList.add('hidden');
    successDiv.classList.add('hidden');
    errorDiv.textContent = '';
    successDiv.textContent = '';

    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!email || !password) {
      showError('Please enter both email and password.');
      return;
    }

    // Show loading state
    setLoading(true);

    try {
      const response = await fetch('http://localhost:5000/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Handle successful login
        const token = data.data.token;
        
        // Save the token to localStorage
        localStorage.setItem('penai_token', token);
        // Optionally save user info
        if (data.data.name) {
          localStorage.setItem('penai_user_name', data.data.name);
        }

        showSuccess('Login successful! Redirecting...');
        
        // Wait a brief moment to show the success message, then close modal and update UI
        setTimeout(() => {
          // Hide auth modal if it exists
          const modal = document.getElementById('auth-modal');
          if (modal) {
            modal.classList.remove('active');
            document.body.style.overflow = '';
          }
          
          // Update UI to reflect logged-in state
          updateUIForLoggedInUser();
        }, 1000);

      } else {
        // Backend returned an error message
        showError(data.message || 'Login failed. Please check your credentials.');
      }
    } catch (err) {
      // Network error or server is unreachable
      console.error('Login error:', err);
      showError('Unable to connect to the server. Please try again later.');
    } finally {
      // Hide loading state
      setLoading(false);
    }
  });

  // --- SIGNUP LOGIC ---
  const signupForm = document.getElementById('signup-form');
  if (signupForm) {
    const signupNameInput = document.getElementById('signup-name');
    const signupEmailInput = document.getElementById('signup-email');
    const signupPasswordInput = document.getElementById('signup-password');
    const signupErrorDiv = document.getElementById('signup-error');
    const signupSuccessDiv = document.getElementById('signup-success');
    const signupBtn = document.getElementById('signup-btn');
    const signupSpinner = document.getElementById('signup-spinner');
    const signupBtnText = signupBtn.querySelector('span');

    signupForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      signupErrorDiv.classList.add('hidden');
      signupSuccessDiv.classList.add('hidden');
      signupErrorDiv.textContent = '';
      signupSuccessDiv.textContent = '';

      const name = signupNameInput.value.trim();
      const email = signupEmailInput.value.trim();
      const password = signupPasswordInput.value;

      if (!name || !email || !password) {
        signupErrorDiv.textContent = 'Please fill out all fields.';
        signupErrorDiv.classList.remove('hidden');
        return;
      }

      // Show loading
      signupBtn.disabled = true;
      signupBtn.classList.add('opacity-80', 'cursor-not-allowed');
      if (signupBtnText) signupBtnText.textContent = 'Creating...';
      if (signupSpinner) signupSpinner.classList.remove('hidden');

      try {
        const response = await fetch('http://localhost:5000/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, password })
        });

        const data = await response.json();

        if (response.ok && data.success) {
          const token = data.data.token;
          localStorage.setItem('penai_token', token);
          if (data.data.name) {
            localStorage.setItem('penai_user_name', data.data.name);
          }

          signupSuccessDiv.textContent = 'Account created successfully! Redirecting...';
          signupSuccessDiv.classList.remove('hidden');
          
          setTimeout(() => {
            const modal = document.getElementById('auth-modal');
            if (modal) {
              modal.classList.remove('active');
              document.body.style.overflow = '';
            }
            updateUIForLoggedInUser();
          }, 1000);

        } else {
          signupErrorDiv.textContent = data.message || 'Registration failed. Please try again.';
          signupErrorDiv.classList.remove('hidden');
        }
      } catch (err) {
        console.error('Signup error:', err);
        signupErrorDiv.textContent = 'Unable to connect to the server. Please try again later.';
        signupErrorDiv.classList.remove('hidden');
      } finally {
        // Hide loading
        signupBtn.disabled = false;
        signupBtn.classList.remove('opacity-80', 'cursor-not-allowed');
        if (signupBtnText) signupBtnText.textContent = 'Create Account';
        if (signupSpinner) signupSpinner.classList.add('hidden');
      }
    });
  }

  function showError(msg) {
    errorDiv.textContent = msg;
    errorDiv.classList.remove('hidden');
  }

  function showSuccess(msg) {
    successDiv.textContent = msg;
    successDiv.classList.remove('hidden');
  }

  function setLoading(isLoading) {
    if (isLoading) {
      submitBtn.disabled = true;
      submitBtn.classList.add('opacity-80', 'cursor-not-allowed');
      if (btnText) btnText.textContent = 'Logging in...';
      if (spinner) spinner.classList.remove('hidden');
    } else {
      submitBtn.disabled = false;
      submitBtn.classList.remove('opacity-80', 'cursor-not-allowed');
      if (btnText) btnText.textContent = 'Login';
      if (spinner) spinner.classList.add('hidden');
    }
  }

  // Helper function to update UI after login
  function updateUIForLoggedInUser() {
    const token = localStorage.getItem('penai_token');
    const userName = localStorage.getItem('penai_user_name');
    
    if (token) {
      // Find buttons by class
      const loginBtns = document.querySelectorAll('.login-btn');
      const signupBtns = document.querySelectorAll('.signup-btn');
      
      const navGreeting = document.getElementById('nav-greeting');
      const navLogoutBtn = document.getElementById('nav-logout-btn');
      const mobileGreeting = document.getElementById('mobile-greeting');
      const mobileLogoutBtn = document.getElementById('mobile-logout-btn');

      // Hide login/signup
      loginBtns.forEach(btn => btn.classList.add('hidden'));
      signupBtns.forEach(btn => btn.classList.add('hidden'));

      // Show greetings
      const firstName = userName ? userName.split(' ')[0] : 'User';
      const displayName = `Hello, ${firstName}`;
      const initial = firstName.charAt(0).toUpperCase();
      
      const navUserProfile = document.getElementById('nav-user-profile');
      const navUserInitial = document.getElementById('nav-user-initial');
      
      const mobileUserProfile = document.getElementById('mobile-user-profile');
      const mobileUserInitial = document.getElementById('mobile-user-initial');
      
      if (navGreeting && navUserProfile && navUserInitial) {
        navGreeting.textContent = displayName;
        navUserInitial.textContent = initial;
        navUserProfile.classList.remove('hidden');
        navUserProfile.classList.add('flex');
      }
      
      if (mobileGreeting && mobileUserProfile && mobileUserInitial) {
        mobileGreeting.textContent = displayName;
        mobileUserInitial.textContent = initial;
        mobileUserProfile.classList.remove('hidden');
        mobileUserProfile.classList.add('flex');
      }

      // Show logout buttons
      if (navLogoutBtn) navLogoutBtn.classList.remove('hidden');
      if (mobileLogoutBtn) mobileLogoutBtn.classList.remove('hidden');
      
      // Show scanner tabs if they exist
      const scannerTabs = document.getElementById('scanner-tabs');
      if (scannerTabs) {
        scannerTabs.classList.remove('hidden');
      }
    }
  }

  function showLogoutConfirm() {
    const logoutModal = document.getElementById('logout-modal');
    if (logoutModal) {
      logoutModal.classList.add('active');
      document.body.style.overflow = 'hidden';
    } else {
      // Fallback if modal doesn't exist
      if (confirm('Are you sure you want to log out?')) {
        performLogout();
      }
    }
  }

  function hideLogoutConfirm() {
    const logoutModal = document.getElementById('logout-modal');
    if (logoutModal) {
      logoutModal.classList.remove('active');
      document.body.style.overflow = '';
    }
  }

  function performLogout() {
    hideLogoutConfirm();

    // Clear tokens
    localStorage.removeItem('penai_token');
    localStorage.removeItem('penai_user_name');

    // Hide logout buttons and user profiles
    const navUserProfile = document.getElementById('nav-user-profile');
    const mobileUserProfile = document.getElementById('mobile-user-profile');
    const navLogoutBtn = document.getElementById('nav-logout-btn');
    const mobileLogoutBtn = document.getElementById('mobile-logout-btn');
    
    if (navUserProfile) {
      navUserProfile.classList.add('hidden');
      navUserProfile.classList.remove('flex');
    }
    if (mobileUserProfile) {
      mobileUserProfile.classList.add('hidden');
      mobileUserProfile.classList.remove('flex');
    }
    if (navLogoutBtn) navLogoutBtn.classList.add('hidden');
    if (mobileLogoutBtn) mobileLogoutBtn.classList.add('hidden');

    // Show login/signup buttons
    const loginBtns = document.querySelectorAll('.login-btn');
    const signupBtns = document.querySelectorAll('.signup-btn');
    loginBtns.forEach(btn => btn.classList.remove('hidden'));
    signupBtns.forEach(btn => btn.classList.remove('hidden'));

    // Hide scanner tabs and history, reset to new scan view, clear reports
    const scannerTabs = document.getElementById('scanner-tabs');
    const scanHistoryView = document.getElementById('scan-history-view');
    const newScanView = document.getElementById('new-scan-view');
    const scanReport = document.getElementById('scan-report');
    
    if (scannerTabs) scannerTabs.classList.add('hidden');
    if (scanHistoryView) scanHistoryView.classList.add('hidden');
    if (newScanView) newScanView.classList.remove('hidden');
    if (scanReport) {
      scanReport.classList.add('hidden');
      scanReport.innerHTML = ''; // Clear report data to protect information
    }

    // Optional: show a small toast or just let the UI reset gracefully
    // We remove the old blocking alert() for a cleaner experience.
  }

  // Setup Logout Confirm listeners
  const confirmLogoutBtn = document.getElementById('confirm-logout-btn');
  const cancelLogoutBtn = document.getElementById('cancel-logout-btn');
  const logoutModalOverlay = document.getElementById('logout-modal');
  
  if (confirmLogoutBtn) confirmLogoutBtn.addEventListener('click', performLogout);
  if (cancelLogoutBtn) cancelLogoutBtn.addEventListener('click', hideLogoutConfirm);
  if (logoutModalOverlay) {
    logoutModalOverlay.addEventListener('click', (e) => {
      if (e.target === logoutModalOverlay) hideLogoutConfirm();
    });
  }

  // Setup Logout button listeners (Trigger Modal)
  const navLogoutBtn = document.getElementById('nav-logout-btn');
  const mobileLogoutBtn = document.getElementById('mobile-logout-btn');
  if (navLogoutBtn) navLogoutBtn.addEventListener('click', showLogoutConfirm);
  if (mobileLogoutBtn) mobileLogoutBtn.addEventListener('click', showLogoutConfirm);

  // Check if user is already logged in on page load
  if (localStorage.getItem('penai_token')) {
    updateUIForLoggedInUser();
  }
});
