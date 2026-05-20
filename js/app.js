// PenAI - Main Application JavaScript

// ── Matrix Rain Background ──
function initMatrix() {
  const canvas = document.getElementById('matrix-bg');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*(){}[]|;:<>?/~';
  const fontSize = 18;
  const columns = Math.floor(canvas.width / fontSize);
  const drops = Array(columns).fill(1);

  function draw() {
    ctx.fillStyle = 'rgba(10, 10, 10, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#00ff9d';
    ctx.font = `${fontSize}px monospace`;

    for (let i = 0; i < drops.length; i++) {
      const text = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
    requestAnimationFrame(draw);
  }
  draw();
}

// ── Navbar Scroll Effect ──
function initNavbar() {
  const navbar = document.getElementById('navbar');
  if (!navbar) return;
  window.addEventListener('scroll', () => {
    navbar.classList.toggle('scrolled', window.scrollY > 50);
  });
}

// ── Mobile Menu ──
function initMobileMenu() {
  const btn = document.getElementById('mobile-menu-btn');
  const closeBtn = document.getElementById('mobile-menu-btn-close');
  const menu = document.getElementById('mobile-menu');
  const overlay = document.getElementById('mobile-overlay');
  if (!btn || !menu || !overlay) return;

  function toggle() {
    menu.classList.toggle('open');
    overlay.classList.toggle('open');
    document.body.style.overflow = menu.classList.contains('open') ? 'hidden' : '';
  }

  btn.addEventListener('click', toggle);
  if (closeBtn) closeBtn.addEventListener('click', toggle);
  overlay.addEventListener('click', toggle);
  menu.querySelectorAll('a').forEach(a => a.addEventListener('click', toggle));
}

// ── Auth Modal ──
function initAuthModal() {
  const modal = document.getElementById('auth-modal');
  if (!modal) return;

  document.querySelectorAll('[data-auth-open]').forEach(btn => {
    btn.addEventListener('click', () => {
      modal.classList.add('active');
      document.body.style.overflow = 'hidden';
    });
  });

  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      modal.classList.remove('active');
      document.body.style.overflow = '';
    }
  });

  const closeBtn = modal.querySelector('[data-auth-close]');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      modal.classList.remove('active');
      document.body.style.overflow = '';
    });
  }
}

// ── Smooth Scroll ──
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', (e) => {
      const id = anchor.getAttribute('href');
      if (id === '#') return;
      const target = document.querySelector(id);
      if (target) {
        e.preventDefault();
        const offset = 80;
        const top = target.getBoundingClientRect().top + window.pageYOffset - offset;
        window.scrollTo({ top, behavior: 'smooth' });
      }
    });
  });
}

// ── Intersection Observer for Fade-in ──
function initScrollAnimations() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('fade-in-up');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  document.querySelectorAll('[data-animate]').forEach(el => observer.observe(el));
}

// ── Active Nav Link ──
function initActiveNav() {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-link');

  window.addEventListener('scroll', () => {
    let current = '';
    sections.forEach(section => {
      const top = section.offsetTop - 100;
      if (window.pageYOffset >= top) current = section.getAttribute('id');
    });
    navLinks.forEach(link => {
      link.classList.toggle('active', link.getAttribute('href') === `#${current}`);
    });
  });
}

// ── Auth Tab Toggle ──
function initAuthTabs() {
  const tabs = document.querySelectorAll('[data-auth-tab]');
  const panels = document.querySelectorAll('[data-auth-panel]');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.authTab;
      tabs.forEach(t => t.classList.remove('active', 'border-[#00ff9d]', 'text-[#00ff9d]'));
      tabs.forEach(t => t.classList.add('border-transparent', 'text-gray-500'));
      tab.classList.add('active', 'border-[#00ff9d]', 'text-[#00ff9d]');
      tab.classList.remove('border-transparent', 'text-gray-500');
      panels.forEach(p => p.classList.toggle('hidden', p.dataset.authPanel !== target));
    });
  });
}

// ── Animated Stat Counters ──
function initStatCounters() {
  const counters = document.querySelectorAll('[data-count]');
  if (!counters.length) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        const target = parseInt(el.dataset.count, 10);
        const suffix = el.dataset.suffix || '';
        const duration = 2000;
        const start = performance.now();

        function update(now) {
          const elapsed = now - start;
          const progress = Math.min(elapsed / duration, 1);
          // Ease out cubic
          const ease = 1 - Math.pow(1 - progress, 3);
          const current = Math.floor(ease * target);
          el.textContent = current.toLocaleString() + suffix;
          if (progress < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
        observer.unobserve(el);
      }
    });
  }, { threshold: 0.3 });

  counters.forEach(c => observer.observe(c));
}

// ── Scroll Reveal for [data-animate] ──
function initScrollReveal() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        // Stagger siblings
        const el = entry.target;
        const parent = el.parentElement;
        const siblings = parent ? [...parent.querySelectorAll('[data-animate]')] : [el];
        const idx = siblings.indexOf(el);
        const delay = idx >= 0 ? idx * 80 : 0;
        setTimeout(() => el.classList.add('visible'), delay);
        observer.unobserve(el);
      }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

  document.querySelectorAll('[data-animate]').forEach(el => observer.observe(el));

  // Expose for dynamic content (scanner report, OWASP cards)
  window._revealObserver = observer;
}

// Re-observe newly inserted [data-animate] elements
function revealNewElements(container) {
  if (!window._revealObserver || !container) return;
  container.querySelectorAll('[data-animate]').forEach(el => {
    window._revealObserver.observe(el);
  });
}
window.revealNewElements = revealNewElements;

// ── Initialize ──
document.addEventListener('DOMContentLoaded', () => {
  initMatrix();
  initNavbar();
  initMobileMenu();
  initAuthModal();
  initSmoothScroll();
  initScrollAnimations();
  initActiveNav();
  initAuthTabs();
  initStatCounters();
  initScrollReveal();
});
