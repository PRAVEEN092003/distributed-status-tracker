/**
 * Distributed Status Tracker - Client-side Utilities
 * Handles mobile navigation, password toggles, and UI interactions.
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Mobile Navigation Toggle
    const mobileNavToggle = document.getElementById('mobileNavToggle');
    const mainNavMenu = document.getElementById('navMenu') || document.getElementById('mainNavMenu');
    if (mobileNavToggle && mainNavMenu) {
        mobileNavToggle.addEventListener('click', () => {
            const isOpen = mainNavMenu.classList.toggle('open');
            mobileNavToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        });

        // Close mobile nav when clicking outside
        document.addEventListener('click', (e) => {
            if (!mobileNavToggle.contains(e.target) && !mainNavMenu.contains(e.target)) {
                mainNavMenu.classList.remove('open');
                mobileNavToggle.setAttribute('aria-expanded', 'false');
            }
        });
    }

    // 2. Password Visibility Toggles
    const passwordToggleButtons = document.querySelectorAll('.password-toggle-btn');
    passwordToggleButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = btn.getAttribute('data-target');
            const targetInput = targetId ? document.getElementById(targetId) : btn.closest('.password-input-wrapper')?.querySelector('input');
            
            if (targetInput) {
                const isPassword = targetInput.getAttribute('type') === 'password';
                targetInput.setAttribute('type', isPassword ? 'text' : 'password');
                
                // Update icon or state
                const eyeIcon = btn.querySelector('.eye-icon');
                const eyeOffIcon = btn.querySelector('.eye-off-icon');
                if (eyeIcon && eyeOffIcon) {
                    eyeIcon.style.display = isPassword ? 'none' : 'block';
                    eyeOffIcon.style.display = isPassword ? 'block' : 'none';
                }
                btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
            }
        });
    });

    // 3. Auto-dismiss flash notifications after 5 seconds
    const flashAlerts = document.querySelectorAll('.flash-alert');
    flashAlerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            setTimeout(() => alert.remove(), 400);
        }, 5000);
    });

    // 4. Client-side validation aid on registration form
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        const passwordInput = document.getElementById('password');
        const confirmInput = document.getElementById('confirm_password');

        registerForm.addEventListener('submit', (e) => {
            if (passwordInput && confirmInput) {
                if (passwordInput.value !== confirmInput.value) {
                    e.preventDefault();
                    showClientToast('Passwords do not match.', 'error');
                    confirmInput.focus();
                    return false;
                }

                if (passwordInput.value.length < 8) {
                    e.preventDefault();
                    showClientToast('Password must be at least 8 characters long.', 'error');
                    passwordInput.focus();
                    return false;
                }
            }
        });
    }

    // 5. Helper to show client-side toast notifications
    function showClientToast(message, type = 'error') {
        let container = document.getElementById('flashContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'flashContainer';
            container.className = 'flash-container';
            const mainContent = document.querySelector('.content-container');
            if (mainContent) {
                mainContent.insertBefore(container, mainContent.firstChild);
            }
        }

        const alert = document.createElement('div');
        alert.className = `flash-alert flash-${type}`;
        alert.innerHTML = `
            <span class="flash-icon">${type === 'error' ? '✕' : 'ℹ'}</span>
            <span class="flash-text">${message}</span>
            <button type="button" class="flash-close" aria-label="Close">&times;</button>
        `;

        alert.querySelector('.flash-close').addEventListener('click', () => alert.remove());
        container.appendChild(alert);

        setTimeout(() => {
            alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            setTimeout(() => alert.remove(), 400);
        }, 5000);
    }
});
