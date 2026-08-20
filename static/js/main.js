// Main JavaScript for Authentication Hub

document.addEventListener('DOMContentLoaded', function() {
    console.log('Authentication Hub initialized');

    // Mobile navbar toggle
    const toggleBtn = document.querySelector('.navbar-toggle');
    const navbarNav = document.getElementById('navbar-nav');

    if (toggleBtn && navbarNav) {
        toggleBtn.addEventListener('click', function() {
            const isExpanded = toggleBtn.getAttribute('aria-expanded') === 'true';
            toggleBtn.setAttribute('aria-expanded', !isExpanded);
            navbarNav.classList.toggle('show');
        });
    }

    // Profile dropdown toggle
    const profileBtn = document.getElementById('profile-dropdown-btn');
    const profileDropdown = document.getElementById('profile-dropdown');

    if (profileBtn && profileDropdown) {
        profileBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            const isExpanded = profileBtn.getAttribute('aria-expanded') === 'true';
            profileBtn.setAttribute('aria-expanded', !isExpanded);
            profileDropdown.classList.toggle('show');
        });
    }

    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
        if (profileBtn && profileDropdown && !profileBtn.contains(e.target) && !profileDropdown.contains(e.target)) {
            profileBtn.setAttribute('aria-expanded', 'false');
            profileDropdown.classList.remove('show');
        }
    });

    // Close dropdown on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && profileBtn && profileDropdown && profileDropdown.classList.contains('show')) {
            profileBtn.setAttribute('aria-expanded', 'false');
            profileDropdown.classList.remove('show');
            profileBtn.focus();
        }
    });

    // Keyboard navigation for dropdown items
    if (profileBtn && profileDropdown) {
        const dropdownItems = profileDropdown.querySelectorAll('.navbar-dropdown-item');
        
        profileBtn.addEventListener('keydown', function(e) {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                profileBtn.setAttribute('aria-expanded', 'true');
                profileDropdown.classList.add('show');
                if (dropdownItems.length > 0) {
                    dropdownItems[0].focus();
                }
            }
        });

        dropdownItems.forEach(function(item, index) {
            item.addEventListener('keydown', function(e) {
                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    const next = dropdownItems[index + 1];
                    if (next) next.focus();
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    const prev = dropdownItems[index - 1];
                    if (prev) {
                        prev.focus();
                    } else {
                        profileBtn.focus();
                    }
                } else if (e.key === 'Escape') {
                    profileBtn.setAttribute('aria-expanded', 'false');
                    profileDropdown.classList.remove('show');
                    profileBtn.focus();
                }
            });
        });
    }

    // Initialize toast notifications with show class for animation
    const toasts = document.querySelectorAll('.toast');
    toasts.forEach(function(toast) {
        // Trigger show animation
        setTimeout(function() {
            toast.classList.add('show');
        }, 50);

        // Auto-dismiss after 4 seconds
        setTimeout(function() {
            toast.classList.add('hide');
        }, 4000);
    });

    // Photo upload filename display
    const photoInput = document.getElementById('id_profile_picture');
    const photoFilename = document.getElementById('photo-filename');

    if (photoInput && photoFilename) {
        photoInput.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
                photoFilename.textContent = this.files[0].name;
            } else {
                photoFilename.textContent = 'No file chosen';
            }
        });
    }

    // Verification banner dismiss
    const bannerClose = document.getElementById('verification-banner-close');
    const banner = document.getElementById('verification-banner');

    if (bannerClose && banner) {
        bannerClose.addEventListener('click', function() {
            banner.style.display = 'none';
        });
    }
});

// Close buttons for toast notifications
document.addEventListener('click', function(e) {
    if (e.target && e.target.classList.contains('toast-close')) {
        const toast = e.target.closest('.toast');
        if (toast) {
            toast.classList.add('hide');
        }
    }
});
