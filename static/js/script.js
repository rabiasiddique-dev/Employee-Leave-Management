document.addEventListener('DOMContentLoaded', function() {
    // --- Navbar Functionality ---
    const navToggler = document.querySelector('.nav-toggler');
    const navbarNav = document.querySelector('.navbar-nav');
    const navbar = document.querySelector('.navbar'); 

    if (navbar) {
        const scrollThreshold = 50; 
        window.addEventListener('scroll', () => {
            if (window.scrollY > scrollThreshold) {
                navbar.classList.add('scrolled');
            } else {
                navbar.classList.remove('scrolled');
            }
        }, { passive: true });
    }

    if (navToggler && navbarNav) {
        navToggler.addEventListener('click', () => {
            const isExpanded = navToggler.getAttribute('aria-expanded') === 'true' || false;
            navToggler.setAttribute('aria-expanded', String(!isExpanded));
            navbarNav.classList.toggle('open'); 
            navToggler.classList.toggle('open'); 
            document.body.style.overflow = navbarNav.classList.contains('open') ? 'hidden' : '';
        });
    }

    const navDropdownToggles = document.querySelectorAll('.navbar-nav .dropdown-toggle');
    navDropdownToggles.forEach(toggle => {
        toggle.addEventListener('click', function(event) {
            if (window.matchMedia('(max-width: 768px)').matches) { 
                const parentDropdownItem = this.closest('.nav-item-dropdown');
                if (!parentDropdownItem) return;

                event.preventDefault(); 

                const currentlyOpen = parentDropdownItem.classList.contains('open');

                document.querySelectorAll('.navbar-nav .nav-item-dropdown.open').forEach(openDropdown => {
                    if (openDropdown !== parentDropdownItem) {
                        openDropdown.classList.remove('open');
                        const otherMenu = openDropdown.querySelector('.dropdown-menu');
                        if (otherMenu) otherMenu.style.display = 'none';
                    }
                });

                parentDropdownItem.classList.toggle('open', !currentlyOpen);
                const dropdownMenu = parentDropdownItem.querySelector('.dropdown-menu');
                if (dropdownMenu) {
                    dropdownMenu.style.display = !currentlyOpen ? 'block' : 'none';
                }
            }
        });
    });

    if (navbarNav) {
        navbarNav.querySelectorAll('a:not(.dropdown-toggle)').forEach(link => {
            link.addEventListener('click', () => {
                if (navbarNav.classList.contains('open')) {
                    navbarNav.classList.remove('open');
                    navToggler.classList.remove('open');
                    navToggler.setAttribute('aria-expanded', 'false');
                    document.body.style.overflow = '';
                }
            });
        });
    }

    document.addEventListener('click', function(event) {
        if (navbarNav && navToggler && navbarNav.classList.contains('open')) {
            const isClickInsideNav = navbarNav.contains(event.target);
            const isClickOnToggler = navToggler.contains(event.target);

            if (!isClickInsideNav && !isClickOnToggler) {
                navbarNav.classList.remove('open');
                navToggler.classList.remove('open');
                navToggler.setAttribute('aria-expanded', 'false');
                document.body.style.overflow = '';
                document.querySelectorAll('.navbar-nav .nav-item-dropdown.open').forEach(openDropdown => {
                    openDropdown.classList.remove('open');
                    const menu = openDropdown.querySelector('.dropdown-menu');
                    if (menu) menu.style.display = 'none';
                });
            }
        }
    });


    // --- Auto-dismiss Flash Messages ---
    const alerts = document.querySelectorAll('.alert[role="alert"]');
    alerts.forEach(alert => {
        if (!alert.closest('form')) { 
            setTimeout(() => {
                alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease, margin-top 0.5s ease, padding 0.5s ease, height 0.5s ease';
                alert.style.opacity = '0';
                alert.style.transform = 'scaleY(0.8) translateY(-20px)';
                alert.style.marginTop = '0';
                alert.style.marginBottom = '0';
                alert.style.paddingTop = '0';
                alert.style.paddingBottom = '0';
                alert.style.height = '0';
                alert.style.borderWidth = '0'; 
                setTimeout(() => alert.remove(), 550);
            }, 5000); 
        }
    });

    document.querySelectorAll('.alert .close-alert').forEach(button => {
        button.addEventListener('click', function() {
            const alertNode = this.closest('.alert');
            if (alertNode) {
                alertNode.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
                alertNode.style.opacity = '0';
                alertNode.style.transform = 'scale(0.9)';
                setTimeout(() => alertNode.remove(), 300);
            }
        });
    });


    // --- Date Validation for Leave Forms ---
    const startDateInput = document.getElementById('startDate');
    const endDateInput = document.getElementById('endDate');

    if (startDateInput && endDateInput) {
        const today = new Date();
        const todayFormatted = today.toISOString().split('T')[0];

        if (!startDateInput.closest('form[action*="/edit"]')) {
            startDateInput.setAttribute('min', todayFormatted);
        }

        startDateInput.addEventListener('input', function() {
            if (this.value) {
                endDateInput.setAttribute('min', this.value);
                if (endDateInput.value && new Date(endDateInput.value) < new Date(this.value)) {
                    endDateInput.value = this.value;
                }
            } else {
                endDateInput.removeAttribute('min');
            }
        });
    }

    // --- Smooth Scroll for Anchor Links ---
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const hrefAttribute = this.getAttribute('href');
            if (hrefAttribute && hrefAttribute.length > 1 && hrefAttribute !== '#') {
                try {
                    const targetElement = document.querySelector(hrefAttribute);
                    if (targetElement) {
                        e.preventDefault();
                        const navbarHeight = document.querySelector('.navbar')?.offsetHeight || 0;
                        const elementPosition = targetElement.getBoundingClientRect().top;
                        const offsetPosition = elementPosition + window.pageYOffset - navbarHeight - 10; 

                        window.scrollTo({
                            top: offsetPosition,
                            behavior: 'smooth'
                        });
                    }
                } catch (error) {
                    console.warn(`Smooth scroll target not found or invalid selector: ${hrefAttribute}`, error);
                }
            }
        });
    });

    // --- Dynamic Year for Footer ---
    const yearSpan = document.getElementById('currentYear');
    if (yearSpan) {
        yearSpan.textContent = new Date().getFullYear();
    }

    // --- Notification Count Update ---
    function updateNotificationCount() {
        fetch('/notifications/count')
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                return response.json();
            })
            .then(data => {
                const badge = document.getElementById('notification-count-badge');
                if (badge) {
                    if (data.unread_count > 0) {
                        badge.textContent = data.unread_count;
                        badge.style.display = 'inline-block'; 
                        badge.classList.add('active'); 
                    } else {
                        badge.textContent = '0'; 
                        badge.style.display = 'none';
                        badge.classList.remove('active');
                    }
                }
            })
            .catch(error => console.error('Error fetching notification count:', error));
    }

    if (document.querySelector('.navbar-nav a[href*="/logout"]')) { 
        updateNotificationCount();
    }

    // --- Form Submission Loading State ---
    const formsWithSubmit = document.querySelectorAll('form.styled-form, form.auth-form, #rejectForm');
    formsWithSubmit.forEach(form => {
        form.addEventListener('submit', function(event) {
            let isValid = true;
            form.querySelectorAll('[required]').forEach(requiredInput => {
                if (!requiredInput.value.trim()) {
                    isValid = false;
                }
            });

            if (!isValid) {
                event.preventDefault(); 
                console.warn("Form validation failed. Please fill all required fields.");
                return;
            }

            const submitButton = form.querySelector('button[type="submit"], input[type="submit"]');
            if (submitButton && !submitButton.disabled) { 
                submitButton.disabled = true;
                const originalContent = submitButton.innerHTML;
                submitButton.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...`;

                setTimeout(() => {
                    if (submitButton.disabled) {
                        submitButton.disabled = false;
                        submitButton.innerHTML = originalContent;
                    }
                }, 8000); 
            }
        });
    });

    // --- Animate elements on scroll (Intersection Observer) ---
    const scrollAnimatedElements = document.querySelectorAll('.animate-on-scroll');
    if (scrollAnimatedElements.length > 0 && "IntersectionObserver" in window) {
        const observer = new IntersectionObserver((entries, observerInstance) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('is-visible');
                    observerInstance.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 }); 

        scrollAnimatedElements.forEach(el => observer.observe(el));
    } else if (scrollAnimatedElements.length > 0) {
        scrollAnimatedElements.forEach(el => el.classList.add('is-visible'));
    }


    // ============================
    // --- MODAL FUNCTIONALITY 
    // ============================
    const rejectModal = document.getElementById('rejectModal');
    const rejectForm = document.getElementById('rejectForm');
    const rejectEmployeeName = document.getElementById('rejectEmployeeName');
    const commentsTextarea = document.getElementById('manager_comments'); // Matching the ID in the HTML

    // This is now a global function that can be called from HTML `onclick`
    window.showRejectModal = function(button) {
        if (!rejectModal) {
            console.error("The reject modal element was not found in the DOM.");
            return;
        }

        // Extract data from the button's data-* attributes. This is the correct way.
        const rejectUrl = button.dataset.rejectUrl;
        const userName = button.dataset.userName;
        
        if (!rejectUrl || !userName) {
            console.error("Button is missing 'data-reject-url' or 'data-user-name' attribute. Make sure your HTML is correct.");
            return;
        }

        if (rejectForm && rejectEmployeeName) {
            // Set the dynamic data in the modal
            rejectEmployeeName.textContent = userName;
            rejectForm.action = rejectUrl; // Set the form's action URL dynamically
            
            // Show the modal
            rejectModal.style.display = 'block';
            if (commentsTextarea) commentsTextarea.focus(); // Focus the textarea for better UX
        } else {
            console.error("Could not find the form or employee name element inside the reject modal.");
        }
    };

    // This is now a global function to close the modal
    window.closeRejectModal = function() {
        if (rejectModal) {
            rejectModal.style.display = 'none';
            if (rejectForm) {
                rejectForm.reset(); // Clear the form/textarea
            }
        }
    };

    // Event listener for closing modal with the Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' || event.key === 'Esc') {
            if (rejectModal && rejectModal.style.display === 'block') {
                closeRejectModal();
            }
        }
    });

    // Close modal if user clicks on the dark background overlay
    if (rejectModal) {
        rejectModal.addEventListener('click', function(event) {
            // Check if the click was on the modal background itself, not on its content
            if (event.target === rejectModal) {
                closeRejectModal();
            }
        });
    }
});