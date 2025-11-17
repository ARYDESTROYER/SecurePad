document.addEventListener('DOMContentLoaded', function () {
    const toggle = document.getElementById('toggle-secret');
    if (!toggle) return;
    const secretPre = document.querySelector('.secret-value');
    let shown = false;
    toggle.addEventListener('click', function () {
        shown = !shown;
        secretPre.classList.toggle('d-none', !shown);
        toggle.textContent = shown ? 'Hide secret' : 'Show secret';
    });
});

// Add form-control class to basic form inputs in login page for styling
document.addEventListener('DOMContentLoaded', function () {
    var loginForm = document.querySelector('form[action="/accounts/login/"]');
    if (loginForm) {
        var inputs = loginForm.querySelectorAll('input[type=text], input[type=password], input[type=email], textarea');
        inputs.forEach(function (el) { el.classList.add('form-control'); });
    }
});

// Auto dismiss alerts with the 'auto-dismiss' class after a short delay
document.addEventListener('DOMContentLoaded', function () {
    const dismissDelayMs = 4500;
    document.querySelectorAll('.alert.auto-dismiss').forEach(function (el) {
        // Ensure fade/show classes exist for smoother transition
        el.classList.add('fade', 'show');
        setTimeout(function () {
            try {
                // Bootstrap 5: the 'remove' will update class list for transitions
                el.classList.remove('show');
                // Remove from DOM after the CSS transition (200ms)
                setTimeout(function () { el.remove(); }, 250);
            } catch (e) {
                // Fallback: remove immediately
                el.remove();
            }
        }, dismissDelayMs);
    });
});
