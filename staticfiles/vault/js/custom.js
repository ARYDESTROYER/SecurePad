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
