document.addEventListener('DOMContentLoaded', function() {
  const toggle = document.getElementById('theme-toggle');
  const themes = ['light', 'dark', 'cupcake', 'emerald', 'synthwave'];  // Your enabled themes
  let currentIndex = 0;

  if (toggle) {
    toggle.addEventListener('change', function() {
      currentIndex = (currentIndex + 1) % themes.length;
      const theme = themes[currentIndex];
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('theme', theme);
      toggle.checked = theme !== 'light';  // Optional: checked for non-light
    });

    // Load saved
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    currentIndex = themes.indexOf(savedTheme);
    toggle.checked = savedTheme !== 'light';
  }
});