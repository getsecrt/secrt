export function isDark(): boolean {
  return document.documentElement.classList.contains('dark');
}

export function setDarkMode(dark: boolean): void {
  document.documentElement.classList.toggle('dark', dark);
  try {
    localStorage.setItem('theme', dark ? 'dark' : 'light');
  } catch {}
}
