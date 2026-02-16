const PASSWORD_GEN_LENGTH_KEY = 'send_password_length';
const PASSWORD_GEN_GROUPED_KEY = 'send_password_grouped';

export interface SendPasswordGeneratorSettings {
  length: number;
  grouped: boolean;
}

export function isDark(): boolean {
  return document.documentElement.classList.contains('dark');
}

export function setDarkMode(dark: boolean): void {
  document.documentElement.classList.toggle('dark', dark);
  try {
    localStorage.setItem('theme', dark ? 'dark' : 'light');
  } catch {}
}

export function getSendPasswordGeneratorSettings(
  defaultLength = 20,
  minLength = 1,
): SendPasswordGeneratorSettings {
  let length = defaultLength;
  let grouped = false;

  try {
    const storedLength = localStorage.getItem(PASSWORD_GEN_LENGTH_KEY);
    if (storedLength !== null) {
      const parsed = Number.parseInt(storedLength, 10);
      if (Number.isInteger(parsed) && parsed >= minLength) {
        length = parsed;
      }
    }

    const storedGrouped = localStorage.getItem(PASSWORD_GEN_GROUPED_KEY);
    if (storedGrouped === 'true') {
      grouped = true;
    } else if (storedGrouped === 'false') {
      grouped = false;
    }
  } catch {}

  return { length, grouped };
}

export function setSendPasswordGeneratorSettings(
  length: number,
  grouped: boolean,
): void {
  if (!Number.isInteger(length) || length < 1) return;

  try {
    localStorage.setItem(PASSWORD_GEN_LENGTH_KEY, String(length));
    localStorage.setItem(PASSWORD_GEN_GROUPED_KEY, grouped ? 'true' : 'false');
  } catch {}
}
