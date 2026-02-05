'use client';

import { useState, useEffect, useCallback } from 'react';
import { type Locale, getStoredLocale, setStoredLocale, t as translate } from './i18n';

export function useLocale() {
  const [locale, setLocaleState] = useState<Locale>('en');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setLocaleState(getStoredLocale());
    setMounted(true);
  }, []);

  const setLocale = useCallback((newLocale: Locale) => {
    setLocaleState(newLocale);
    setStoredLocale(newLocale);
  }, []);

  const t = useCallback((key: string) => translate(key, locale), [locale]);

  const toggleLocale = useCallback(() => {
    const next = locale === 'en' ? 'tr' : 'en';
    setLocale(next);
  }, [locale, setLocale]);

  return { locale, setLocale, t, toggleLocale, mounted };
}
