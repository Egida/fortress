'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import {
  Shield, ShieldAlert, Crosshair, Server, Radio, Swords, Ban,
  ScrollText, BarChart3, Settings, Network, LogOut, Fingerprint,
  FileCheck, Globe, Zap, Eye, BookLock, Languages, BookOpen
} from 'lucide-react';
import { PROTECTION_LEVELS } from '@/lib/constants';
import { useLocale } from '@/lib/useLocale';

const FORTRESS_VERSION = 'v2.0.0';

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [protectionLevel, setProtectionLevel] = useState<string>('Normal');
  const { locale, toggleLocale, t, mounted } = useLocale();

  const navItems = [
    { key: 'nav.command_center', href: '/', icon: Crosshair },
    { key: 'nav.attack_monitor', href: '/attack-monitor', icon: Eye },
    { key: 'nav.services', href: '/services', icon: Server },
    { key: 'nav.live', href: '/live', icon: Radio },
    { key: 'nav.attacks', href: '/attacks', icon: Swords },
    { key: 'nav.blocklist', href: '/blocklist', icon: Ban },
    { key: 'nav.rules', href: '/rules', icon: ScrollText },
    { key: 'nav.analytics', href: '/analytics', icon: BarChart3 },
    { key: 'nav.ip_reputation', href: '/ip-reputation', icon: Fingerprint },
    { key: 'nav.auto_bans', href: '/auto-bans', icon: Zap },
    { key: 'nav.managed_rules', href: '/managed-rules', icon: BookLock },
    { key: 'nav.threat_map', href: '/threat-map', icon: Globe },
    { key: 'nav.knowledge_base', href: '/knowledge-base', icon: BookOpen },
  ];

  const bottomItems = [
    { key: 'nav.settings', href: '/settings', icon: Settings },
    { key: 'nav.l4', href: '/settings/l4', icon: Network },
  ];

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch('/api/fortress/status');
        if (res.ok) {
          const data = await res.json();
          if (data.protection_level) {
            setProtectionLevel(data.protection_level);
          }
        }
      } catch {
        // Silently handle - status will update on next poll
      }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const currentLevel = PROTECTION_LEVELS[protectionLevel] ?? PROTECTION_LEVELS.Normal;

  const isActive = (href: string) => {
    if (href === '/') return pathname === '/';
    return pathname.startsWith(href);
  };

  const handleLogout = async () => {
    await fetch('/api/auth', { method: 'DELETE' });
    router.push('/login');
    router.refresh();
  };

  return (
    <aside className="fixed left-0 top-0 bottom-0 w-60 bg-zinc-950 border-r border-zinc-800 flex flex-col z-50">
      {/* Branding Header */}
      <div className="px-5 py-5 border-b border-zinc-800">
        <Link href="/" className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center relative">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="text-white font-bold text-lg tracking-tight flex items-center gap-2">
              FORTRESS
              <span className="text-[10px] font-mono font-normal text-zinc-600 bg-zinc-800/60 px-1.5 py-0.5 rounded">
                {FORTRESS_VERSION}
              </span>
            </div>
            <div className="text-zinc-500 text-xs tracking-wide">Threat Defense Platform</div>
          </div>
        </Link>
      </div>

      {/* Protection Level Indicator */}
      <div className={`mx-3 mt-3 px-3 py-2 rounded-lg border ${currentLevel.borderColor} ${currentLevel.color}`}>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${currentLevel.dotColor} animate-pulse`} />
          <span className={`text-xs font-semibold font-mono ${currentLevel.textColor}`}>
            {currentLevel.label}
          </span>
        </div>
        <div className={`text-[10px] mt-0.5 ${currentLevel.textColor} opacity-70`}>
          {currentLevel.name}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {navItems.map((item) => {
          const active = isActive(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] transition-all duration-150 ${
                active
                  ? 'bg-blue-600/10 text-blue-400 font-medium border border-blue-500/10'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 border border-transparent'
              }`}
            >
              <item.icon className={`w-4 h-4 flex-shrink-0 ${active ? 'text-blue-400' : 'text-zinc-500'}`} />
              <span className="truncate">{t(item.key)}</span>
            </Link>
          );
        })}

        <div className="pt-3 mt-3 border-t border-zinc-800/60">
          {bottomItems.map((item) => {
            const active = isActive(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] transition-all duration-150 ${
                  active
                    ? 'bg-blue-600/10 text-blue-400 font-medium border border-blue-500/10'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 border border-transparent'
                }`}
              >
                <item.icon className={`w-4 h-4 flex-shrink-0 ${active ? 'text-blue-400' : 'text-zinc-500'}`} />
                <span className="truncate">{t(item.key)}</span>
              </Link>
            );
          })}
        </div>
      </nav>

      {/* Footer */}
      <div className="px-3 py-3 border-t border-zinc-800">
        <button
          onClick={toggleLocale}
          className="flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] text-zinc-400 hover:text-blue-400 hover:bg-blue-500/10 transition-colors w-full mb-1"
        >
          <Languages className="w-4 h-4" />
          <span>{mounted ? (locale === 'en' ? 'Turkce' : 'English') : 'Turkce'}</span>
          <span className="ml-auto text-[10px] font-mono text-zinc-600 bg-zinc-800 px-1.5 py-0.5 rounded">
            {mounted ? locale.toUpperCase() : 'EN'}
          </span>
        </button>
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] text-zinc-500 hover:text-red-400 hover:bg-red-500/10 transition-colors w-full"
        >
          <LogOut className="w-4 h-4" />
          {t('nav.disconnect')}
        </button>
        <div className="px-3 mt-2 flex items-center justify-between">
          <span className="text-[10px] font-mono text-zinc-700">FORTRESS {FORTRESS_VERSION}</span>
          <span className="flex items-center gap-1">
            <span className={`w-1.5 h-1.5 rounded-full ${currentLevel.dotColor}`} />
            <span className="text-[10px] font-mono text-zinc-600">{currentLevel.label}</span>
          </span>
        </div>
      </div>
    </aside>
  );
}
