'use client';

import { usePathname } from 'next/navigation';
import Sidebar from '@/components/sidebar';

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isLoginPage = pathname === '/login';

  if (isLoginPage) {
    return <>{children}</>;
  }

  return (
    <>
      <Sidebar />
      <main className="ml-60 min-h-screen">
        <div className="p-6 max-w-[1600px] mx-auto">
          {children}
        </div>
      </main>
    </>
  );
}
