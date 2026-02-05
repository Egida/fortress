import type { Metadata } from 'next';
import './globals.css';
import AuthLayout from '@/components/auth-layout';

export const metadata: Metadata = {
  title: 'Fortress - Anti-DDoS Panel',
  description: 'Fortress Anti-DDoS Reverse Proxy Admin Panel',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="tr" className="dark" suppressHydrationWarning>
      <body className="bg-black text-zinc-100 antialiased" suppressHydrationWarning>
        <AuthLayout>{children}</AuthLayout>
      </body>
    </html>
  );
}
