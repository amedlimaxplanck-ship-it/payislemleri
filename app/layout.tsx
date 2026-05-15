import React from 'react';
import type { Metadata } from "next";
import { JakartaSans } from "@/lib/fonts";
import "./globals.css";

export const metadata: Metadata = {
  title: "SUPA PANEL | Güvenli Erişim",
  description: "Kurumsal Yönetim ve Güvenlik Portalı",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="tr">
      <body className={JakartaSans.className}>{children}</body>
    </html>
  );
}
