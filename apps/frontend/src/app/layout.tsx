/*
SOC-CyBe Security Platform
Module: Frontend Root Layout

Purpose:
This file defines the shared document shell for the SOC dashboard.
It applies the project's typography, metadata, and animated background.

Design Notes:
- The layout is intentionally minimal because operational screens should be
  easy to extend without reworking the app shell.
- The background animation supports the cyber operations aesthetic without
  getting in the way of dashboard readability.
*/

import type { Metadata } from "next";
import { JetBrains_Mono, Oxanium } from "next/font/google";

import { TerminalRain } from "@/components/terminal-rain";

import "./globals.css";

const headingFont = Oxanium({
  subsets: ["latin"],
  variable: "--font-heading",
});

const monoFont = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "SOC-CyBe | Security Operations Center - Cyber Behavior Engine",
  description:
    "Distributed SOC platform for real-time threat monitoring, API detection, risk scoring, incident response, and compliance review.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  /* The terminal rain effect is mounted once at the root so every page gets
     the same atmosphere without each screen re-implementing it. */
  return (
    <html lang="en">
      <body className={`${headingFont.variable} ${monoFont.variable}`}>
        <TerminalRain />
        {children}
      </body>
    </html>
  );
}
