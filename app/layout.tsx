import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "가드오피스 — 나의 AI 보안팀",
  description: "전문 분야별 AI 보안팀이 웹사이트와 운영 환경을 지켜보는 보안 관제 서비스",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="ko"><body>{children}</body></html>;
}
