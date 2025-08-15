export const metadata = {
  title: "SEO Checker API",
  description: "Edge API for quick SEO checks",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
