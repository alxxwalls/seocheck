export const metadata = {
  title: "SEO Checker API",
  description: "Edge API for quick SEO checks",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
