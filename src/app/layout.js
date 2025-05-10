import "./globals.css"

export const metadata = {
  title: "Happy Mother's Day",
  description: "A special Mother's Day message from your child",
}

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased">{children}</body>
    </html>
  )
}
