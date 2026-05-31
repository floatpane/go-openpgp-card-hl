import type { Metadata } from "next";
import "./globals.css";
import "highlight.js/styles/github-dark.css";

export const metadata: Metadata = {
	title: "go-openpgp-card-hl",
	description:
		"High-level OpenPGP smartcard signer and decryptor for Go. Detached armored signatures, RSA decryption, and structured card info for YubiKey, Nitrokey, and other OpenPGP cards — with errors a human can act on.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
	return (
		<html lang="en">
			<body>
				<header className="site-header">
					<a href="/" className="brand">
						go-openpgp-card-hl
					</a>
					<nav>
						<a href="https://github.com/floatpane/go-openpgp-card-hl">GitHub</a>
					</nav>
				</header>
				<main>{children}</main>
			</body>
		</html>
	);
}
