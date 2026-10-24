package allow

import "strings"

// Well-known hex constants that a wallet-address pattern can match but that are never a
// payment destination an attacker controls.
//
// The P-CRYPTO-WALLET rule (and the IOC extractor's wallet type) treat a standalone
// 0x-prefixed 40-hex token as an Ethereum address. Cryptography and DeFi libraries carry
// such tokens as public constants: the burn and zero addresses that every ERC-20 helper
// compares against, the canonical stablecoin contracts every wallet SDK lists, and the
// secp256k1 curve parameters (64 hex, kept here so a looser pattern cannot pick them up
// either). Audited 2026-10: `_N = 0xFFFF…364141`, `0x000…dEaD` and USDC on Base
// (`0x833589fC…02913`) were each read as an attacker wallet in a pypi library.
//
// Only values that are unambiguously public constants are listed; each contract address
// is the issuer's canonical deployment. Matching is case-insensitive (EIP-55 checksum
// casing is presentation, not identity), and a leading 0x is optional.
var wellKnownConstants = func() map[string]string {
	m := map[string]string{}
	add := func(name string, vals ...string) {
		for _, v := range vals {
			m[normHex(v)] = name
		}
	}

	// secp256k1 (SEC 2, §2.4.1): the group order n and the field prime p.
	add("secp256k1 order n", "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	add("secp256k1 field prime p", "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")

	// EVM sentinel addresses.
	add("EVM zero address", "0x0000000000000000000000000000000000000000")
	add("EVM burn address", "0x000000000000000000000000000000000000dEaD")

	// Canonical stablecoin contracts (issuer deployments).
	add("USDC (Ethereum)", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
	add("USDT (Ethereum)", "0xdAC17F958D2ee523a2206206994597C13D831ec7")
	add("USDC (Base)", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	add("USDC (Polygon)", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359")
	add("USDC.e bridged (Polygon)", "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174")
	add("USDT (Polygon)", "0xc2132D05D31c914a87C6611C10748AEb04B58e8F")
	add("USDC (Arbitrum One)", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831")
	add("USDC.e bridged (Arbitrum One)", "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8")
	add("USDT (Arbitrum One)", "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9")
	return m
}()

func normHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(s, "0x")
}

// KnownConstant reports whether s (a hex token, with or without 0x, any case) is a well-known
// public constant, and names it. A wallet-shaped match on one of these is not an indicator.
func KnownConstant(s string) (string, bool) {
	name, ok := wellKnownConstants[normHex(s)]
	return name, ok
}
