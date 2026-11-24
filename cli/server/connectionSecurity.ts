// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-Present The Lula Authors

/**
 * Local-server connection policy.
 *
 * Lula's UI is a local application: it is served from a loopback address and is
 * meant to be used by the browser window that the CLI opened.  A localhost
 * listener is not, by itself, a security boundary.  Any web page can make a
 * request to (or open a WebSocket with) a localhost service, and DNS rebinding
 * can make a remote page look local at the TCP layer.
 *
 * This module contains the single decision used by both the HTTP middleware and
 * the WebSocket upgrade/connection handling.  Keeping the decision in one place
 * avoids the common bug where CORS is locked down but the WebSocket endpoint is
 * still an unauthenticated, cross-origin write channel.
 */

export interface HeaderMapLike {
	[key: string]: string | string[] | undefined;
}

export interface RequestLike {
	headers?: HeaderMapLike;
	socket?: { remoteAddress?: string | null } | null;
	connection?: { remoteAddress?: string | null } | null;
	ip?: string;
}

export interface ConnectionDecision {
	allowed: boolean;
	reason?: string;
	origin?: string;
	host?: string;
}

export interface ConnectionPolicyOptions {
	/** The port the server is actually listening on. */
	port?: number;
	/** The address the server was asked to listen on. */
	host?: string;
	/** Extra exact origins (for example, a custom development proxy). */
	allowedOrigins?: string[];
}

/**
 * Vite's development server (and `vite preview`) use a different origin than
 * the API server.  These are the ports used by the project's dev workflows.
 * They are still loopback-only origins; the port is what has to be special
 * cased, not the host.
 */
export const DEFAULT_DEV_ORIGIN_PORTS = new Set<number>();
for (let port = 4173; port <= 4183; port++) {
	DEFAULT_DEV_ORIGIN_PORTS.add(port);
}
for (let port = 5173; port <= 5183; port++) {
	DEFAULT_DEV_ORIGIN_PORTS.add(port);
}

const IPV4_PATTERN = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV6_MAPPED_PATTERN = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i;

function isIPv4(value: string): boolean {
	if (!IPV4_PATTERN.test(value)) {
		return false;
	}
	return value.split('.').every((part) => {
		const octet = Number(part);
		return Number.isInteger(octet) && octet >= 0 && octet <= 255;
	});
}

function ipv4FromMappedIPv6(value: string): string | null {
	const match = IPV6_MAPPED_PATTERN.exec(value);
	if (!match) {
		return null;
	}
	const high = parseInt(match[1], 16);
	const low = parseInt(match[2], 16);
	return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

/**
 * Normalize a hostname or socket address so that equivalent IPv4/IPv6 forms
 * compare consistently.  Brackets, trailing dots, zones, and IPv4-mapped IPv6
 * addresses are handled here.
 */
export function normalizeHostname(hostname: string | null | undefined): string {
	let value = (hostname ?? '').trim().toLowerCase();
	if (!value) {
		return '';
	}

	if (value.startsWith('[') && value.endsWith(']')) {
		value = value.slice(1, -1);
	}

	// IPv6 scopes are only meaningful to the OS, not to a Host/Origin check.
	const zoneIndex = value.indexOf('%');
	if (zoneIndex !== -1) {
		value = value.slice(0, zoneIndex);
	}

	if (value.endsWith('.')) {
		value = value.slice(0, -1);
	}

	const mapped = ipv4FromMappedIPv6(value);
	if (mapped) {
		return mapped;
	}
	if (value.startsWith('::ffff:') && isIPv4(value.slice(7))) {
		return value.slice(7);
	}

	return value;
}

/**
 * Is this hostname one of the local machine's loopback names?  `localhost` and
 * the whole 127.0.0.0/8 range are accepted for IPv4; `::1` and IPv4-mapped
 * loopback addresses are accepted for IPv6.
 */
export function isLoopbackHostname(hostname: string | null | undefined): boolean {
	const value = normalizeHostname(hostname);
	if (!value) {
		return false;
	}

	if (value === 'localhost' || value.endsWith('.localhost')) {
		return true;
	}

	if (value === '::1' || value === '0:0:0:0:0:0:0:1') {
		return true;
	}

	if (isIPv4(value)) {
		return value.split('.')[0] === '127';
	}

	return false;
}

/** Is a socket's remote address a loopback address? */
export function isLoopbackAddress(address: string | null | undefined): boolean {
	return isLoopbackHostname(address);
}

export interface ParsedAuthority {
	hostname: string;
	port?: number;
}

function parsePort(value: string | null | undefined): number | undefined {
	if (!value) {
		return undefined;
	}
	const port = Number(value);
	if (!Number.isInteger(port) || port < 1 || port > 65535) {
		return undefined;
	}
	return port;
}

/**
 * Parse a Host header or an Origin host into a hostname/port pair.  A malformed
 * authority (multiple values, userinfo, a path, etc.) returns null so callers
 * can fail closed.
 */
export function parseAuthority(authority: string | null | undefined): ParsedAuthority | null {
	if (!authority) {
		return null;
	}
	const raw = authority.trim();
	if (!raw || raw.includes(',') || raw.includes('/') || raw.includes('\\') || raw.includes('@')) {
		return null;
	}

	try {
		const url = new URL(`http://${raw}`);
		if (!url.hostname) {
			return null;
		}
		const hostname = normalizeHostname(url.hostname);
		const port = parsePort(url.port);
		return { hostname, port };
	} catch {
		return null;
	}
}

export interface ParsedOrigin extends ParsedAuthority {
	protocol: string;
}

/** Parse and sanity-check an Origin header. */
export function parseOrigin(origin: string | null | undefined): ParsedOrigin | null {
	if (!origin) {
		return null;
	}
	const raw = origin.trim();
	if (!raw || raw === 'null' || raw.includes(',')) {
		return null;
	}

	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return null;
	}

	if (url.protocol !== 'http:' && url.protocol !== 'https:') {
		return null;
	}
	if (url.username || url.password) {
		return null;
	}
	if (url.pathname !== '/' && url.pathname !== '') {
		return null;
	}
	if (url.search || url.hash) {
		return null;
	}

	const hostname = normalizeHostname(url.hostname);
	if (!hostname) {
		return null;
	}

	return {
		protocol: url.protocol,
		hostname,
		port: parsePort(url.port)
	};
}

function defaultPortForProtocol(protocol: string | undefined): number | undefined {
	if (protocol === 'http:') {
		return 80;
	}
	if (protocol === 'https:') {
		return 443;
	}
	return undefined;
}

function headerValue(value: string | string[] | undefined): string | undefined {
	if (Array.isArray(value)) {
		return value[0];
	}
	return value;
}

/**
 * A mutable policy object.  The port becomes known only after the HTTP server
 * has actually bound its socket, so the same policy instance is updated at that
 * point rather than being rebuilt for HTTP and WebSocket separately.
 */
export class ConnectionPolicy {
	public port?: number;
	public host?: string;
	private readonly allowedOrigins: Set<string>;

	constructor(options: ConnectionPolicyOptions = {}) {
		// The CLI's default API port.  A standalone policy (for example one
		// created before an HTTP server exists) should still fail closed for
		// random localhost ports rather than accepting every local web page.
		this.port = options.port ?? 3000;
		this.host = options.host;
		this.allowedOrigins = new Set(
			(options.allowedOrigins ?? [])
				.map((origin) => this.normalizeOriginKey(origin))
				.filter((origin): origin is string => Boolean(origin))
		);
	}

	/** Update the policy once the real listening address is known. */
	public setBoundAddress(port?: number, host?: string): void {
		if (port !== undefined) {
			this.port = port;
		}
		if (host) {
			this.host = host;
		}
	}

	private normalizeOriginKey(origin: string): string | null {
		const parsed = parseOrigin(origin);
		if (!parsed) {
			return null;
		}
		const port = parsed.port ?? defaultPortForProtocol(parsed.protocol);
		return `${parsed.protocol}//${parsed.hostname}${port ? `:${port}` : ''}`;
	}

	private isAllowedOriginPort(port: number | undefined, protocol: string): boolean {
		const actualPort = port ?? defaultPortForProtocol(protocol);
		if (actualPort === undefined) {
			return false;
		}
		if (this.port === actualPort) {
			return true;
		}
		return DEFAULT_DEV_ORIGIN_PORTS.has(actualPort);
	}

	/** Check an Origin header value. */
	public authorizeOrigin(origin: string | null | undefined): ConnectionDecision {
		if (!origin) {
			return { allowed: false, reason: 'missing-origin' };
		}
		const parsed = parseOrigin(origin);
		if (!parsed) {
			return { allowed: false, reason: 'invalid-origin' };
		}
		if (!isLoopbackHostname(parsed.hostname)) {
			return { allowed: false, reason: 'non-loopback-origin', origin };
		}

		const normalized = this.normalizeOriginKey(origin);
		if (normalized && this.allowedOrigins.has(normalized)) {
			return { allowed: true, origin };
		}

		if (!this.isAllowedOriginPort(parsed.port, parsed.protocol)) {
			return { allowed: false, reason: 'unexpected-origin-port', origin };
		}

		return { allowed: true, origin };
	}

	/** Check a Host header value. */
	public authorizeHost(host: string | null | undefined): ConnectionDecision {
		if (!host) {
			return { allowed: false, reason: 'missing-host' };
		}
		const parsed = parseAuthority(host);
		if (!parsed) {
			return { allowed: false, reason: 'invalid-host' };
		}
		if (!isLoopbackHostname(parsed.hostname)) {
			return { allowed: false, reason: 'non-loopback-host', host };
		}
		if (this.port !== undefined && parsed.port !== undefined) {
			const actualPort = parsed.port ?? 80;
			if (actualPort !== this.port) {
				return { allowed: false, reason: 'unexpected-host-port', host };
			}
		}
		return { allowed: true, host };
	}

	/**
	 * Authorize one HTTP request or WebSocket handshake.  This is the shared
	 * conclusion required by both transports.
	 */
	public authorizeRequest(request: RequestLike | null | undefined): ConnectionDecision {
		if (!request) {
			return { allowed: false, reason: 'missing-request' };
		}

		// Only a connection from the local machine may talk to this server.  The
		// remote address comes from the socket, never from X-Forwarded-For.
		const remoteAddress = request.socket?.remoteAddress ?? request.connection?.remoteAddress;
		if (remoteAddress && !isLoopbackAddress(remoteAddress)) {
			return { allowed: false, reason: 'non-loopback-peer' };
		}

		// Sec-Fetch-Site is a browser signal, not a secret.  When present, refuse
		// the one value that unambiguously describes a cross-site page.  A direct
		// WebSocket from the Vite dev origin is "same-site", which must remain
		// usable for the development workflow.
		const fetchSite = headerValue(request.headers?.['sec-fetch-site']);
		if (fetchSite && fetchSite.toLowerCase() === 'cross-site') {
			return { allowed: false, reason: 'cross-site-request' };
		}

		const host = headerValue(request.headers?.host);
		const hostDecision = this.authorizeHost(host);
		if (!hostDecision.allowed) {
			return hostDecision;
		}

		const origin = headerValue(request.headers?.origin);
		if (origin) {
			const originDecision = this.authorizeOrigin(origin);
			if (!originDecision.allowed) {
				return originDecision;
			}
		} else if (fetchSite && fetchSite.toLowerCase() === 'cross-site') {
			// Defensive: covered above, but keeps the "no origin + cross-site"
			// combination explicit for readers and future refactors.
			return { allowed: false, reason: 'cross-site-request' };
		}

		return { allowed: true, origin, host };
	}

	public isAllowed(request: RequestLike | null | undefined): boolean {
		return this.authorizeRequest(request).allowed;
	}

	public isOriginAllowed(origin: string | null | undefined): boolean {
		return this.authorizeOrigin(origin).allowed;
	}

	public isHostAllowed(host: string | null | undefined): boolean {
		return this.authorizeHost(host).allowed;
	}
}

export function createConnectionPolicy(
	options: ConnectionPolicyOptions = {}
): ConnectionPolicy {
	return new ConnectionPolicy(options);
}

/**
 * Convenience wrapper used by middleware and tests that only care about the
 * boolean result.
 */
export function isAllowedRequest(
	request: RequestLike | null | undefined,
	policy: ConnectionPolicy
): boolean {
	return policy.authorizeRequest(request).allowed;
}

function asPolicy(policy?: ConnectionPolicy | ConnectionPolicyOptions): ConnectionPolicy {
	return policy instanceof ConnectionPolicy ? policy : createConnectionPolicy(policy ?? {});
}

export function isAllowedOrigin(
	origin: string | null | undefined,
	policy?: ConnectionPolicy | ConnectionPolicyOptions
): boolean {
	return asPolicy(policy).authorizeOrigin(origin).allowed;
}

export function isAllowedHost(
	host: string | null | undefined,
	policy?: ConnectionPolicy | ConnectionPolicyOptions
): boolean {
	return asPolicy(policy).authorizeHost(host).allowed;
}

export function isAllowedBrowserRequest(
	request: RequestLike | null | undefined,
	policy?: ConnectionPolicy | ConnectionPolicyOptions
): boolean {
	return asPolicy(policy).authorizeRequest(request).allowed;
}

/** Format a hostname for use in a URL (IPv6 needs brackets). */
export function formatHostForUrl(hostname: string): string {
	const value = hostname.trim();
	if (value.startsWith('[') && value.endsWith(']')) {
		return value;
	}
	const normalized = normalizeHostname(value);
	return normalized.includes(':') ? `[${normalized}]` : normalized;
}

/**
 * Key used by express-rate-limit.  Deliberately use the TCP peer address and
 * ignore X-Forwarded-For and friends, which are attacker-controlled unless a
 * trusted proxy has already been configured.
 */
export function getRateLimitKey(request: RequestLike | null | undefined): string {
	const address =
		request?.socket?.remoteAddress ?? request?.connection?.remoteAddress ?? 'unknown';
	return normalizeHostname(address) || 'unknown';
}

// Aliases kept intentionally small and descriptive for callers/tests.
export const getClientIdentity = getRateLimitKey;
export const isTrustedRequest = isAllowedRequest;
export const isLoopbackOrigin = isAllowedOrigin;
