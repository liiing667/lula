// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-Present The Lula Authors

import cors from 'cors';
import express from 'express';
import ratelimit from 'express-rate-limit';
import { existsSync, mkdirSync } from 'fs';
import { createServer as createHttpServer } from 'http';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import {
	initializeServerState,
	loadAllData,
	resetServerState,
	saveMappingsToFile
} from './serverState';
import {
	ConnectionPolicy,
	createConnectionPolicy,
	formatHostForUrl,
	getRateLimitKey,
	isLoopbackHostname
} from './connectionSecurity';
import spreadsheetRoutes from './spreadsheetRoutes';
import { wsManager } from './websocketServer';
import { createHash } from 'crypto';

export * from './connectionSecurity';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface ServerOptions {
	controlSetDir: string;
	port: number;
	/**
	 * Loopback address to bind.  Defaults to 127.0.0.1 so the server is never
	 * exposed on a team machine's LAN interface by accident.  Pass `::1` (or
	 * `localhost`) when IPv6 loopback is preferred.
	 */
	host?: string;
	/** Alias for `host`, kept for callers that describe the bind address. */
	bindAddress?: string;
	/** Extra exact loopback origins, normally only needed by a dev proxy. */
	allowedOrigins?: string[];
	/** Alias for `allowedOrigins`. */
	trustedOrigins?: string[];
}

/**
 * Resolve and validate the address the HTTP/WS server will bind to.  A
 * non-loopback host is rejected before any state or socket is created: this is
 * a local UI, not a network service.
 */
export function resolveListenHost(options: Pick<ServerOptions, 'host' | 'bindAddress'>): string {
	const host = (options.host || options.bindAddress || process.env.LULA_HOST || '127.0.0.1').trim();
	const normalized = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
	if (!isLoopbackHostname(normalized)) {
		throw new Error(
			`Refusing to bind Lula to non-loopback address "${host}". Use 127.0.0.1, ::1, or localhost.`
		);
	}
	return normalized;
}

export async function createServer(options: ServerOptions): Promise<{
	app: express.Application;
	start: () => Promise<void>;
	stop: () => Promise<void>;
	policy: ConnectionPolicy;
}> {
	const { controlSetDir, port } = options;
	const host = resolveListenHost(options);

	// The policy is shared by the HTTP guard and the WebSocket server.  Its port
	// is filled in from the actual bound socket (important when port === 0).
	const policy = createConnectionPolicy({
		port,
		host,
		allowedOrigins: options.allowedOrigins ?? options.trustedOrigins
	});

	// Never trust proxy headers.  In particular, X-Forwarded-For must not be
	// allowed to choose the rate-limit bucket or the "local" peer identity.
	const rateLimitOptions = {
		windowMs: 15 * 60 * 1000, // 15 minutes
		max: 200, // max requests per windowMs
		// Use the TCP peer address, never a proxy/forwarded header.  With
		// `trust proxy` disabled this also keeps Express' own req.ip honest.
		keyGenerator: (request: Parameters<typeof getRateLimitKey>[0]) =>
			getRateLimitKey(request)
	};
	const limiter = ratelimit(rateLimitOptions);

	let stateReady = false;
	let stateInitPromise: Promise<void> | null = null;

	const initializeState = (): Promise<void> => {
		if (stateReady) {
			return Promise.resolve();
		}
		if (!stateInitPromise) {
			stateInitPromise = (async () => {
				// Create the writer only after the listening address has been
				// successfully bound.  A failed bind therefore leaves no write state.
				if (!existsSync(controlSetDir)) {
					mkdirSync(controlSetDir, { recursive: true });
				}
				initializeServerState(controlSetDir);
				await loadAllData();
				stateReady = true;
			})();
		}
		return stateInitPromise;
	};

	const resetStateAfterFailure = (): void => {
		stateReady = false;
		stateInitPromise = null;
		if (typeof resetServerState === 'function') {
			resetServerState();
		}
	};

	// Create Express app
	const app = express();

	// Express defaults to not trusting proxy headers, but set this explicitly so
	// changing the app later cannot silently make rate-limit/auth identities
	// spoofable via X-Forwarded-For.
	if (typeof (app as unknown as { set?: unknown }).set === 'function') {
		(app as unknown as { set: (key: string, value: unknown) => void }).set('trust proxy', false);
	}

	// Middleware
	app.use(
		cors({
			origin: (origin, callback) => {
				// No Origin means a non-browser client or a same-origin GET.  The
				// Host/peer checks below still apply to those requests.
				if (!origin) {
					callback(null, true);
					return;
				}
				const decision = policy.authorizeOrigin(origin);
				callback(null, decision.allowed);
			}
		})
	);

	// Enforce the same conclusion for every route, not just CORS preflights.
	// CORS is a browser response-header mechanism; it does not protect simple
	// requests (for example a cross-origin multipart form POST).
	app.use((req, res, next) => {
		const decision = policy.authorizeRequest(req);
		if (!decision.allowed) {
			res.status(403).json({
				error: 'Forbidden',
				reason: decision.reason
			});
			return;
		}
		next();
	});

	// Requests may arrive between the socket becoming writable and the in-memory
	// data finishing loading.  Wait for that one-time initialization instead of
	// touching a partially initialized state.
	app.use((_req, res, next) => {
		if (stateReady) {
			next();
			return;
		}
		if (!stateInitPromise) {
			res.status(503).json({ error: 'Server is starting' });
			return;
		}
		stateInitPromise.then(
			() => next(),
			() => res.status(503).json({ error: 'Server failed to start' })
		);
	});

	app.use(express.json({ limit: '50mb' }));
	app.use(limiter);

	// Serve static files from dist directory (build output)
	const distPath = join(__dirname, '../dist');
	app.use(express.static(distPath));

	// API Routes
	app.use('/api', spreadsheetRoutes);

	// Serve frontend for all other routes (SPA fallback)
	app.get('/*splat', (req, res) => {
		res.sendFile('index.html', { root: distPath });
	});

	// Frontend cannot create hash - webcrypto hash is not supported in all browsers
	app.post('/hash', (req, res) => {
		delete req.body.hash;
		const hash = createHash('sha256').update(JSON.stringify(req.body)).digest('hex');
		res.status(200).json({ hash });
	});

	// Create HTTP server for both Express and WebSocket
	const httpServer = createHttpServer(app);

	// Hand the exact same policy object to the WebSocket server.  Using a
	// property (rather than rebuilding a policy there) is what guarantees HTTP
	// and WS reach the same conclusion, including the actual bound port.
	(httpServer as unknown as { __lulaConnectionPolicy?: ConnectionPolicy }).__lulaConnectionPolicy =
		policy;

	// Initialize WebSocket server
	const websocketManager = wsManager as unknown as {
		setConnectionPolicy?: (policy: ConnectionPolicy) => void;
	};
	if (typeof websocketManager.setConnectionPolicy === 'function') {
		websocketManager.setConnectionPolicy(policy);
	}
	wsManager.initialize(httpServer);

	let startPromise: Promise<void> | null = null;

	const stop = (): Promise<void> => {
		return new Promise<void>((resolve) => {
			if (typeof (httpServer as unknown as { close?: unknown }).close !== 'function') {
				resetStateAfterFailure();
				startPromise = null;
				resolve();
				return;
			}
			(httpServer as unknown as { close: (cb?: () => void) => void }).close(() => {
				resetStateAfterFailure();
				startPromise = null;
				resolve();
			});
		});
	};

	return {
		app,
		policy,
		stop,
		start: () => {
			if (startPromise) {
				return startPromise;
			}

			startPromise = new Promise<void>((resolve, reject) => {
				let settled = false;
				const finish = (error?: Error): void => {
					if (settled) {
						return;
					}
					settled = true;
					if (error) {
						startPromise = null;
						resetStateAfterFailure();
						reject(error);
					} else {
						resolve();
					}
				};

				const onError = (error: Error): void => {
					if (typeof (httpServer as unknown as { off?: unknown }).off === 'function') {
						(httpServer as unknown as { off: (event: string, cb: (e: Error) => void) => void }).off(
							'error',
							onError
						);
					}
					finish(error);
				};

				if (typeof (httpServer as unknown as { once?: unknown }).once === 'function') {
					(httpServer as unknown as { once: (event: string, cb: (e: Error) => void) => void }).once(
						'error',
						onError
					);
				}

				const onListening = async (): Promise<void> => {
					try {
						if (typeof (httpServer as unknown as { off?: unknown }).off === 'function') {
							(
								httpServer as unknown as {
									off: (event: string, cb: (e: Error) => void) => void;
								}
							).off('error', onError);
						}

						// Capture the port that was actually assigned (port 0).
						if (typeof (httpServer as unknown as { address?: unknown }).address === 'function') {
							const address = (
								httpServer as unknown as {
									address: () => { port?: number; address?: string } | string | null;
								}
							).address();
							if (address && typeof address === 'object') {
								policy.setBoundAddress(address.port, address.address);
							}
						}

						await initializeState();
						// A WebSocket may have connected while the initial data was
						// loading.  Send the now-complete state to every client so an
						// early/reconnected local page recovers without a reload.
						const manager = wsManager as unknown as { notifyDataRefresh?: () => void };
						if (typeof manager.notifyDataRefresh === 'function') {
							manager.notifyDataRefresh();
						}
						const displayHost =
							host === '127.0.0.1' ? 'localhost' : formatHostForUrl(host);
						console.log(
							`\n✨ Lula is running at http://${displayHost}:${policy.port ?? port}`
						);
						finish();
					} catch (error) {
						try {
							await stop();
						} catch {
							// The bind failure is the useful error.
						}
						finish(error as Error);
					}
				};

				try {
					// Bind explicitly to a loopback address.  The three-argument
					// form is important: a plain listen(port) would expose the
					// control-set writer on every interface.
					httpServer.listen(port, host, () => {
						void onListening();
					});
				} catch (error) {
					onError(error as Error);
				}
			});

			return startPromise;
		}
	};
}

export async function startServer(options: ServerOptions) {
	const server = await createServer(options);
	await server.start();

	// Set up keyboard input handling
	if (process.stdin.isTTY) {
		process.stdin.setRawMode(true);
		process.stdin.resume();
		process.stdin.setEncoding('utf8');

		console.log('\nPress ESC to close the app\n');

		process.stdin.on('data', async (key) => {
			const keyStr = key.toString();
			// ESC key or Ctrl+C
			if (keyStr === '\u001b' || keyStr === '\u0003') {
				console.log('\n\nShutting down server...');
				try {
					await saveMappingsToFile();
					console.log('Changes saved successfully');
				} catch (error) {
					console.error('Error saving changes:', error);
				}
				process.exit(0);
			}
		});
	}

	// Graceful shutdown
	process.on('SIGINT', async () => {
		try {
			await saveMappingsToFile();
		} catch (error) {
			console.error('Error saving changes:', error);
		}
		process.exit(0);
	});
}
