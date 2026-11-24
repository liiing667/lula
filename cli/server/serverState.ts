// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023-Present The Lula Authors

import { join, relative, isAbsolute } from 'path';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { debug } from '../utils/debug';
import { FileStore } from './infrastructure/fileStore';
import { GitHistoryUtil } from './infrastructure/gitHistory';
import * as controlHelpers from './infrastructure/controlHelpers';
import type { Control, ControlSetMetadata, Mapping } from './types';

/**
 * A single file that could not be loaded as part of a generation.
 * Invalid YAML is isolated to the file that contains it: the rest of the
 * generation is still committed.
 */
export interface GenerationLoadError {
	path: string;
	error: string;
}

/**
 * Immutable view of one committed generation. Discovery, loading and the
 * websocket client state all read the same snapshot so a failed reload can
 * never blend the previous cache with files from the failed attempt.
 */
export interface CommittedGeneration {
	generation: number;
	controlSetDir: string;
	currentSubdir: string;
	currentPath: string;
	metadata: ControlSetMetadata;
	controls: Control[];
	mappings: Mapping[];
	families: string[];
	totalControls: number;
	totalMappings: number;
	loadErrors: GenerationLoadError[];
}

/**
 * Server state management for the CLI server
 */
export interface CLIServerState {
	CONTROL_SET_DIR: string; // Base directory (root)
	currentSubdir: string; // Current subdirectory (e.g., 'new-fancy' or '.')
	currentPath: string; // Committed path for currentSubdir
	fileStore: FileStore;
	gitHistory: GitHistoryUtil;
	controlsCache: Map<string, Control>;
	mappingsCache: Map<string, Mapping>;
	controlsByFamily: Map<string, Set<string>>;
	mappingsByFamily: Map<string, Set<string>>;
	mappingsByControl: Map<string, Set<string>>;
	/** Monotonic id of the last successfully committed snapshot. */
	generation: number;
	/** Explicit alias used by callers that need the committed value. */
	committedGeneration: number;
	/** Metadata that belongs to the committed generation (not re-read per client). */
	metadata: ControlSetMetadata;
	/** Files that failed to load, scoped to the generation they belong to. */
	loadErrors: GenerationLoadError[];
}

let serverState: CLIServerState | undefined = undefined;
let switchSequence = 0;

export function resolveControlSetPath(controlSetDir: string, subdir: string = '.'): string {
	return subdir === '.' ? controlSetDir : join(controlSetDir, subdir);
}

function loadMetadataForPath(currentPath: string): ControlSetMetadata {
	try {
		const existsSync = fs.existsSync;
		const readFileSync = fs.readFileSync;
		if (typeof existsSync !== 'function' || typeof readFileSync !== 'function') {
			return {};
		}
		const metadataPath = join(currentPath, 'lula.yaml');
		if (!existsSync(metadataPath)) {
			return {};
		}
		const content = readFileSync(metadataPath, 'utf8');
		const parsed = typeof yaml.load === 'function' ? yaml.load(content) : null;
		return (parsed && typeof parsed === 'object' ? parsed : {}) as ControlSetMetadata;
	} catch (error) {
		// A bad lula.yaml only affects the metadata itself. Controls can still
		// be discovered and loaded, so do not fail the generation here.
		debug('Failed to load control set metadata:', error);
		return {};
	}
}

function createServerState(controlSetDir: string, subdir: string = '.'): CLIServerState {
	const fullPath = resolveControlSetPath(controlSetDir, subdir);

	return {
		CONTROL_SET_DIR: controlSetDir,
		currentSubdir: subdir,
		currentPath: fullPath,
		fileStore: new FileStore({ baseDir: fullPath }),
		gitHistory: new GitHistoryUtil(fullPath),
		controlsCache: new Map<string, Control>(),
		mappingsCache: new Map<string, Mapping>(),
		controlsByFamily: new Map<string, Set<string>>(),
		mappingsByFamily: new Map<string, Set<string>>(),
		mappingsByControl: new Map<string, Set<string>>(),
		generation: 0,
		committedGeneration: 0,
		metadata: loadMetadataForPath(fullPath),
		loadErrors: []
	};
}

function clearControlMetadataCache(): void {
	try {
		const clearMetadataCache = controlHelpers.clearMetadataCache;
		if (typeof clearMetadataCache === 'function') {
			clearMetadataCache();
		}
	} catch {
		// Older/mocked integrations may not expose the cache helper.
	}
}

function warmControlMetadataCache(currentPath: string): void {
	try {
		const loadControlSetMetadata = controlHelpers.loadControlSetMetadata;
		if (typeof loadControlSetMetadata === 'function') {
			loadControlSetMetadata(currentPath);
		}
	} catch {
		// Metadata will be reloaded lazily by getControlId if needed.
	}
}

export function initializeServerState(controlSetDir: string, subdir: string = '.'): CLIServerState {
	switchSequence++;

	// Metadata is cached by controlHelpers. Clear it when (re)initialising so a
	// retry cannot keep metadata from a previously failed generation.
	clearControlMetadataCache();

	serverState = createServerState(controlSetDir, subdir);

	return serverState;
}

export function getServerState(): CLIServerState {
	if (!serverState) {
		throw new Error('Server state not initialized. Call initializeServerState() first.');
	}
	return serverState;
}

export function getCurrentControlSetPath(): string {
	const state = getServerState();
	return state.currentPath || resolveControlSetPath(state.CONTROL_SET_DIR, state.currentSubdir);
}

function indexControl(control: Control, controlsByFamily: Map<string, Set<string>>): void {
	const family = control.family;

	if (!family) {
		return;
	}

	// Add to family index
	if (!controlsByFamily.has(family)) {
		controlsByFamily.set(family, new Set());
	}
	controlsByFamily.get(family)!.add(control.id);
}

export function addControlToIndexes(control: Control): void {
	const state = getServerState();
	indexControl(control, state.controlsByFamily);
}

function indexMapping(
	mapping: Mapping,
	mappingsByFamily: Map<string, Set<string>>,
	mappingsByControl: Map<string, Set<string>>
): void {
	const family = mapping.control_id.split('-')[0];

	// Add to family index
	if (!mappingsByFamily.has(family)) {
		mappingsByFamily.set(family, new Set());
	}
	mappingsByFamily.get(family)!.add(mapping.hash!);

	// Add to control index
	if (!mappingsByControl.has(mapping.control_id)) {
		mappingsByControl.set(mapping.control_id, new Set());
	}
	mappingsByControl.get(mapping.control_id)!.add(mapping.hash!);
}

export function addMappingToIndexes(mapping: Mapping): void {
	const state = getServerState();
	indexMapping(mapping, state.mappingsByFamily, state.mappingsByControl);
}

function replaceMapContents<K, V>(target: Map<K, V>, source: Map<K, V>): void {
	// Mutate the existing map instead of replacing it: other modules keep a
	// reference to these maps and must observe the committed generation.
	target.clear();
	for (const [key, value] of source) {
		target.set(key, value);
	}
}

function isInsideOrEqual(parent: string, child: string): boolean {
	const rel = relative(parent, child);
	return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

export { isInsideOrEqual };

/**
 * Read the currently committed generation. The snapshot is built
 * synchronously from the published state, so controls, mappings, metadata
 * and currentPath always describe the same generation.
 */
export function getCommittedState(): CommittedGeneration {
	const state = getServerState();
	const currentPath = getCurrentControlSetPath();

	return {
		generation: state.committedGeneration ?? state.generation ?? 0,
		controlSetDir: state.CONTROL_SET_DIR,
		currentSubdir: state.currentSubdir,
		currentPath,
		metadata: { ...(state.metadata || {}) },
		controls: Array.from(state.controlsCache.values()),
		mappings: Array.from(state.mappingsCache.values()),
		families: Array.from(state.controlsByFamily.keys()).sort(),
		totalControls: state.controlsCache.size,
		totalMappings: state.mappingsCache.size,
		loadErrors: [...(state.loadErrors || [])]
	};
}

// Friendly aliases for callers that want an explicit snapshot rather than
// reaching into the mutable state object.
export const getStateSnapshot = getCommittedState;
export const getCommittedGenerationSnapshot = getCommittedState;

export function getGeneration(): number {
	const state = getServerState();
	return state.committedGeneration ?? state.generation ?? 0;
}

export const getCommittedGeneration = getGeneration;

/**
 * Load all controls and mappings from disk into the supplied state as a new
 * generation.
 *
 * Nothing is written to the target caches until both loads have completed.
 * If a reload fails, the previously committed generation remains untouched
 * and can be used (and retried) as a consistent snapshot.
 */
export async function loadAllData(targetState?: CLIServerState): Promise<boolean> {
	const state = targetState ?? getServerState();
	debug('Loading data into memory...');

	try {
		// controlHelpers caches metadata per path. Reloads (and retries after a
		// failure) must not keep metadata from the previous generation.
		clearControlMetadataCache();

		// Load controls from individual files
		const controls = await state.fileStore.loadAllControls();

		// Load mappings from mappings files before touching any committed cache.
		const mappings = await state.fileStore.loadMappings();

		const controlsCache = new Map<string, Control>();
		const controlsByFamily = new Map<string, Set<string>>();
		for (const control of controls) {
			controlsCache.set(control.id, control);
			indexControl(control, controlsByFamily);
		}
		debug(`Loaded ${controls.length} controls from individual files`);

		const mappingsCache = new Map<string, Mapping>();
		const mappingsByFamily = new Map<string, Set<string>>();
		const mappingsByControl = new Map<string, Set<string>>();
		for (const mapping of mappings) {
			if (!mapping.hash) {
				mapping.hash = createHash('sha256').update(JSON.stringify(mapping)).digest('hex');
			}
			const compositeKey = `${mapping.control_id}:${mapping.hash}`;
			mappingsCache.set(compositeKey, mapping);
			indexMapping(mapping, mappingsByFamily, mappingsByControl);
		}
		debug(`Loaded ${mappings.length} mappings`);

		// The metadata file belongs to the same generation as the controls.
		// A malformed lula.yaml is scoped to the metadata and does not abort
		// loading the rest of the generation.
		const currentPath = resolveControlSetPath(state.CONTROL_SET_DIR, state.currentSubdir);
		const metadata = loadMetadataForPath(currentPath);

		// Commit the staged generation. Only after every read above succeeded
		// do we mutate the published caches.
		replaceMapContents(state.controlsCache, controlsCache);
		replaceMapContents(state.mappingsCache, mappingsCache);
		replaceMapContents(state.controlsByFamily, controlsByFamily);
		replaceMapContents(state.mappingsByFamily, mappingsByFamily);
		replaceMapContents(state.mappingsByControl, mappingsByControl);

		const previousGeneration = state.committedGeneration ?? state.generation ?? 0;
		state.generation = previousGeneration + 1;
		state.committedGeneration = state.generation;
		state.currentPath = currentPath;
		state.metadata = metadata;
		state.loadErrors = [];

		return true;
	} catch (error) {
		console.error('Error loading data:', error);
		return false;
	}
}

/**
 * Switch to another control set transactionally.
 *
 * The new state is built and loaded off to the side. It is published only if
 * the whole load succeeds; otherwise the previous committed generation (and
 * its currentPath) stays active, so a retry starts from a coherent snapshot.
 */
export async function switchServerState(
	controlSetDir: string,
	subdir: string = '.'
): Promise<boolean> {
	const sequence = ++switchSequence;
	const previousState = serverState;

	clearControlMetadataCache();

	let candidate: CLIServerState;
	try {
		candidate = createServerState(controlSetDir, subdir);
	} catch (error) {
		console.error('Error loading data:', error);
		return false;
	}

	const loaded = await loadAllData(candidate);
	if (!loaded) {
		// Leave the published generation untouched. Drop metadata cached for
		// the failed candidate so a retry re-reads it from disk.
		clearControlMetadataCache();
		if (previousState) {
			// Warm the cache back to the still-committed control set.
			warmControlMetadataCache(
				resolveControlSetPath(previousState.CONTROL_SET_DIR, previousState.currentSubdir)
			);
		}
		return false;
	}

	// A newer switch started while this candidate was loading. Never publish
	// an older generation over it.
	if (sequence !== switchSequence) {
		return false;
	}

	const previousGeneration = previousState?.committedGeneration ?? previousState?.generation ?? 0;
	candidate.generation = previousGeneration + 1;
	candidate.committedGeneration = candidate.generation;
	serverState = candidate;
	return true;
}

// Friendly aliases used by callers that phrase the operation as a plain switch.
export const switchControlSet = switchServerState;
export const switchToControlSet = switchServerState;

export async function saveMappingsToFile(): Promise<void> {
	const state = getServerState();
	try {
		const allMappings = Array.from(state.mappingsCache.values());
		await state.fileStore.saveMappings(allMappings);
		debug(`Saved ${allMappings.length} mappings`);
	} catch (error) {
		console.error('Error saving mappings:', error);
	}
}
