import { useCallback, useEffect, useRef, useState } from 'react';
import { publicDesktop } from './desktop-channel';
import { connectDesktop } from './desktop-transport';
import { ORIGIN, WEB_ORIGIN } from './sync';
import { CryptoClient, windowsVault } from './worker-client';
import { IdleClock } from './idle';
import { canUseHello, enrollHello, evaluateHello } from './hello';
import { HELLO_SYNC_RECONNECT, HELLO_SYNC_UNAVAILABLE, SYNC_HISTORY_CHANGED, VAULT_KEY_CHANGED, type AttachmentView, type HelloCredential } from './format';
import type { Calibration } from './calibration';
import { readPreference, writePreference, readTimeout } from './preferences';
import { VaultView, type Page } from './VaultView';
import type { ImportedItem, ImportSummary } from './bitwarden';
import { itemDraft, itemType, makeItem, type ItemDraft } from './item-editor';
import { recordTitle, type VaultRecord as Note } from './organization';
import type { HistoryAction, HistoryEntry } from './generator-history';
import { useWebUpdate } from './web-update';
import { validPalette } from './appearance';
import { copyToClipboard, readClipboardTimeout, windowsClipboard } from './clipboard';

type ImportPreview = ImportSummary & { newItems: number; newFolders: number; duplicates: number; changed: number };
type SourceVersion = { id: string; size: number; created: number };
type Status = {
  exists: boolean; pending: number; attachments: AttachmentView[]; remote: 'local' | 'new' | 'configured' | 'unavailable';
  rejectedServerData?: boolean; server?: string | null;
  hello?: HelloCredential; helloOnly?: boolean; helloSync?: boolean; helloSyncReconnect?: boolean; masterSession?: boolean;
  requiresRecoveryFile?: boolean; importAvailable?: boolean;
};
export function App() {
  const webUpdate = useWebUpdate();
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [syncPaused, setSyncPaused] = useState(false);
  const [syncRetry, setSyncRetry] = useState(false);
  const [rotationNeeded, setRotationNeeded] = useState(false);
  const [helloSetup, setHelloSetup] = useState(false);
  const [browserHelloToken, setBrowserHelloToken] = useState<string>();
  const [status, setStatus] = useState<Status>({ exists: false, pending: 0, attachments: [], remote: 'unavailable' });
  const [notes, setNotes] = useState<Note[]>([]);
  const [selected, setSelected] = useState(-1);
  const [newItem, setNewItem] = useState<ImportedItem>();
  const [draft, setDraft] = useState('');
  const [editor, setEditor] = useState<ItemDraft>(() => itemDraft());
  const [password, setPassword] = useState('');
  const [setup, setSetup] = useState('');
  const [recoveryFile, setRecoveryFile] = useState<File>();
  const [recoveryDownloaded, setRecoveryDownloaded] = useState(false);
  const [importFile, setImportFile] = useState<File>();
  const [importPassword, setImportPassword] = useState('');
  const [importPreview, setImportPreview] = useState<ImportPreview>();
  const [importProgress, setImportProgress] = useState<{ label: string; done?: number; total?: number }>();
  const importing = importProgress !== undefined;
  const [sourceVersions, setSourceVersions] = useState<SourceVersion[]>();
  const [recoveryVersions, setRecoveryVersions] = useState<SourceVersion[]>();
  const [sourcePassword, setSourcePassword] = useState('');
  const [sourceRecovery, setSourceRecovery] = useState<{ publicKey: string; recovery: string }>();
  const [calibration, setCalibration] = useState<Calibration>();
  const [page, setPage] = useState<Page>('vault');
  const [unlocked, setUnlocked] = useState(false);
  const [hidden, setHidden] = useState(document.hidden);
  const [timeout, setTimeoutMinutes] = useState(readTimeout);
  const [clipboardSeconds, setClipboardSeconds] = useState(readClipboardTimeout);
  const [theme, setTheme] = useState(() => readPreference('vault-theme', 'system'));
  const [palette, setPalette] = useState(() => validPalette(readPreference('vault-palette', 'vault')));
  const [online, setOnline] = useState(navigator.onLine);
  const [mobileDetail, setMobileDetail] = useState(false);
  const clock = useRef<IdleClock | null>(null);
  const client = useRef<CryptoClient | null>(null);
  const generation = useRef(0);
  const pendingBrowserHello = useRef<HelloCredential | undefined>(undefined);
  const previousOnline = useRef(online);
  const links = useRef<string[]>([]);
  if (!client.current) client.current = new CryptoClient(setNotice);
  const generatorHistory = useCallback((action: HistoryAction) =>
    client.current!.call<HistoryEntry[]>('generator-history', action), []);
  const currentItem = notes[selected];
  const dirty = unlocked && (!!newItem || (!!currentItem && (draft !== currentItem.text ||
    JSON.stringify(editor) !== JSON.stringify(itemDraft(currentItem.item, currentItem.text)))));
  const helloAvailable = canUseHello();
  const independentWeb = window.location.origin === WEB_ORIGIN;
  const canSync = status.remote === 'configured' && !status.helloOnly && !syncPaused && !rotationNeeded;
  const refresh = async () => {
    const current = generation.current;
    const next = await client.current!.call<Status>('status');
    if (current === generation.current) setStatus(next);
    return next;
  };
  const lock = (message = 'Vault locked.') => {
    generation.current++; client.current!.stop(); clock.current = null;
    pendingBrowserHello.current = undefined;
    setBrowserHelloToken(undefined);
    setHelloSetup(false);
    setSyncPaused(false);
    setSyncRetry(false);
    setRotationNeeded(false);
    setUnlocked(false); setNotes([]); setDraft(''); setPassword(''); setSetup(''); setRecoveryFile(undefined); setRecoveryDownloaded(false); setCalibration(undefined); setBusy(false); setError(''); setNotice(message);
    setEditor(itemDraft()); setSelected(-1); setNewItem(undefined); setMobileDetail(false);
    setStatus(prior => ({ ...prior, pending: 0, attachments: [], helloOnly: false, masterSession: false, helloSyncReconnect: false }));
    setImportFile(undefined); setImportPassword(''); setImportPreview(undefined); setImportProgress(undefined);
    setSourceVersions(undefined);
    setRecoveryVersions(undefined);
    setSourcePassword(''); setSourceRecovery(undefined);
    for (const url of links.current) URL.revokeObjectURL(url); links.current = [];
  };
  async function run(action: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(''); setNotice(''); const current = generation.current;
    try { await action(); } catch (e) {
      if (current === generation.current) {
        const message = e instanceof Error ? e.message : 'Operation failed. Your existing saved data is unchanged.';
        if (message === VAULT_KEY_CHANGED) setRotationNeeded(true);
        if (message === HELLO_SYNC_RECONNECT || message === VAULT_KEY_CHANGED) await refresh().catch(() => {});
        if (current === generation.current) setError(message);
      }
    } finally { if (current === generation.current) setBusy(false); }
  }
  useEffect(() => {
    if (!windowsClipboard()) return;
    const copySelection = (event: ClipboardEvent) => {
      if (event.defaultPrevented) return;
      const focused = document.activeElement;
      if (focused instanceof HTMLInputElement && focused.type === 'password') return;
      const field = focused instanceof HTMLInputElement || focused instanceof HTMLTextAreaElement ? focused : undefined;
      const start = field?.selectionStart ?? 0, end = field?.selectionEnd ?? 0;
      const original = field?.value;
      const cut = event.type === 'cut';
      if (cut && (!field || field.readOnly)) return;
      const value = field ? field.value.slice(start, end) : document.getSelection()?.toString();
      if (!value) return;
      event.preventDefault();
      const current = generation.current;
      void copyToClipboard(value, clipboardSeconds).then(() => {
        if (!cut || !field || generation.current !== current || document.activeElement !== field
          || field.value !== original || field.selectionStart !== start || field.selectionEnd !== end) return;
        field.setRangeText('', start, end, 'end');
        field.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'deleteByCut' }));
      }).catch(() => {
        if (generation.current === current) setError('Could not copy to the Windows clipboard.');
      });
    };
    document.addEventListener('copy', copySelection);
    document.addEventListener('cut', copySelection);
    return () => {
      document.removeEventListener('copy', copySelection);
      document.removeEventListener('cut', copySelection);
    };
  }, [clipboardSeconds]);
  function showNotes(result: Note[], objectId?: string) {
    const currentId = notes[selected]?.revision.context.revisionId;
    const exact = result.findIndex(note => note.revision.context.objectId === objectId && note.revision.context.revisionId === currentId);
    const index = exact >= 0 ? exact : result.findIndex(note => !note.folderEntry && note.revision.context.objectId === objectId);
    const chosen = result[index];
    setNotes(result); setSelected(index); setDraft(chosen?.text ?? ''); setEditor(itemDraft(chosen?.item, chosen?.text));
  }
  useEffect(() => {
    let active = true;
    const start = async () => {
      const session = await client.current!.call<{ notes: Note[]; lastInteraction: number; page: Page; objectId?: string } | undefined>('session-resume');
      if (!active) return;
      if (session) {
        const resumed = new IdleClock(timeout * 60_000, session.lastInteraction);
        if (!resumed.expired()) {
          clock.current = resumed;
          showNotes(session.notes, session.objectId);
          setMobileDetail(!!session.objectId);
          setPage(session.page === 'device' || session.page === 'attachments' ? session.page : 'vault');
          setUnlocked(true); setPassword('');
        }
      }
      const currentStatus = await refresh();
      if (active && currentStatus.remote === 'unavailable' && !independentWeb && !publicDesktop) setError('Vault server unavailable. Reload when connected.');
    };
    start().catch(() => { if (active) setError('Local encrypted storage is unavailable.'); });
    return () => { active = false; client.current?.disconnect(); };
  }, []);
  useEffect(() => {
    if (unlocked) void client.current!.call('session-view', { page, objectId: currentItem?.revision.context.objectId }).catch(() => {});
  }, [unlocked, page, currentItem?.revision.context.objectId]);
  useEffect(() => {
    const system = window.matchMedia('(prefers-color-scheme: dark)');
    const apply = () => {
      const root = document.documentElement;
      root.dataset.theme = theme === 'system' ? (system.matches ? 'dark' : 'light') : theme;
      if (palette === 'vault') delete root.dataset.skin;
      else root.dataset.skin = palette;
      document.querySelector('meta[name="theme-color"]')?.setAttribute('content',
        getComputedStyle(root).getPropertyValue('--bg').trim());
    };
    apply();
    system.addEventListener('change', apply);
    writePreference('vault-theme', theme);
    writePreference('vault-palette', palette);
    return () => system.removeEventListener('change', apply);
  }, [theme, palette]);
  useEffect(() => {
    const changed = (event: StorageEvent) => {
      if (event.key !== 'vault-idle-minutes' && event.key !== null) return;
      const next = readTimeout();
      if (next === timeout) return;
      setTimeoutMinutes(next);
      if (clock.current) lock('Vault locked because the lock timeout changed.');
    };
    window.addEventListener('storage', changed);
    return () => window.removeEventListener('storage', changed);
  }, [timeout]);
  useEffect(() => {
    const tick = () => { if (clock.current?.expired()) lock('Locked after inactivity.'); };
    const interaction = (event: Event) => {
      if (!event.isTrusted || document.hidden || !clock.current) return;
      if (!clock.current.interact()) lock('Locked after inactivity.');
      else void client.current!.call('session-touch').catch(() => {});
    };
    const visibility = () => { tick(); setHidden(document.hidden); };
    const net = () => setOnline(navigator.onLine);
    const fatalEvent = (event: Event) => lock((event as CustomEvent<string>).detail);
    const noticeEvent = (event: Event) => setError((event as CustomEvent<string>).detail);
    const interval = window.setInterval(tick, 1000);
    document.addEventListener('visibilitychange', visibility); window.addEventListener('pageshow', tick);
    document.addEventListener('pointerdown', interaction, true); document.addEventListener('keydown', interaction, true);
    window.addEventListener('online', net); window.addEventListener('offline', net); window.addEventListener('vault-status', noticeEvent); window.addEventListener('vault-fatal', fatalEvent);
    return () => {
      clearInterval(interval); document.removeEventListener('visibilitychange', visibility); window.removeEventListener('pageshow', tick);
      document.removeEventListener('pointerdown', interaction, true); document.removeEventListener('keydown', interaction, true);
      window.removeEventListener('online', net); window.removeEventListener('offline', net); window.removeEventListener('vault-status', noticeEvent); window.removeEventListener('vault-fatal', fatalEvent);
    };
  }, []);
  useEffect(() => {
    const beforeUnload = (e: BeforeUnloadEvent) => { if (dirty || importing) { e.preventDefault(); e.returnValue = ''; } };
    const lockInTray = () => lock(dirty ? 'Vault locked. Unsaved changes were discarded.' : 'Vault locked.');
    window.addEventListener('beforeunload', beforeUnload);
    window.addEventListener('vault-tray-hide', lockInTray);
    return () => {
      window.removeEventListener('beforeunload', beforeUnload);
      window.removeEventListener('vault-tray-hide', lockInTray);
    };
  }, [dirty, importing]);
  useEffect(() => {
    const reconnected = online && !previousOnline.current;
    previousOnline.current = online;
    if (reconnected && unlocked && !busy && !dirty && canSync) void run(() => syncNow());
  }, [online, unlocked, busy, dirty, canSync]);
  useEffect(() => {
    if (!syncRetry || !canSync || !unlocked || !online || hidden || busy || dirty) return;
    const retry = window.setTimeout(() => void run(() => syncNow()), 15_000);
    return () => window.clearTimeout(retry);
  }, [syncRetry, canSync, unlocked, online, hidden, busy, dirty]);
  const changePage = (next: Page) => {
    if (page === 'vault' && next !== 'vault' && !unlocked) setRecoveryFile(undefined);
    setPage(next);
    setMobileDetail(false);
  };
  async function doUnlock(hello?: HelloCredential) {
    const current = generation.current;
    const idleMs = timeout * 60_000;
    let result: Note[];
    if (hello) {
      setNotice('Waiting for Windows Hello…');
      const secret = await helloSecret(hello);
      try {
        if (current !== generation.current) return;
        result = await client.current!.call<Note[]>('hello-unlock', { id: hello.id, secret, idleMs });
      } finally { secret.fill(0); }
    } else {
      result = await client.current!.call<Note[]>(status.exists ? 'unlock' : 'create', { password, setup, recoveryFile, idleMs });
    }
    if (current !== generation.current) return;
    const next = await refresh();
    if (current !== generation.current) return;
    showNotes(result); setUnlocked(true); setPassword(''); setSetup(''); setRecoveryFile(undefined); setRecoveryDownloaded(false); clock.current = new IdleClock(idleMs);
    setNotice(hello && next.helloOnly && !windowsVault() ? 'To sync, unlock with your master password.' : '');
    if (online && next.remote === 'configured' && !next.helloOnly) await syncNow();
  }
  async function syncNow(objectId = notes[selected]?.revision.context.objectId, resumeAfterRestore = false, reportSuccess = false, importing = false) {
    const current = generation.current;
    try {
      const result = await client.current!.call<{
        notes: Note[]; unavailable: number; quotaDeferred: number; deferredFiles: number; deferredRevisions: number;
      }>('sync', { resumeAfterRestore, importProgress: importing }, importing ? (done, total) => {
        if (current !== generation.current) return;
        setImportProgress(done < total ? { label: 'Syncing with the vault…', done, total }
          : { label: 'Finishing sync…' });
      } : undefined);
      if (current !== generation.current) return;
      setSyncPaused(false);
      setSyncRetry(false);
      showNotes(result.notes, objectId); await refresh();
      if (current !== generation.current) return;
      const warnings = [];
      if (result.deferredRevisions) warnings.push(`${result.deferredRevisions} ${result.deferredRevisions === 1 ? 'edit remains' : 'edits remain'} on this device pending sync.`);
      if (result.deferredFiles) warnings.push(`${result.deferredFiles} ${result.deferredFiles === 1 ? 'file could' : 'files could'} not sync. Check the local copies and retry.`);
      if (result.quotaDeferred) warnings.push('The server is out of room for some attachments. Those files are still saved on this device.');
      if (warnings.length) {
        if (importing && result.deferredRevisions) throw Error('Some imported items still need to sync.');
        if (result.unavailable) warnings.push('Some files are unavailable.');
        setError(warnings.join(' '));
      } else if (resumeAfterRestore) {
        setNotice(result.unavailable ? 'Sync resumed. Some files are missing from the server and this device.' : 'Sync resumed.');
      } else if (reportSuccess) {
        setNotice(result.unavailable ? 'Vault synced. Some files are unavailable.' : 'Vault synced.');
      }
    } catch (error) {
      if (current === generation.current) setSyncRetry(windowsVault() &&
        error instanceof Error && (error.message === HELLO_SYNC_UNAVAILABLE || error instanceof TypeError || error.name === 'TimeoutError'));
      if (current === generation.current && error instanceof Error && error.message === SYNC_HISTORY_CHANGED) setSyncPaused(true);
      if (current === generation.current && error instanceof Error && error.message === VAULT_KEY_CHANGED) setRotationNeeded(true);
      throw error;
    }
  }
  async function save(resolve = false) {
    const current = generation.current;
    if (newItem) {
      const result = await client.current!.call<{ notes: Note[]; objectId: string }>('new-note', {
        itemType: itemType(newItem), text: draft, editor, item: newItem,
      });
      if (current !== generation.current) return;
      setNewItem(undefined);
      showNotes(result.notes, result.objectId); await refresh();
      if (current === generation.current && online && canSync) await syncNow(result.objectId);
      return;
    }
    const revision = notes[selected].revision, objectId = revision.context.objectId;
    const parents = resolve ? notes.filter(n => n.revision.context.objectId === objectId).map(n => n.revision.context.revisionId) : undefined;
    const result = await client.current!.call<{ status: string; notes: Note[] }>('save', { text: draft, editor, revision, resolve: parents });
    if (current !== generation.current) return;
    showNotes(result.notes, objectId); await refresh();
    if (current !== generation.current) return;
    if (result.status === 'conflict') setNotice('Both versions preserved.');
    if (online && canSync) await syncNow(objectId);
  }
  async function checkStorage(request = false) {
    if (!navigator.storage?.estimate) throw Error('This browser does not expose storage estimates');
    const persistent = request ? await navigator.storage.persist() : await navigator.storage.persisted();
    const estimate = await navigator.storage.estimate();
    setNotice(`${((estimate.usage ?? 0) / 1e6).toFixed(1)} MB used · ${((estimate.quota ?? 0) / 1e9).toFixed(1)} GB quota · ${persistent ? 'Persistent storage enabled.' : 'The browser may clear offline files.'}`);
  }
  async function calibrateDevice() {
    const current = generation.current;
    setNotice('Measuring unlock time…');
    const c = await client.current!.call<Calibration>('calibrate');
    if (current !== generation.current) return;
    setCalibration(c); setNotice(c.targetReached ? `Unlock time measured at ${(c.measuredMs / 1000).toFixed(1)} seconds.` : 'Target missed. Measure again.');
  }
  async function helloSecret(credential: HelloCredential) {
    try { return await evaluateHello(credential); }
    catch (error) {
      if (error instanceof DOMException) throw Error('Windows Hello did not complete. Try again or use your master password.');
      if (typeof error === 'string') throw Error(error);
      throw error;
    }
  }
  async function enableHello(masterPassword: string) {
    const current = generation.current;
    setHelloSetup(true);
    try { await finishHelloSetup(masterPassword); }
    catch (error) {
      if (current === generation.current) await client.current!.call('hello-cancel').catch(() => {});
      throw error;
    }
    finally { if (current === generation.current) setHelloSetup(false); }
  }
  async function finishHelloSetup(masterPassword: string) {
    const current = generation.current;
    setNotice('Checking your master password…');
    const token = await client.current!.call<string>('hello-confirm', { password: masterPassword });
    if (current !== generation.current) return;
    if (!pendingBrowserHello.current) setNotice('Choose Windows Hello on this PC.');
    let enrollment: Awaited<ReturnType<typeof enrollHello>>;
    try { enrollment = pendingBrowserHello.current ? { credential: pendingBrowserHello.current } : await enrollHello(); }
    catch (error) {
      if (error instanceof DOMException) {
        if (/not focused|lost focus/i.test(error.message)) {
          throw Error('Chrome lost focus during setup. Keep the Voltura tab selected until Windows Hello finishes.');
        }
        throw Error('Chrome could not finish saving the passkey (' + error.name + ').');
      }
      if (typeof error === 'string') throw Error(error);
      throw error;
    }
    const { credential, secret } = enrollment;
    if (current !== generation.current) { secret?.fill(0); return; }
    if (secret) {
      await saveHelloSetup(credential, token, secret);
      return;
    }
    if (independentWeb) {
      pendingBrowserHello.current = credential;
      setBrowserHelloToken(token);
      setNotice('');
      return;
    }
    await verifyHelloSetup(credential, token);
  }
  async function confirmBrowserHello() {
    const credential = pendingBrowserHello.current;
    if (!credential || !browserHelloToken) return;
    const current = generation.current;
    setHelloSetup(true);
    try { await verifyHelloSetup(credential, browserHelloToken); }
    finally { if (current === generation.current) setHelloSetup(false); }
  }
  async function verifyHelloSetup(credential: HelloCredential, token: string) {
    const current = generation.current;
    setNotice('Step 2 of 2. Confirm with Windows Hello again to finish setup.');
    const secret = await helloSecret(credential);
    if (current !== generation.current) { secret.fill(0); return; }
    await saveHelloSetup(credential, token, secret);
  }
  async function saveHelloSetup(credential: HelloCredential, token: string, secret: Uint8Array) {
    const current = generation.current;
    try {
      setBrowserHelloToken(undefined);
      await client.current!.call('hello-enroll', { credential, secret, token });
      if (current === generation.current) pendingBrowserHello.current = undefined;
      const next = await refresh();
      if (current !== generation.current) return;
      const withSync = windowsVault() && next.remote === 'configured';
      if (next.hello?.id !== credential.id || (withSync && !next.helloSync)) throw Error('Windows Hello setup was not saved. Try again.');
      setNotice('Windows Hello enabled.');
    } finally { secret.fill(0); }
  }
  async function reconnectHelloSync(masterPassword: string) {
    const credential = status.hello;
    if (!credential || !online || dirty) return;
    const current = generation.current;
    setHelloSetup(true);
    try {
      setNotice('Confirm with Windows Hello…');
      const secret = await helloSecret(credential);
      try {
        if (current !== generation.current) return;
        await client.current!.call('hello-sync-reconnect', { id: credential.id, secret, password: masterPassword });
      } finally { secret.fill(0); }
      if (current !== generation.current) return;
      await refresh();
      if (current !== generation.current) return;
      setNotice('Sync reconnected.');
      if (!syncPaused) await syncNow(undefined, false, true);
    } finally { if (current === generation.current) setHelloSetup(false); }
  }
  async function generateAttachment(file: File, recordId?: string) {
    const current = generation.current;
    await client.current!.call('attachment-create', { file, recordId }); await refresh();
    if (current !== generation.current) return;
    setNotice('File encrypted and saved on this device.');
    if (online && canSync) await syncNow();
  }
  async function previewImport() {
    const current = generation.current;
    setImportPreview(undefined);
    const pending = client.current!.call<ImportPreview>('import-preview', { file: importFile, password: importPassword });
    setImportPassword('');
    const result = await pending;
    if (current === generation.current) setImportPreview(result);
  }
  async function commitImport() {
    const current = generation.current;
    setImportProgress({ label: 'Checking the vault…' });
    try {
      const result = await client.current!.call<{ added: number; skipped: number; foldersAdded: number; notes: Note[] }>(
        'import-commit', {}, (done, total) => {
          if (current === generation.current) setImportProgress({ label: 'Saving items and folders…', done, total });
        });
      if (current !== generation.current) return;
      const skipped = result.skipped + (importPreview?.duplicates ?? 0);
      const summary = `Imported ${result.added} items and ${result.foldersAdded} folders. ${skipped} items already existed.`;
      setImportPreview(undefined); setImportFile(undefined); showNotes(result.notes);
      setImportProgress({ label: 'Syncing with the vault…' });
      try {
        await refresh();
        if (current !== generation.current) return;
        if (canSync) await syncNow(undefined, false, false, true);
        else throw Error('Sync is unavailable.');
        if (current === generation.current) setNotice(summary);
      } catch {
        if (current === generation.current) setError(`${summary} Some changes may still be on this device only. Use Sync now to retry.`);
      }
    } finally {
      if (current === generation.current) setImportProgress(undefined);
    }
  }
  async function readFile(id: string, download: boolean, keep = false) {
    const current = generation.current;
    setNotice(keep ? 'Saving encrypted file for offline use…' : download ? 'Preparing download…' : 'Verifying file…');
    const result = await client.current!.call<{ blob?: Blob; name: string; verifiedBytes: number }>('attachment-read', { id, download, keep });
    if (current !== generation.current) return;
    if (download && result.blob) {
      const url = URL.createObjectURL(result.blob); links.current.push(url);
      const link = document.createElement('a'); link.href = url; link.download = result.name; link.click();
      setNotice('');
    } else if (keep) { await refresh(); if (current === generation.current) setNotice('Encrypted file available offline.'); }
    else setNotice(`${result.verifiedBytes.toLocaleString()} bytes verified.`);
  }
  return <VaultView model={{ page, unlocked, hidden, busy, notice, error, status, syncPaused, rotationNeeded, notes, selected, newItem, draft, editor, dirty, password, setup, recoveryFile, recoveryDownloaded, calibration, online, mobileDetail, theme, palette, timeout, clipboardSeconds, privateClipboard: windowsClipboard(), helloAvailable, windowsVault: windowsVault(), helloSetup, browserHelloPending: !!browserHelloToken, importFile, importPassword, importPreview, importProgress, sourceVersions, recoveryVersions, sourcePassword, sourceRecovery: !!sourceRecovery, webUpdate, independentWeb, publicDesktop }} actions={{
    navigate: changePage,
    lock: () => lock(dirty ? 'Locked. Unsaved changes discarded; your last saved version is retained.' : undefined),
    unlock: () => void run(doUnlock), setPassword, setSetup, setRecoveryFile,
    downloadRecoveryKey: () => void run(async () => {
      const current = generation.current;
      setRecoveryFile(undefined);
      setRecoveryDownloaded(false);
      const blob = await client.current!.call<Blob>('make-recovery-file');
      if (current !== generation.current) return;
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'voltura-vault-recovery.vvrk';
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 30_000);
      setRecoveryDownloaded(true);
    }),
    calibrate: () => void run(calibrateDevice),
    checkPairing: () => void run(async () => {
      if (!publicDesktop || dirty) throw Error('Save or discard the open edit before checking.');
      await client.current!.call('check-pending-pairing');
      setNotice('No pending changes. Pair the other server in a fresh OS profile. This vault stays here.');
    }),
    connectDesktop: (url, certificate) => void run(async () => {
      try {
        await connectDesktop(url, certificate);
      } catch (error) {
        throw Error(typeof error === 'string' ? error : error instanceof Error ? error.message : 'Vault connection failed.');
      }
      setPassword(''); setSetup(''); setRecoveryFile(undefined); setRecoveryDownloaded(false);
      if ((await refresh()).remote === 'unavailable') throw Error('The server did not provide a usable Vault configuration.');
    }),
    connect: () => void run(async () => {
      if (!independentWeb) return;
      const message = 'Could not reach the vault. Check WireGuard and allow local network access for this site if your browser asks.';
      // Request access from the page: a background worker cannot show Chrome’s permission prompt.
      const response = await fetch(ORIGIN + '/api/v1/config', {
        credentials: 'omit', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(20_000),
      }).catch(() => { throw Error(message); });
      if ((!response.ok && response.status !== 404) || (await refresh()).remote === 'unavailable') throw Error(message);
    }),
    select: index => { setNewItem(undefined); setSelected(index); setDraft(notes[index]?.text ?? ''); setEditor(itemDraft(notes[index]?.item, notes[index]?.text)); setMobileDetail(index >= 0); },
    setDraft, setEditor, save: () => void run(() => save()), resolve: () => void run(() => save(true)),
    generatorHistory,
    recoverRotation: (password, recoveryFile) => void run(async () => {
      const current = generation.current;
      const result = await client.current!.call<{ rejectedServerData: boolean }>('recover-rotation',
        { password, recoveryFile, idleMs: timeout * 60_000 });
      if (current !== generation.current) return;
      setRotationNeeded(false); setSyncPaused(false); setImportPreview(undefined); setImportFile(undefined); setImportPassword('');
      showNotes([]); setNewItem(undefined); await refresh();
      try { await syncNow(); }
      catch (error) { if (current === generation.current) setNotice('Device recovered. Saved changes will sync when the server is available.'); throw error; }
      if (current === generation.current) setNotice(result.rejectedServerData
        ? 'Device recovered. Some server changes failed verification.' : 'Device recovered and synced.');
    }),
    sync: () => {
      if (syncPaused && !window.confirm('Resume sync with the restored server? This sends saved local changes and available offline files to the server.')) return;
      void run(() => syncNow(undefined, syncPaused, true));
    },
    newNote: (type, folder) => {
      const item = { ...makeItem(type), name: '', folder: folder ?? '' };
      setSelected(-1); setNewItem(item); setEditor(itemDraft(item)); setDraft(''); setMobileDetail(true);
    },
    clone: index => {
      const source = notes[index];
      if (!source || source.trashed || source.folderEntry) return;
      const original = source.item ?? makeItem(2);
      const { id, attachments, passwordHistory, ...values } = original.source;
      const item = { ...original, source: values };
      const editor = itemDraft(source.item, source.text);
      editor.name = recordTitle(source);
      setSelected(-1); setNewItem(item); setEditor(editor); setDraft(source.text); setMobileDetail(true);
    },
    saveFolder: async (name, key, remove) => {
      let saved = false;
      await run(async () => {
        const current = generation.current;
        const result = await client.current!.call<Note[]>(remove ? 'folder-delete' : 'folder-save', { name, key });
        if (current !== generation.current) return;
        saved = true;
        showNotes(result, currentItem?.revision.context.objectId); await refresh();
        if (current === generation.current && online && canSync) await syncNow();
      });
      return saved;
    },
    setTrashed: (index, trashed) => void run(async () => {
      const current = generation.current, target = notes[index];
      const result = await client.current!.call<{ status: string; notes: Note[] }>(trashed ? 'trash-item' : 'restore-item',
        { revisionId: target.revision.context.revisionId });
      if (current !== generation.current) return;
      const keep = currentItem?.revision.context.objectId !== target.revision.context.objectId ? currentItem?.revision.context.objectId : undefined;
      showNotes(result.notes, keep);
      if (!keep) setMobileDetail(false);
      await refresh();
      if (current === generation.current && online && canSync) await syncNow(keep ?? '');
      if (current === generation.current) setNotice(result.status === 'conflict' ? 'Both versions preserved.' : trashed ? 'Moved to Trash.' : 'Item restored.');
    }),
    setTheme, setPalette, setTimeout: (value) => {
      writePreference('vault-idle-minutes', String(value));
      setTimeoutMinutes(value);
    },
    unlockHello: () => { if (helloAvailable && status.hello) void run(() => doUnlock(status.hello)); },
    enableHello: password => void run(() => enableHello(password)),
    reconnectHelloSync: password => void run(() => reconnectHelloSync(password)),
    confirmBrowserHello: () => void run(confirmBrowserHello),
    disableHello: () => void run(async () => {
      await client.current!.call('hello-disable');
      await refresh();
      setNotice('Windows Hello is turned off on this device.');
    }),
    checkStorage: persist => void run(() => checkStorage(persist)),
    generate: (file, recordId) => void run(() => generateAttachment(file, recordId)), read: (id, download, keep) => void run(() => readFile(id, download, keep)),
    deleteFile: id => void run(async () => {
      const current = generation.current;
      if (status.remote === 'configured' && !online) throw Error('Connect to the vault before deleting files.');
      await client.current!.call('attachment-delete', { id });
      await refresh();
      if (current === generation.current) setNotice('File deleted.');
    }),
    importFile: file => { setImportFile(file); setImportPreview(undefined); },
    importPassword: setImportPassword, previewImport: () => void run(previewImport), commitImport: () => void run(commitImport),
    setClipboardSeconds: seconds => {
      writePreference('vault-clipboard-seconds', String(seconds));
      setClipboardSeconds(seconds);
    },
    copy: value => void run(async () => { await copyToClipboard(value, clipboardSeconds); setNotice('Copied.'); }),
    setSourcePassword,
    enrollSource: () => void run(async () => {
      const current = generation.current;
      const pending = client.current!.call<{ publicKey: string; recovery: string }>('source-enroll', { password: sourcePassword });
      setSourcePassword('');
      const result = await pending;
      if (current !== generation.current) return;
      setSourceRecovery(result); await refresh();
      if (current === generation.current && online) await syncNow();
      if (current === generation.current) setNotice('Source keys are ready to save.');
    }),
    saveSourceKey: publicOnly => {
      if (!sourceRecovery) return;
      const blob = new Blob([publicOnly ? sourceRecovery.publicKey + '\n' : sourceRecovery.recovery], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob); links.current.push(url);
      const link = document.createElement('a'); link.href = url;
      link.download = publicOnly ? 'voltura-source.pub' : 'voltura-source-recovery.json'; link.click();
    },
    listSources: recovery => void run(async () => {
      const current = generation.current, result = await client.current!.call<SourceVersion[]>('source-list', { recovery });
      if (current === generation.current) (recovery ? setRecoveryVersions : setSourceVersions)(result);
    }),
    downloadSource: (id, size, recovery) => void run(async () => {
      const current = generation.current, blob = await client.current!.call<Blob>('source-download', { id, size, recovery });
      if (current !== generation.current) return;
      const url = URL.createObjectURL(blob); links.current.push(url);
      const link = document.createElement('a'); link.href = url;
      link.download = recovery ? `voltura-recovery-${id}.vvkr` : `voltura-source-${id}.vvsa`; link.click();
      setNotice(recovery ? 'Encrypted recovery kit downloaded.' : 'Encrypted source version downloaded.');
    }),
  }}/>;
}
