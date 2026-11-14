import { useId, useLayoutEffect, useRef, useState } from 'react';
import { Icon, itemIcons, type IconName } from './Icon';
import { Toast } from './Toast';
import { PALETTES } from './appearance';
import { Popup, ThemedSelect, type SelectOption } from './Popup';
import { VaultList } from './VaultList';
import { ItemFields } from './ItemFields';
import { GeneratorDialog } from './GeneratorDialog';
import { itemDraft, itemType, ITEM_TYPES, type ItemDraft, type ItemType } from './item-editor';
import { readPreference, TIMEOUTS, writePreference } from './preferences';
import type { AttachmentView, HelloCredential } from './format';
import type { Calibration } from './calibration';
import type { ImportedItem, ImportSummary } from './bitwarden';
import { recordTitle, vaultFolders, type VaultRecord } from './organization';
import type { HistoryAction, HistoryEntry } from './generator-history';
import { buildVersion, type useWebUpdate } from './web-update';
import { CLIPBOARD_TIMEOUTS } from './clipboard';

const testBuild = !import.meta.env.VITE_VAULT_PRODUCTION_RELEASE;

export type Page = 'vault' | 'device' | 'attachments';
export type Model = {
  page: Page; unlocked: boolean; hidden: boolean; busy: boolean; notice: string; error: string; syncPaused: boolean; rotationNeeded: boolean;
  status: { exists: boolean; pending: number; attachments: AttachmentView[]; remote: 'local' | 'new' | 'configured' | 'unavailable'; hello?: HelloCredential; helloOnly?: boolean; helloSyncReconnect?: boolean; masterSession?: boolean; server?: string | null; requiresRecoveryFile?: boolean; importAvailable?: boolean; rejectedServerData?: boolean };
  notes: VaultRecord[]; selected: number; newItem?: ImportedItem; draft: string; dirty: boolean;
  editor: ItemDraft;
  password: string; setup: string; recoveryFile?: File; recoveryDownloaded: boolean; calibration?: Calibration; online: boolean; mobileDetail: boolean;
  theme: string; palette: string; timeout: number; clipboardSeconds: number; privateClipboard: boolean; helloAvailable: boolean; windowsVault: boolean; helloSetup: boolean; browserHelloPending: boolean;
  importFile?: File; importPassword: string; importPreview?: ImportSummary & { newItems: number; newFolders: number; duplicates: number; changed: number };
  importProgress?: { label: string; done?: number; total?: number };
  sourceVersions?: { id: string; size: number; created: number }[];
  recoveryVersions?: { id: string; size: number; created: number }[];
  sourcePassword: string; sourceRecovery: boolean;
  webUpdate: ReturnType<typeof useWebUpdate>;
  independentWeb: boolean; publicDesktop: boolean;
};
export type Actions = {
  navigate: (page: Page) => void; lock: () => void; unlock: () => void;
  connect: () => void;
  checkPairing: () => void;
  connectDesktop: (url: string, certificate?: File) => void;
  setPassword: (value: string) => void; calibrate: () => void; select: (index: number) => void;
  setSetup: (value: string) => void; setRecoveryFile: (file?: File) => void; downloadRecoveryKey: () => void; sync: () => void; newNote: (type: ItemType, folder?: string) => void; clone: (index: number) => void; resolve: () => void;
  saveFolder: (name: string, key?: string, remove?: boolean) => Promise<boolean>; setTrashed: (index: number, trashed: boolean) => void;
  setDraft: (value: string) => void; setEditor: (value: ItemDraft) => void; save: () => void;
  generatorHistory: (action: HistoryAction) => Promise<HistoryEntry[]>;
  setTheme: (value: string) => void; setPalette: (value: string) => void; setTimeout: (value: number) => void;
  setClipboardSeconds: (value: number) => void;
  unlockHello: () => void; enableHello: (password: string) => void; reconnectHelloSync: (password: string) => void; disableHello: () => void;
  confirmBrowserHello: () => void;
  checkStorage: (persist: boolean) => void;
  recoverRotation: (password: string, recoveryFile: File) => void;
  generate: (file: File, recordId?: string) => void; read: (id: string, download: boolean, keep?: boolean) => void;
  deleteFile: (id: string) => void;
  importFile: (file?: File) => void; importPassword: (value: string) => void;
  previewImport: () => void; commitImport: () => void; copy: (value: string) => void;
  listSources: (recovery?: boolean) => void; downloadSource: (id: string, size: number, recovery?: boolean) => void;
  setSourcePassword: (value: string) => void; enrollSource: () => void; saveSourceKey: (publicOnly: boolean) => void;
};

function ImportedFields({ item, copy }: { item: ImportedItem; copy: (value: string) => void }) {
  const payload = item.source;
  const fields: [string, unknown][] = [['Password history', payload.passwordHistory], ['Attachment references', payload.attachments]];
  return <>
    {fields.filter(([, value]) => value !== null && value !== undefined && value !== '').map(([label, value]) => {
      const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
      return <details key={label}><summary>{label}</summary><pre className="imported-field-value">{text}</pre>
        <button onClick={() => copy(text)}>Copy</button></details>;
    })}
  </>;
}

function AttachmentList({ files, model: m, actions: a }: {
  files: AttachmentView[]; model: Model; actions: Actions;
}) {
  const [deleting, setDeleting] = useState<{ id: string; name: string }>();
  return <>{files.length === 0 ? <div className="empty"><Icon name="file"/><h3>No files yet</h3></div> : <div className="file-list">{files.map((file, index) => {
              const onDemand = file.offline === false;
              const missing = onDemand && file.remote === false;
              const unavailable = m.busy || (onDemand && (missing || !m.online || m.status.helloOnly));
              const id = file.context.objectId;
              const name = file.displayName ?? `File ${index + 1}`;
              return <div className="attachment-row" key={id}><span className="item-icon"><Icon name="file"/></span><div className="file-name"><strong>{name}</strong><small>{file.size < 1e6 ? `${file.size.toLocaleString()} bytes` : `${(file.size / 1e6).toFixed(1)} MB`}{missing ? ' · Missing from restored server' : onDemand ? ' · Download on open' : file.remote ? ' · Synced' : ''}</small></div>
                {!onDemand && <span className="offline-available"><Icon name="check"/>Available offline</span>}
                <button className="icon-button" aria-label={`Download file ${index + 1}`} disabled={unavailable} onClick={() => a.read(id, true)}><Icon name="download"/></button>
                <Popup label={`Actions for ${name}`} className="icon-button row-action" trigger={<Icon name="more"/>} showLabel={false} disabled={m.busy}
                  choices={[
                    ...(!unavailable ? [
                      ...(onDemand ? [{ label: 'Keep offline', icon: 'download' as const, action: () => a.read(id, false, true) }] : []),
                      { label: 'Verify', icon: 'check' as const, action: () => a.read(id, false) },
                    ] : []),
                    { label: 'Delete file', icon: 'trash', danger: true, divider: !unavailable, action: () => setDeleting({ id, name }) },
                  ]}/>
              </div>;
            })}</div>}
    {deleting && <ConfirmItemAction title="Delete file" cancelLabel="Cancel"
      description={`Delete “${deleting.name}” from the vault? This can’t be undone in the app.`}
      cancel={() => setDeleting(undefined)} action={() => { setDeleting(undefined); a.deleteFile(deleting.id); }}/>}
  </>;
}

function RecordAttachments({ record, model, actions, close }: {
  record: VaultRecord; model: Model; actions: Actions; close: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const title = useId();
  const recordId = record.revision.context.objectId;
  const files = model.status.attachments.filter(file => file.recordId === recordId);
  useLayoutEffect(() => { dialog.current?.showModal(); }, []);
  return <dialog ref={dialog} className="folder-dialog" aria-labelledby={title} onCancel={event => {
    event.preventDefault(); if (!model.busy) close();
  }}>
    <div className="folder-dialog-heading"><h2 id={title}>Attachments</h2>
      <button className="icon-button" aria-label="Close attachments" disabled={model.busy} onClick={close}><Icon name="close"/></button>
    </div>
    <p>{recordTitle(record)}</p>
    <label>Add attachment <input type="file" disabled={model.busy} onChange={event => {
      const file = event.target.files?.[0];
      event.target.value = '';
      if (file) actions.generate(file, recordId);
    }}/></label>
    <AttachmentList files={files} model={model} actions={actions}/>
  </dialog>;
}

const itemTypes = ([1, 3, 4, 2, 5, 6, 7, 8] as const).map(type => ({ type, label: ITEM_TYPES[type], icon: itemIcons[type] }));
const filterLabels = { 1: 'Logins', 2: 'Secure notes', 3: 'Cards', 4: 'Identities', 5: 'SSH keys',
  6: 'Bank accounts', 7: 'Driver’s licenses', 8: 'Passports' };
const baseFilters: { value: string; label: string; icon: IconName }[] = [
  { value: 'all', label: 'All items', icon: 'vault' }, { value: 'favorites', label: 'Favorites', icon: 'star' },
  ...itemTypes.map(({ type, icon }) => ({ value: `type:${type}`, label: filterLabels[type], icon })),
  { value: 'trash', label: 'Trash', icon: 'trash' },
];

export function VaultView(props: { model: Model; actions: Actions }) {
  return <VaultSurface key={String(props.model.unlocked)} {...props}/>;
}

function HelloSetupFields({ busy, enable, label = 'Enable Windows Hello', hint = 'Save the passkey to this Windows device when prompted.' }: {
  busy: boolean; enable: Actions['enableHello']; label?: string; hint?: string;
}) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  function confirm() {
    const field = input.current;
    if (busy || !field || !field.reportValidity()) return;
    const password = field.value;
    field.value = '';
    enable(password);
  }
  return <div>
    {hint && <p className="fine">{hint}</p>}
    <label htmlFor={id}>Confirm master password</label>
    <input ref={input} id={id} type="password" autoComplete="off" required maxLength={1024} disabled={busy}
      onKeyDown={event => {
        if (event.key === 'Enter' && !event.nativeEvent.isComposing) {
          event.preventDefault();
          confirm();
        }
      }}/>
    <button className="calibrate-button" type="button" disabled={busy} onClick={confirm}>{label}</button>
  </div>;
}

function FolderDialog({ folder, hasItems, busy, error, save, dismiss, onDeleted }: {
  folder: { key?: string; name: string }; hasItems: boolean; busy: boolean; error: string;
  save: Actions['saveFolder']; dismiss: () => void; onDeleted: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const title = useId();
  const [name, setName] = useState(folder.name);
  const [deleting, setDeleting] = useState(false);
  const [attempted, setAttempted] = useState(false);
  useLayoutEffect(() => {
    const element = dialog.current!;
    element.showModal();
    return () => element.close();
  }, []);
  useLayoutEffect(() => {
    if (deleting) cancel.current?.focus();
    else { input.current?.focus(); input.current?.select(); }
  }, [deleting]);
  function cancelAction() {
    if (deleting) { setDeleting(false); setAttempted(false); }
    else dismiss();
  }

  return <dialog ref={dialog} className="folder-dialog" aria-labelledby={title} onCancel={event => {
    event.preventDefault();
    if (!busy) cancelAction();
  }}>
    <form onSubmit={async event => {
      event.preventDefault();
      if (busy || (!deleting && !name.trim())) return;
      setAttempted(true);
      if (await save(name, folder.key, deleting)) {
        if (deleting) onDeleted();
        dismiss();
      }
    }}>
      <div className="folder-dialog-heading">
        <h2 id={title}>{deleting ? 'Delete folder' : folder.key ? 'Edit folder' : 'Add folder'}</h2>
        <button type="button" className="icon-button" aria-label="Close" disabled={busy} onClick={dismiss}><Icon name="close"/></button>
      </div>
      {deleting ? <p>Delete “{folder.name}”?{hasItems && ' Its items will move to No folder.'}</p>
        : <label>Folder name<input ref={input} value={name} maxLength={256} required disabled={busy}
          onChange={event => setName(event.target.value)}/></label>}
      <div className="button-row folder-dialog-actions">
        <button className={deleting ? 'danger' : 'primary'} disabled={busy || (!deleting && !name.trim())}>
          {deleting ? 'Delete folder' : 'Save'}
        </button>
        <button ref={cancel} type="button" disabled={busy} onClick={cancelAction}>Cancel</button>
        {folder.key && !deleting && <button type="button" className="icon-button danger folder-delete" aria-label="Delete folder"
          title="Delete folder" disabled={busy} onClick={() => { setAttempted(false); setDeleting(true); }}><Icon name="trash"/></button>}
      </div>
    </form>
    {attempted && error && <Toast key={error} message={error} kind="error"/>}
  </dialog>;
}

function ConfirmItemAction({ title, description, action, cancel, cancelLabel = 'Keep editing' }: {
  title: string; description: string; action: () => void; cancel: () => void; cancelLabel?: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const cancelButton = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const descriptionId = useId();
  useLayoutEffect(() => {
    const element = dialog.current!;
    element.showModal();
    cancelButton.current?.focus();
    return () => element.close();
  }, []);
  return <dialog ref={dialog} className="folder-dialog" aria-labelledby={titleId} aria-describedby={descriptionId}
    onCancel={event => { event.preventDefault(); cancel(); }}>
    <div className="folder-dialog-heading"><h2 id={titleId}>{title}</h2></div>
    <p id={descriptionId}>{description}</p>
    <div className="button-row folder-dialog-actions">
      <button type="button" className="danger" onClick={action}>{title}</button>
      <button ref={cancelButton} type="button" onClick={cancel}>{cancelLabel}</button>
    </div>
  </dialog>;
}

function ImportProgressDialog({ label, done, total }: NonNullable<Model['importProgress']>) {
  const dialog = useRef<HTMLDialogElement>(null);
  const title = useId(), status = useId();
  useLayoutEffect(() => {
    const element = dialog.current!;
    element.showModal();
    return () => element.close();
  }, []);
  return <dialog ref={dialog} className="folder-dialog import-progress" aria-labelledby={title}
    onCancel={event => event.preventDefault()}>
    <div className="folder-dialog-heading"><h2 id={title}>Importing from Bitwarden</h2></div>
    <p id={status} role="status">{label}</p>
    <progress aria-labelledby={status} max={total || 1} value={total ? done : undefined}/>
    {!!total && <small>{done} of {total} processed</small>}
  </dialog>;
}

function VaultSurface({ model: m, actions: a }: { model: Model; actions: Actions }) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [attachmentRecord, setAttachmentRecord] = useState<VaultRecord>();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => readPreference('vault-sidebar', 'expanded') === 'collapsed');
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [recoveryExpanded, setRecoveryExpanded] = useState(false);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [folderEdit, setFolderEdit] = useState<{ key?: string; name: string }>();
  const [itemConfirmation, setItemConfirmation] = useState<'discard' | 'delete'>();
  const folders = vaultFolders(m.notes);
  const folderFilters: SelectOption[] = [
    ...folders.map(folder => ({ value: `folder:${folder.key}`, label: folder.name, icon: 'folder' as const })),
    { value: 'folder:', label: 'No folder', icon: 'folder' },
  ];
  folderFilters[0].section = 'Folders';
  const filters = [...baseFilters, ...folderFilters];
  const activeFilter = filters.some(option => option.value === filter) ? filter : 'all';
  const folderKey = activeFilter.startsWith('folder:') ? activeFilter.slice(7) : undefined;
  const blocked = m.busy || m.dirty;
  const optionalRecovery = m.status.exists && !m.status.requiresRecoveryFile;
  const recoveryFields = <>
    {!optionalRecovery && <label htmlFor="vault-recovery-file">Recovery key file</label>}
    <input id="vault-recovery-file" type="file" accept=".vvrk" disabled={m.busy} required={!optionalRecovery}
      aria-label={optionalRecovery ? 'Choose recovery key file' : undefined} aria-describedby="vault-recovery-help"
      onChange={event => a.setRecoveryFile(event.target.files?.[0])}/>
    <p id="vault-recovery-help" className="fine">{m.status.exists ? 'Choose your .vvrk file to recover access. Recovering a newer vault can replace older vault data on this device.'
      : 'Save the downloaded file offline, then select it here to confirm you have it.'}</p>
  </>;
  function changeFilter(value: string) {
    setFilter(value); setQuery(''); setFolderEdit(undefined); a.select(-1); a.navigate('vault');
  }
  function startFolder(key?: string) {
    setFolderEdit({ key, name: folders.find(folder => folder.key === key)?.name ?? '' });
  }
  const addChoices = [...itemTypes.map(({ type, label, icon }) => ({ label, icon, action: () => {
    const destination = folderKey || undefined;
    changeFilter(destination ? `folder:${destination}` : 'all');
    a.newNote(type, destination);
  } })), { label: 'Folder', icon: 'folder' as const, divider: true, action: () => startFolder() }];
  const note = m.notes[m.selected];
  const item = m.newItem ?? note?.item;
  const hasDetail = !!(note || m.newItem);
  function closeItem() {
    const edited = m.newItem ? !!m.draft || JSON.stringify(m.editor) !== JSON.stringify(itemDraft(m.newItem)) : m.dirty;
    if (edited) setItemConfirmation('discard');
    else a.select(-1);
  }
  function deleteItem() {
    if (m.dirty) setItemConfirmation('delete');
    else a.setTrashed(m.selected, true);
  }
  const conflict = !!note && m.notes.filter(n => n.revision.context.objectId === note.revision.context.objectId).length > 1;
  function toggleSidebar() {
    const next = !sidebarCollapsed;
    setSidebarCollapsed(next);
    writePreference('vault-sidebar', next ? 'collapsed' : 'expanded');
  }
  const sidebarAction = sidebarCollapsed ? 'Expand side navigation' : 'Collapse side navigation';
  return <div className={sidebarCollapsed ? 'shell sidebar-collapsed' : 'shell'}>
    <aside className="sidebar">
      <div className="brand" aria-label="Voltura Vault"><img src="/icon-192.png" width="32" height="32" alt=""/><strong>Voltura Vault</strong></div>
      <nav aria-label="Main navigation">
        <button aria-label="Vault" title={sidebarCollapsed ? 'Vault' : undefined} aria-current={m.page === 'vault' ? 'page' : undefined} className={m.page === 'vault' ? 'active' : ''} onClick={() => a.navigate('vault')}><Icon name="vault"/><span className="nav-label">Vault</span></button>
        <button aria-label="Files" title={sidebarCollapsed ? 'Files' : undefined} aria-current={m.page === 'attachments' ? 'page' : undefined} className={m.page === 'attachments' ? 'active' : ''} disabled={m.dirty} onClick={() => a.navigate('attachments')}><Icon name="file"/><span className="nav-label">Files</span>{m.unlocked && !m.hidden && m.status.attachments.length > 0 && <span className="count">{m.status.attachments.length}</span>}</button>
        <button aria-label="Settings" title={sidebarCollapsed ? 'Settings' : undefined} aria-current={m.page === 'device' ? 'page' : undefined} className={m.page === 'device' ? 'active' : ''} disabled={m.dirty} onClick={() => a.navigate('device')}><Icon name="settings"/><span className="nav-label">Settings</span></button>
        {m.unlocked && !m.hidden && <button type="button" className="sidebar-generator" aria-label="Generator"
          aria-haspopup="dialog" title={sidebarCollapsed ? 'Generator' : undefined} disabled={m.busy} onClick={() => setGeneratorOpen(true)}>
          <Icon name="refresh"/><span className="nav-label">Generator</span>
        </button>}
      </nav>
      {m.unlocked && !m.hidden && <div className="vault-filters" aria-label="Vault filters">
        {baseFilters.map(option => <button type="button" key={option.value} aria-pressed={m.page === 'vault' && filter === option.value}
          disabled={blocked} onClick={() => changeFilter(option.value)}><Icon name={option.icon}/><span>{option.label}</span></button>)}
        <details open className="folder-filters">
          <summary><Icon name="folder"/>Folders<Icon name="chevron"/></summary>
          {folders.map(folder => <div className="folder-filter" key={folder.key}>
            <button type="button" aria-pressed={m.page === 'vault' && folderKey === folder.key} disabled={blocked}
              onClick={() => changeFilter(`folder:${folder.key}`)}><Icon name="folder"/><span>{folder.name}</span></button>
            <button type="button" aria-label={`Rename ${folder.name}`} title={`Rename ${folder.name}`} disabled={blocked}
              onClick={() => startFolder(folder.key)}><Icon name="edit"/></button>
          </div>)}
          <button type="button" aria-pressed={m.page === 'vault' && folderKey === ''} disabled={blocked} onClick={() => changeFilter('folder:')}><Icon name="folder"/><span>No folder</span></button>
        </details>
      </div>}
      <div className="sidebar-bottom">
        {testBuild && <span className="build-tag">Test build</span>}<span className="version">v{buildVersion}</span>
        <button type="button" className="sidebar-toggle icon-button" aria-label={sidebarAction}
          aria-expanded={!sidebarCollapsed} title={sidebarAction} onClick={toggleSidebar}><Icon name="chevron"/></button>
      </div>
    </aside>
    <main>
      <header className="topbar"><h1>{m.page === 'vault' ? 'Vault' : m.page === 'device' ? 'Settings' : 'Files'}</h1><div className="header-actions">
        {!m.online && <span className="connection"><i/>Offline</span>}
        {m.webUpdate && <button type="button" className={m.unlocked ? 'icon-button' : undefined}
          aria-label="Check for updates" title="Check for updates" disabled={m.webUpdate.checking}
          onClick={m.webUpdate.check}><Icon name="refresh"/>{!m.unlocked && 'Check for updates'}</button>}
        {m.unlocked && !m.hidden && m.page === 'vault' && <Popup label="Add" className="primary add-trigger"
          trigger={<><Icon name="plus"/>Add</>} disabled={blocked} choices={addChoices}/>}
        {m.unlocked && (m.helloSetup
          ? <button type="button" onClick={a.lock}>Cancel setup and lock</button>
          : <button className="icon-button" title="Lock vault" aria-label="Lock vault" onClick={a.lock}><Icon name="lock"/></button>)}
      </div></header>
      <div className="page-content">
        {m.unlocked && !m.hidden && m.status.rejectedServerData &&
          <p role="status">Vault skipped server data it could not authenticate. Check the server before relying on this copy.</p>}
        {m.unlocked && !m.hidden && m.status.helloSyncReconnect && !m.rotationNeeded && m.page !== 'device' &&
          <div className="setting-row"><span>Sync needs to reconnect.</span>
            <button disabled={m.busy} onClick={() => a.navigate('device')}>Reconnect sync</button></div>}
        {m.webUpdate?.version && <section className="web-update" aria-label="Vault update">
          <div><strong>New version available</strong><span>v{m.webUpdate.version}</span></div>
          <div className="web-update-actions">
            <button type="button" className="primary" disabled={blocked || !m.online} onClick={() => window.location.reload()}>Update now</button>
            <button type="button" onClick={m.webUpdate.dismiss}>Later</button>
          </div>
          {m.dirty && <small>Save or discard your edits to update.</small>}
        </section>}
        {!folderEdit && (m.error
          ? <Toast key={`error:${m.error}`} message={m.error} kind="error"/>
          : m.webUpdate?.feedback
            ? <Toast key={`update:${m.webUpdate.feedback.message}`} message={m.webUpdate.feedback.message}
              kind={m.webUpdate.feedback.kind} onDismiss={m.webUpdate.dismissFeedback}/>
            : m.notice && <Toast key={m.notice} message={m.notice} kind={m.busy ? 'progress' : 'status'}/>)}
        {m.hidden && m.unlocked ? <section className="empty"><Icon name="lock"/><h2>Content hidden</h2></section> : <>
          {m.page === 'vault' && (!m.unlocked ? <section className="unlock-layout">
            {m.publicDesktop && !m.status.exists && m.status.remote === 'unavailable' ? <ConnectDesktop model={m} actions={a}/> :
            m.independentWeb && !m.status.exists && m.status.remote === 'unavailable' ? <div className="unlock-card">
              <div className="unlock-mark"><Icon name="lock"/></div>
              <h2>Connect to your vault</h2>
              <p className="subtitle">Turn on WireGuard. If your browser asks for local network access, allow it for this site.</p>
              <button className="primary unlock-submit" type="button" disabled={m.busy} onClick={a.connect}>{m.busy ? 'Connecting…' : 'Connect to Vault'}<Icon name="arrow"/></button>
              {testBuild && <p className="test-notice">Test data only. Not ready for real passwords.</p>}
            </div> :
            <form className="unlock-card" onSubmit={event => { event.preventDefault(); setPasswordVisible(false); a.unlock(); }}>
              <div className="unlock-mark"><Icon name="lock"/></div>
              <h2>{m.status.exists ? 'Unlock your vault' : testBuild ? 'Create a test vault' : 'Create your vault'}</h2>
              {m.publicDesktop && m.status.server && <p className="fine">{m.status.server}</p>}
              <p className="subtitle">{m.status.exists ? 'Enter your master password.' : testBuild ? 'Choose a password for this test vault.' : 'Choose a master password with at least 15 characters.'}</p>
              <label htmlFor="password">Master password</label>
              <div className="input-with-actions">
                <input id="password" type={passwordVisible ? 'text' : 'password'} autoComplete="off" autoCapitalize="none"
                  autoCorrect="off" spellCheck={false} value={m.password} onChange={e => a.setPassword(e.target.value)}
                  disabled={m.busy} required maxLength={1024}/>
                <div className="field-actions">
                  <button type="button" className="icon-button" aria-controls="password"
                    aria-label={passwordVisible ? 'Hide master password' : 'Show master password'}
                    disabled={m.busy} onClick={() => setPasswordVisible(visible => !visible)}>
                    <Icon name={passwordVisible ? 'eye-off' : 'eye'}/>
                  </button>
                </div>
              </div>
              {m.status.remote === 'new' && <><label htmlFor="setup">Server setup token</label><input id="setup" type="password" autoComplete="off" value={m.setup} onChange={e => a.setSetup(e.target.value)} disabled={m.busy} required maxLength={43}/></>}
              {!m.status.exists && <button className="calibrate-button" type="button" disabled={m.busy} onClick={a.downloadRecoveryKey}>Download recovery key</button>}
              {!optionalRecovery && (m.status.exists || m.recoveryDownloaded) && recoveryFields}
              {!m.status.exists && <button className="calibrate-button" type="button" disabled={m.busy} onClick={a.calibrate}>{m.calibration?.targetReached ? <><Icon name="check"/>Unlock time measured</> : 'Measure unlock time'}</button>}
              <button className="primary unlock-submit" type="submit" disabled={m.busy || !m.password || m.status.remote === 'unavailable' || (!m.status.exists && !m.calibration?.targetReached) || ((!m.status.exists || m.status.requiresRecoveryFile) && !m.recoveryFile)}>{m.busy ? 'Working…' : m.status.exists ? 'Unlock' : testBuild ? 'Create test vault' : 'Create vault'}{!m.busy && <Icon name="arrow"/>}</button>
              {m.helloAvailable && m.status.hello && <button className="calibrate-button" type="button" disabled={m.busy} onClick={a.unlockHello}>Unlock with Windows Hello</button>}
              {optionalRecovery && <div className="unlock-recovery">
                <button type="button" className="unlock-recovery-toggle"
                  aria-expanded={recoveryExpanded} aria-controls="vault-recovery-fields" disabled={m.busy}
                  onClick={() => {
                    if (recoveryExpanded) a.setRecoveryFile(undefined);
                    setRecoveryExpanded(!recoveryExpanded);
                  }}>
                  Recovery key file (optional)<Icon name="chevron"/>
                </button>
                <div id="vault-recovery-fields" hidden={!recoveryExpanded}>{recoveryExpanded && recoveryFields}</div>
              </div>}
              {testBuild && <p className="test-notice">Test data only. Not ready for real passwords.</p>}
            </form>}
          </section> : <section className={`vault-grid ${hasDetail ? 'has-detail' : ''} ${hasDetail && m.mobileDetail ? 'show-detail' : ''}`}>
            <VaultList model={m} actions={a} folders={folders} filters={filters} filter={activeFilter} folderKey={folderKey}
              query={query} setQuery={setQuery} changeFilter={changeFilter}
              startFolder={startFolder} openAttachments={setAttachmentRecord} emptyAction={<Popup label="Add item" trigger={<><Icon name="plus"/>Add item</>}
                className="primary" disabled={blocked} choices={addChoices}/>}/>
            {hasDetail && <article className="detail" key={note?.revision.context.revisionId ?? 'new-item'}>
              <button className="back" disabled={m.busy} onClick={closeItem}>← Back to list</button>
              <div className="detail-heading"><span className="item-icon"><Icon name={itemIcons[itemType(item)] ?? 'note'}/></span>
                <div><h2>{m.newItem ? `Add ${m.newItem.kind.toLowerCase()}` : note && recordTitle(note)}</h2>{!m.newItem && item && <p className="fine">{item.kind}</p>}</div>
                <button type="button" className="icon-button close-detail" aria-label="Close item" data-tooltip="Close item" disabled={m.busy} onClick={closeItem}><Icon name="close"/></button></div>
              {note?.trashed ? <button disabled={m.busy} onClick={() => a.setTrashed(m.selected, false)}>Restore item</button> : <>
              <ItemFields item={item} folders={folders} draft={m.editor} change={a.setEditor} disabled={m.busy} copy={a.copy}
                generatorHistory={a.generatorHistory}/>
              {itemType(item) === 2 && <><label htmlFor="note">Note</label><textarea id="note" value={m.draft} onChange={e => a.setDraft(e.target.value)} disabled={m.busy} spellCheck={false}/></>}
              {note?.item && <ImportedFields item={note.item} copy={a.copy}/>}
              <div className="detail-actions">
                {m.newItem ? <>
                  <button disabled={m.busy || !m.editor.name.trim()} className="primary" onClick={a.save}>Save</button>
                  <button type="button" disabled={m.busy} onClick={closeItem}>Cancel</button>
                </> : <>
                  <button type="button" className="danger icon-button" aria-label="Delete item" data-tooltip="Delete item" disabled={m.busy} onClick={deleteItem}><Icon name="trash"/></button>
                  {note && <button type="button" disabled={blocked} onClick={() => setAttachmentRecord(note)}><Icon name="file"/>Attachments</button>}
                  <button disabled={m.busy || !m.dirty} className="primary" onClick={a.save}>Save changes</button>
                </>}
              </div>
              {conflict && <div className="warning"><p>Concurrent versions are preserved. Save this draft as the resolution when you’re ready.</p><button disabled={m.busy} onClick={a.resolve}>Resolve with this draft</button></div>}
              </>}
            </article>}
          </section>)}
          {m.page === 'device' && <section className="settings-page">
            {m.unlocked && m.rotationNeeded && <form className="card" onSubmit={event => {
              event.preventDefault();
              const form = event.currentTarget, fields = new FormData(form);
              const password = fields.get('rotation-password'), recovery = fields.get('rotation-file');
              if (m.busy || m.dirty || !m.online || typeof password !== 'string' || !(recovery instanceof File)) return;
              form.reset(); a.recoverRotation(password, recovery);
            }}>
              <h2>Recover this device</h2>
              <p className="fine">Use the new master password and recovery file. Saved offline edits and files will be carried into the new vault key.</p>
              <label>New master password <input name="rotation-password" type="password" autoComplete="off" required disabled={m.busy}/></label>
              <label>New recovery file <input name="rotation-file" type="file" accept=".vvrk" required disabled={m.busy}/></label>
              <button className="primary" disabled={m.busy || m.dirty || !m.online}>Recover device</button>
            </form>}
            {m.unlocked && <article className="card">
              <h2>Import from Bitwarden</h2>
              {!m.status.importAvailable ? <p className="fine">Import requires a protected vault unlocked with your master password in the installed app or the independent web client.</p> : <>
              {testBuild && <p className="warning">Use a test export until the production vault and its recovery are verified.</p>}
              <p className="fine">Choose a JSON export. The file is decrypted and encrypted for Vault on this device.</p>
              <label>Bitwarden JSON <input type="file" accept=".json,application/json" disabled={m.busy || m.dirty}
                onChange={event => { a.importFile(event.target.files?.[0]); event.target.value = ''; }}/></label>
              {m.importFile && <p className="fine">{m.importFile.name}</p>}
              <label>Export password <input type="password" autoComplete="off" disabled={m.busy} value={m.importPassword} onChange={event => a.importPassword(event.target.value)}/></label>
              <div className="button-row"><button disabled={m.busy || m.dirty || !m.importFile} onClick={a.previewImport}>Preview import</button>
                {m.importPreview && <button className="primary" disabled={m.busy || m.dirty || (!m.importPreview.newItems && !m.importPreview.newFolders)} onClick={a.commitImport}>Import items</button>}</div>
              {m.importPreview && <><p>{m.importPreview.newItems} new · {m.importPreview.duplicates} already present · {m.importPreview.newFolders} new folders</p>
                {m.importPreview.changed > 0 && <p>{m.importPreview.changed} existing items differ from this export and will be skipped.</p>}
                {m.importPreview.passkeys > 0 && <p>{m.importPreview.passkeys} passkeys will be stored as encrypted data. Keep Bitwarden for passkey sign-in.</p>}
                {m.importPreview.archived > 0 && <p>{m.importPreview.archived} archived items will appear in the item list.</p>}
                {m.importPreview.unresolvedFolders > 0 && <p>{m.importPreview.unresolvedFolders} items reference folders missing from the export.</p>}
                <p className="fine">{Object.entries(m.importPreview.types).map(([kind, count]) => `${kind}: ${count}`).join(' · ')}</p>
                <p className="fine">JSON exports omit attachment bytes. {m.importPreview.attachments ? `${m.importPreview.attachments} attachment references were preserved.` : ''}</p></>}</>}
            </article>}
            {m.publicDesktop && m.unlocked && m.status.server && <article className="card">
              <h3>Paired server</h3>
              <p className="fine">{m.status.server}</p>
              <button type="button" disabled={m.busy || m.dirty} onClick={a.checkPairing}>Check before changing servers</button>
            </article>}
            {m.unlocked && m.status.remote === 'configured' && m.status.masterSession && <article className="card">
              <h2>Source versions</h2>
              <p className="fine">Deployment snapshots can be restored with your offline source recovery key.</p>
              <details><summary>Set up source backups</summary>
                <p className="fine">Save the public key on your development PC and keep the encrypted recovery file outside the Vault.</p>
                <label>Confirm master password <input type="password" autoComplete="off" disabled={m.busy}
                  value={m.sourcePassword} onChange={event => a.setSourcePassword(event.target.value)}/></label>
                <div className="button-row"><button disabled={m.busy || m.dirty || !m.sourcePassword} onClick={a.enrollSource}>Prepare source keys</button>
                {m.sourceRecovery && <><button onClick={() => a.saveSourceKey(true)}>Save public key</button>
                  <button onClick={() => a.saveSourceKey(false)}>Save encrypted recovery file</button></>}</div>
              </details>
              <button disabled={m.busy || !m.online} onClick={() => a.listSources()}>Load source versions</button>
              {m.sourceVersions?.length === 0 && <p className="fine">No source versions stored yet.</p>}
              {m.sourceVersions?.map(version => <div className="setting-row" key={version.id}>
                <span>{new Date(version.created * 1000).toLocaleString()} <small>{version.id.slice(0, 8)}</small></span>
                <button disabled={m.busy || !m.online} onClick={() => a.downloadSource(version.id, version.size)}>Download encrypted source</button>
              </div>)}
            </article>}
            {m.unlocked && m.status.remote === 'configured' && m.status.masterSession && <article className="card">
              <h2>Recovery Kit</h2>
              <p className="fine">Encrypted infrastructure keys for rebuilding Vault. Keep the recovery key and a kit copy outside the app.</p>
              <button disabled={m.busy || !m.online} onClick={() => a.listSources(true)}>Load recovery kits</button>
              {m.recoveryVersions?.length === 0 && <p className="fine">No recovery kits stored yet.</p>}
              {m.recoveryVersions?.map(version => <div className="setting-row" key={version.id}>
                <span>{new Date(version.created * 1000).toLocaleString()} <small>{version.id.slice(0, 8)}</small></span>
                <button disabled={m.busy || !m.online} onClick={() => a.downloadSource(version.id, version.size, true)}>Download encrypted recovery kit</button>
              </div>)}
            </article>}
            <h2 className="section-label">Preferences</h2>
            <div className="settings-group">
              <div className="setting-row"><span>Appearance</span><ThemedSelect label="Appearance" value={m.theme} onChange={a.setTheme}
                options={[{ value: 'system', label: 'System' }, { value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' }]}/></div>
              <div className="setting-row"><span>Color palette</span><ThemedSelect label="Color palette" value={m.palette}
                onChange={a.setPalette} options={PALETTES}/></div>
              <div className="setting-row"><span>Lock after<small>{m.unlocked ? 'Lock the vault to change this.' : 'Includes time in the background.'}</small></span>
                <ThemedSelect label="Lock after" disabled={m.unlocked} value={String(m.timeout)} onChange={value => a.setTimeout(Number(value))}
                  options={TIMEOUTS.map(n => ({ value: String(n), label: `${n} minutes` }))}/></div>
              {m.privateClipboard && <div className="setting-row"><span>Clear copied values after</span>
                <ThemedSelect label="Clear copied values after" value={String(m.clipboardSeconds)}
                  onChange={value => a.setClipboardSeconds(Number(value))}
                  options={CLIPBOARD_TIMEOUTS.map(seconds => ({ value: String(seconds), label: `${seconds} seconds` }))}/></div>}
            </div>
            <h2 className="section-label">Device checks</h2>
            <div className="check-grid">
              <article className="card"><h3>Windows Hello</h3>
                {m.helloAvailable && m.unlocked && <p className="fine">{m.status.hello ? 'Enabled' : 'Disabled'}</p>}
                {!m.helloAvailable ? <p className="fine">Set up Windows Hello in the installed Windows app.</p>
                  : !m.unlocked ? <p className="fine">Unlock the vault to manage Windows Hello.</p>
                  : m.status.hello ? <>
                    {m.status.helloSyncReconnect && !m.rotationNeeded &&
                      <HelloSetupFields busy={m.busy || m.dirty || !m.online} enable={a.reconnectHelloSync}
                        label="Reconnect sync" hint=""/>}
                    <button type="button" disabled={m.busy} onClick={a.disableHello}>Turn off Windows Hello</button>
                  </>
                  : m.browserHelloPending ? <>
                    <p className="fine">Windows saved your passkey. Confirm it to finish setup. If Windows can’t find it yet, wait a moment and try again.</p>
                    <button type="button" disabled={m.busy} onClick={a.confirmBrowserHello}>Confirm Windows Hello</button>
                  </>
                  : <HelloSetupFields busy={m.busy || (m.windowsVault && m.status.remote === 'configured' && !m.online)}
                    enable={a.enableHello} hint={m.windowsVault && m.status.remote === 'configured'
                      ? m.online ? '' : 'Connect to your vault to set up Windows Hello.'
                      : undefined}/>}
              </article>
              <article className="card"><h3>Offline storage</h3><div className="button-row"><button disabled={m.busy} onClick={() => a.checkStorage(false)}>Check storage</button><button disabled={m.busy} onClick={() => a.checkStorage(true)}>Keep storage</button></div><details><summary>About local storage</summary><p>Only encrypted data is stored. Browser storage may be removed and is not a backup.</p></details></article>
              {testBuild && <article className="card">
                <h3>Before real data</h3>
                <ul className="gate-list">
                  <li>iPhone Home Screen <span>Unlock and lock verified</span></li>
                  <li>Lenovo encrypted boot <span>TPM unlock verified</span></li>
                  <li>Backup restore <span>Scheduled backup restored</span></li>
                </ul>
              </article>}
            </div>
          </section>}
          {m.page === 'attachments' && (!m.unlocked ? <section className="empty"><Icon name="lock"/>
            <h2>Unlock your vault to view files</h2><button className="primary" onClick={() => a.navigate('vault')}>Unlock vault</button>
          </section> : <section className="files-page"><div className="files-heading"><div><h2>Encrypted files</h2><p className="subtitle">Up to 100 MB per file.</p></div></div>
            <label>Add file <input type="file" disabled={m.busy} onChange={event => { const file = event.target.files?.[0]; if (file) a.generate(file); event.target.value = ''; }}/></label>
            <AttachmentList files={m.status.attachments} model={m} actions={a}/>
          </section>)}
        </>}
        {m.importProgress && <ImportProgressDialog {...m.importProgress}/>}
        {m.unlocked && !m.hidden && generatorOpen && <GeneratorDialog history={a.generatorHistory} close={() => setGeneratorOpen(false)}/>}
        {attachmentRecord && !m.hidden && <RecordAttachments record={attachmentRecord} model={m} actions={a} close={() => setAttachmentRecord(undefined)}/>}
        {folderEdit && !m.hidden && <FolderDialog folder={folderEdit}
          hasItems={!!folderEdit.key && m.notes.some(note => !note.trashed && note.item?.folder === folderEdit.key)}
          busy={m.busy} error={m.error} save={a.saveFolder}
          dismiss={() => setFolderEdit(undefined)} onDeleted={() => {
            if (filter === `folder:${folderEdit.key}`) changeFilter('folder:');
          }}/>}
        {itemConfirmation && !m.hidden && <ConfirmItemAction
          title={itemConfirmation === 'delete' ? 'Move to Trash' : 'Discard changes'}
          description={itemConfirmation === 'delete' ? 'Unsaved changes will be discarded. The saved item will move to Trash.'
            : m.newItem ? 'This new item will be discarded.' : 'Your unsaved changes will be discarded.'}
          cancel={() => setItemConfirmation(undefined)} action={() => {
            setItemConfirmation(undefined);
            if (itemConfirmation === 'delete') a.setTrashed(m.selected, true);
            else a.select(-1);
          }}/>}
      </div>
    </main>
  </div>;
}

function ConnectDesktop({ model: m, actions: a }: { model: Model; actions: Actions }) {
  const [url, setUrl] = useState(m.status.server ?? '');
  const [certificate, setCertificate] = useState<File>();
  return <form className="unlock-card" onSubmit={event => { event.preventDefault(); a.connectDesktop(url, certificate); }}>
    <h2>Connect to Vault</h2>
    <p className="subtitle">Enter the HTTPS address from your server operator.</p>
    <label htmlFor="vault-server-url">Server URL</label>
    <input id="vault-server-url" value={url} onChange={event => setUrl(event.target.value)} type="url"
      autoComplete="off" maxLength={2048} placeholder="https://vault.example.com" required disabled={m.busy}/>
    <label htmlFor="vault-server-ca">Public CA certificate (optional)</label>
    <input id="vault-server-ca" type="file" accept=".cer,.crt,.pem,.der" disabled={m.busy}
      onChange={event => setCertificate(event.target.files?.[0])}/>
    <p className="fine">Select the public CA file from your operator if your device does not already trust the server.</p>
    <button className="primary unlock-submit" type="submit" disabled={m.busy || !url}>{m.busy ? 'Connecting…' : 'Connect to Vault'}<Icon name="arrow"/></button>
  </form>;
}
