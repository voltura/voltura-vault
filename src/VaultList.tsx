import { Icon, itemIcons } from './Icon';
import { Popup, ThemedSelect, type SelectOption } from './Popup';
import { itemType } from './item-editor';
import { matchesSearch, quickCopies, recordTitle, type Folder, type VaultRecord } from './organization';
import type { Actions, Model } from './VaultView';
import type { ReactNode } from 'react';

export function VaultList({ model: m, actions: a, folders, filters, filter, folderKey, query, setQuery,
  changeFilter, startFolder, openAttachments, emptyAction }: {
  model: Model; actions: Actions; folders: Folder[]; filters: SelectOption[]; filter: string;
  folderKey?: string; query: string; setQuery: (query: string) => void; changeFilter: (value: string) => void;
  startFolder: (key: string) => void; openAttachments: (record: VaultRecord) => void; emptyAction: ReactNode;
}) {
  const blocked = m.busy || m.dirty;
  const folderNames = new Map(folders.map(folder => [folder.key, folder.name]));
  const rows = m.notes.map((record, index) => ({
    record, index, title: recordTitle(record), folder: folderNames.get(record.item?.folder ?? '') ?? '',
  })).filter(({ record, folder }) => {
    if (record.folderEntry || !!record.trashed !== (filter === 'trash')) return false;
    const membership = record.item?.folder ?? '';
    if (folderKey !== undefined && (folderNames.has(membership) ? membership : '') !== folderKey) return false;
    if (filter === 'favorites' && record.item?.source.favorite !== true) return false;
    if (filter.startsWith('type:') && itemType(record.item) !== Number(filter.slice(5))) return false;
    return !query.trim() || matchesSearch(record, query, folder);
  }).sort((a, b) => a.title.localeCompare(b.title));

  return <div className="item-list">
    <div className="mobile-filter"><ThemedSelect label="Filter vault" value={filter} options={filters} onChange={changeFilter} disabled={blocked}/></div>
    <div className="vault-search"><Icon name="search"/>
      <input type="search" aria-label="Search vault" placeholder={folderKey === undefined ? 'Search vault' : 'Search folder'} value={query}
        autoComplete="off" onChange={event => setQuery(event.target.value)}/>
      {query && <button type="button" aria-label="Clear search" onClick={() => setQuery('')}><Icon name="close"/></button>}
    </div>
    <div className="list-heading"><h2>{filters.find(option => option.value === filter)?.label ?? 'Vault items'}</h2>
      <span>{rows.length} {rows.length === 1 ? 'item' : 'items'}</span>
      {folderKey && <button type="button" className="icon-button" aria-label="Rename folder" title="Rename folder" disabled={blocked} onClick={() => startFolder(folderKey)}><Icon name="edit"/></button>}
      {m.status.remote === 'configured' && !m.status.helloOnly && <button disabled={blocked || !m.online} onClick={a.sync}>{m.syncPaused ? 'Resume sync' : 'Sync now'}</button>}
    </div>
    {!rows.length && (!query.trim() && (filter === 'all' || folderKey !== undefined)
      ? <div className="vault-empty">
        <div className="vault-empty-icons" aria-hidden="true">
          <Icon name="key"/><Icon name="card"/><Icon name="identity"/><Icon name="note"/>
        </div>
        <h3>{filter === 'all' ? 'No items in the vault' : 'No items here yet.'}</h3>
        {emptyAction}
      </div>
      : <p className="list-empty">{query.trim() ? 'No matching items.' : filter === 'trash' ? 'Trash is empty.' : 'No items here yet.'}</p>)}
    {rows.map(({ record, index, title, folder }) => {
      const copies = record.trashed ? [] : quickCopies(record);
      return <div key={record.revision.context.revisionId} className={`item-row ${m.selected === index ? 'selected' : ''}`}>
        <button className="item" aria-pressed={m.selected === index} disabled={blocked} onClick={() => a.select(index)}>
          <span className="item-icon"><Icon name={itemIcons[itemType(record.item)] ?? 'note'}/></span>
          <span className="item-title"><strong>{title}</strong><small>{[record.item?.kind ?? 'Secure note', folder].filter(Boolean).join(' · ')}</small></span>
          {record.item?.source.favorite === true && <Icon name="star"/>}
        </button>
        {copies.length > 0 && <Popup label={`Quick copy for ${title}`} className="icon-button row-action"
          trigger={<Icon name="copy"/>} showLabel={false} disabled={m.busy}
          choices={copies.map(([label, value]) => ({ label: `Copy ${label}`, action: () => a.copy(value) }))}/>}
        <Popup label={`Actions for ${title}`} className="icon-button row-action" trigger={<Icon name="more"/>} showLabel={false} disabled={blocked}
          choices={record.trashed ? [{ label: 'Restore', icon: 'arrow', action: () => a.setTrashed(index, false) }]
            : [{ label: 'Edit', icon: 'edit', action: () => a.select(index) },
              { label: 'Attachments', icon: 'file', action: () => openAttachments(record) },
              { label: 'Clone', icon: 'copy', action: () => a.clone(index) },
              ...copies.map(([label, value]) => ({ label: `Copy ${label}`, icon: 'copy' as const, action: () => a.copy(value) })),
              { label: 'Delete', icon: 'trash', danger: true, divider: true, action: () => a.setTrashed(index, true) }]}/>
      </div>;
    })}
    {m.status.remote === 'configured' && m.status.pending > 0 && <p className="list-foot">{m.status.pending} {m.status.pending === 1 ? 'edit' : 'edits'} pending sync</p>}
  </div>;
}
