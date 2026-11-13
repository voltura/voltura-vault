import { useId, useLayoutEffect, useRef, useState } from 'react';
import { Icon } from './Icon';
import { GeneratorDialog, type GeneratorTarget } from './GeneratorDialog';
import type { HistoryAction, HistoryEntry } from './generator-history';
import type { ImportedItem } from './bitwarden';
import { changeFieldType, fieldType, linkedOptions, type CustomField, type EditableFieldType } from './fields';
import { fieldLabel, itemKeys, itemType, secretFields, type ItemDraft } from './item-editor';
import { ThemedSelect } from './Popup';
import type { Folder } from './organization';

const MATCH_RULES = ['Base domain', 'Host', 'Starts with', 'Exact', 'Regular expression', 'Never'];
const IDENTITY_TITLES = ['Mr', 'Mrs', 'Ms', 'Mx', 'Dr'];
const FIELD_TYPES = [
  { value: 'text', label: 'Text' }, { value: 'number', label: 'Number' }, { value: 'hidden', label: 'Hidden' },
  { value: 'boolean', label: 'Checkbox' }, { value: 'linked', label: 'Linked to item' },
];
const labelFor = (key: string) => fieldLabel[key] ?? key[0].toUpperCase() + key.slice(1);
type Common = { disabled: boolean; copy: (value: string) => void };

function GenerateButton({ kind, disabled, open }: { kind: GeneratorTarget; disabled: boolean; open: () => void }) {
  const label = `Generate ${kind}`;
  return <button type="button" className="icon-button" aria-label={label} data-tooltip={label}
    disabled={disabled} onClick={open}><Icon name="refresh"/></button>;
}

function SecretInput({ label, value, change, disabled, copy, generate, multiline }: Common & {
  label: string; value: string; change: (value: string) => void; generate?: () => void; multiline?: boolean;
}) {
  const [visible, setVisible] = useState(false);
  const inputId = useId();
  const visibilityLabel = `${visible ? 'Hide' : 'Show'} ${label.toLowerCase()}`;
  const copyLabel = `Copy ${label.toLowerCase()}`;
  return <div className="vault-field"><label htmlFor={inputId}>{label}</label>
    <div className={generate ? 'input-with-actions secret-input has-generator' : 'input-with-actions secret-input'}>
      {visible && (multiline || /[\r\n]/.test(value))
        ? <textarea id={inputId} value={value} disabled={disabled} onChange={e => change(e.target.value)} rows={2} spellCheck={false}/>
        : <input id={inputId} type={visible ? 'text' : 'password'} value={value} disabled={disabled}
          onChange={e => change(e.target.value)} autoComplete="off" spellCheck={false}/>}
      <div className="field-actions">
        <button type="button" className="icon-button" aria-label={visibilityLabel} data-tooltip={visibilityLabel}
          aria-controls={inputId} disabled={disabled} onClick={() => setVisible(current => !current)}>
          <Icon name={visible ? 'eye-off' : 'eye'}/>
        </button>
        <button type="button" className="icon-button" aria-label={copyLabel} data-tooltip={copyLabel}
          disabled={disabled || !value} onClick={() => copy(value)}><Icon name="copy"/></button>
        {generate && <GenerateButton kind="password" disabled={disabled} open={generate}/>}
      </div>
    </div>
  </div>;
}

function Websites({ urls, change, disabled }: { urls: ItemDraft['urls']; change: (urls: ItemDraft['urls']) => void; disabled: boolean }) {
  const swap = (from: number, to: number) => {
    const next = urls.slice(); [next[from], next[to]] = [next[to], next[from]]; change(next);
  };
  return <section className="vault-editor-section"><h3>Websites</h3>
    {urls.map((entry, index) => {
      const edit = (patch: Partial<typeof entry>) => change(urls.map((url, i) => i === index ? { ...url, ...patch } : url));
      const match = entry.match;
      const matchOption = match == null ? '' : typeof match === 'number' && Number.isInteger(match) && MATCH_RULES[match]
        ? String(match) : 'imported';
      return <div className="vault-editor-row" key={index}>
        <label>Website URL {index + 1}<input value={entry.uri} disabled={disabled} onChange={e => edit({ uri: e.target.value })} inputMode="url" spellCheck={false}/></label>
        <div className="choice-field"><span>Matching rule</span><ThemedSelect label={`Matching rule ${index + 1}`} value={matchOption}
          disabled={disabled} onChange={value => {
            if (value !== 'imported') edit({ match: value === '' ? null : Number(value) });
          }}
          options={[{ value: '', label: 'Default' }, ...MATCH_RULES.map((label, mode) => ({ value: String(mode), label })),
            ...(matchOption === 'imported' ? [{ value: 'imported', label: 'Imported rule' }] : [])]}/></div>
        <div className="button-row"><button disabled={disabled || index === 0} onClick={() => swap(index, index - 1)}>Move up</button>
          <button disabled={disabled || index === urls.length - 1} onClick={() => swap(index, index + 1)}>Move down</button>
          <button disabled={disabled} onClick={() => change(urls.filter((_, i) => i !== index))}>Remove URL</button></div>
      </div>;
    })}
    <button disabled={disabled || urls.length >= 128} onClick={() => change([...urls, { uri: '', match: null }])}>Add website URL</button>
  </section>;
}

function FieldDialog({ field, links, save, remove, close }: {
  field?: CustomField; links: Record<number, string>; save: (field: CustomField) => void;
  remove?: () => void; close: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  const title = useId();
  const [label, setLabel] = useState(field?.name ?? '');
  const originalType = field ? fieldType(field) : 'text';
  const [type, setType] = useState<EditableFieldType>(originalType === 'preserved' ? 'text' : originalType);
  const choices = Object.entries(links);
  const existingLink = originalType === 'linked' ? field?.linkedId : undefined;
  const [link, setLink] = useState(existingLink ?? Number(choices[0]?.[0]));
  const linkChoices = choices.map(([id, key]) => ({ value: id, label: labelFor(key) }));
  if (existingLink !== undefined && !links[existingLink]) {
    linkChoices.unshift({ value: String(existingLink), label: 'Imported link' });
  }
  useLayoutEffect(() => {
    const element = dialog.current!;
    element.showModal();
    nameInput.current?.focus();
    return () => element.close();
  }, []);
  return <dialog ref={dialog} className="folder-dialog field-dialog" aria-labelledby={title}
    onCancel={event => { event.preventDefault(); close(); }}>
    <form onSubmit={event => {
      event.preventDefault();
      if (!label.trim()) return;
      const named = { ...(field ?? { type: 0, value: '' }), name: label.trim() };
      const updated = originalType === type ? named : changeFieldType(named, type, link);
      save(type === 'linked' ? { ...updated, linkedId: link } : updated);
    }}>
      <div className="folder-dialog-heading"><h2 id={title}>{field ? 'Edit field' : 'Add field'}</h2>
        <button type="button" className="icon-button" aria-label="Close" onClick={close}><Icon name="close"/></button></div>
      <div className="choice-field"><span>Field type</span><ThemedSelect label="Field type" value={type}
        options={FIELD_TYPES.filter(option => linkChoices.length || option.value !== 'linked')}
        onChange={value => setType(value as EditableFieldType)}/></div>
      <label>Field label<input ref={nameInput} required maxLength={256} value={label} onChange={event => setLabel(event.target.value)}/></label>
      {type === 'linked' && <div className="choice-field"><span>Linked value</span><ThemedSelect label="Linked value"
        value={String(link)} options={linkChoices} onChange={value => setLink(Number(value))}/></div>}
      <div className="button-row folder-dialog-actions">
        <button className="primary" disabled={!label.trim()}>{field ? 'Save' : 'Add'}</button><button type="button" onClick={close}>Cancel</button>
        {remove && <button type="button" className="icon-button danger remove-custom-field" aria-label="Remove field"
          data-tooltip="Remove field" onClick={remove}><Icon name="trash"/></button>}
      </div>
    </form>
  </dialog>;
}

function CustomFields({ fields, change, type, values, disabled, copy, generatorHistory }: Common & {
  fields: CustomField[]; change: (fields: CustomField[]) => void; type: number; values: ItemDraft['values'];
  generatorHistory: (action: HistoryAction) => Promise<HistoryEntry[]>;
}) {
  const options = linkedOptions[type] ?? {};
  const [editing, setEditing] = useState<number | 'new'>();
  const [generating, setGenerating] = useState<number>();
  const [order, setOrder] = useState(0);
  const [dropIndex, setDropIndex] = useState<number>();
  const replace = (index: number, field: CustomField) => change(fields.map((f, i) => i === index ? field : f));
  const move = (from: number, to: number) => {
    if (disabled || from === to || to < 0 || to >= fields.length) return;
    const next = fields.slice();
    next.splice(to, 0, ...next.splice(from, 1));
    setOrder(current => current + 1);
    change(next);
  };
  const targetIndex = (x: number, y: number, list: Element) => {
    const row = document.elementFromPoint(x, y)?.closest<HTMLElement>('[data-custom-field-index]');
    return row?.parentElement === list ? Number(row.dataset.customFieldIndex) : undefined;
  };
  return <section className="vault-editor-section"><h3>Custom fields</h3>
    <div className="custom-field-list">
      {fields.map((field, index) => {
        const kind = fieldType(field), edit = (patch: Partial<CustomField>) => replace(index, { ...field, ...patch });
        if (kind === 'preserved') return <p className="fine" key={index}>{field.name || 'Unnamed field'} · Imported field preserved</p>;
        const label = field.name || 'Unnamed field';
        const key = kind === 'linked' ? options[field.linkedId!] : undefined;
        const linked = key === 'fullName' ? [values.firstName, values.middleName, values.lastName].filter(Boolean).join(' ') : key ? values[key] ?? '' : '';
        return <div className="custom-field-row" key={`${order}:${fields.length}:${index}`}
          data-custom-field-index={index} data-drop-target={dropIndex === index || undefined}>
          {kind === 'linked' ? <div className="custom-linked-field"><label>{label}<input readOnly value={key ? labelFor(key) : 'Imported link'}/></label>
            <button type="button" className="icon-button" disabled={disabled || !linked} aria-label={`Copy ${label}`}
              data-tooltip={`Copy ${label}`} onClick={() => copy(linked)}><Icon name="copy"/></button></div>
            : kind === 'boolean' ? <label className="vault-check"><input type="checkbox" checked={field.value?.toLowerCase() === 'true'} disabled={disabled}
              onChange={e => edit({ value: String(e.target.checked) })}/>{label}</label>
            : kind === 'hidden' ? <SecretInput label={label} value={field.value ?? ''} change={value => edit({ value })} disabled={disabled} copy={copy}
              generate={() => setGenerating(index)}/>
            : <label>{label}<input spellCheck={false} autoCorrect="off" value={field.value ?? ''} inputMode={kind === 'number' ? 'decimal' : 'text'} disabled={disabled} onChange={e => edit({ value: e.target.value })}/></label>}
          <button type="button" className="icon-button" disabled={disabled} aria-label={`Edit ${label}`}
            data-tooltip="Edit field" onClick={() => setEditing(index)}><Icon name="edit"/></button>
          <button type="button" className="icon-button custom-field-grip" disabled={disabled || fields.length < 2}
            aria-label={`Reorder ${label}. Drag or use Up and Down arrow keys.`} data-tooltip="Reorder field"
            onPointerDown={event => {
              if (event.button !== 0) return;
              event.currentTarget.setPointerCapture(event.pointerId);
              setDropIndex(index);
            }}
            onPointerMove={event => {
              if (event.currentTarget.hasPointerCapture(event.pointerId)) {
                setDropIndex(targetIndex(event.clientX, event.clientY, event.currentTarget.closest('.custom-field-list')!));
              }
            }}
            onLostPointerCapture={() => setDropIndex(undefined)}
            onPointerUp={event => {
              if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
              const target = targetIndex(event.clientX, event.clientY, event.currentTarget.closest('.custom-field-list')!);
              if (target !== undefined) move(index, target);
              setDropIndex(undefined);
            }}
            onKeyDown={event => {
              if (event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return;
              event.preventDefault();
              const target = index + (event.key === 'ArrowUp' ? -1 : 1);
              const list = event.currentTarget.closest('.custom-field-list')!;
              move(index, target);
              requestAnimationFrame(() => list.querySelector<HTMLButtonElement>(`[data-custom-field-index="${target}"] .custom-field-grip`)?.focus());
            }}><Icon name="grip"/></button>
        </div>;
      })}
      <button type="button" className="add-field-trigger" disabled={disabled || fields.length >= 128} onClick={() => setEditing('new')}><Icon name="plus"/>Add field</button>
    </div>
    {editing !== undefined && <FieldDialog field={editing === 'new' ? undefined : fields[editing]} links={options}
      close={() => setEditing(undefined)} save={field => {
        if (editing === 'new') change([...fields, field]);
        else replace(editing, field);
        setEditing(undefined);
      }} remove={editing === 'new' ? undefined : () => {
        change(fields.filter((_, index) => index !== editing));
        setEditing(undefined);
      }}/>}
    {generating !== undefined && <GeneratorDialog target="password" history={generatorHistory} close={() => setGenerating(undefined)}
      apply={value => {
        replace(generating, { ...fields[generating], value });
        setGenerating(undefined);
      }}/>}
  </section>;
}

export function ItemFields({ item, draft, change, disabled, copy, folders, generatorHistory }: Common & {
  item?: ImportedItem; draft: ItemDraft; change: (draft: ItemDraft) => void; folders: Folder[];
  generatorHistory: (action: HistoryAction) => Promise<HistoryEntry[]>;
}) {
  const type = itemType(item);
  const [generator, setGenerator] = useState<GeneratorTarget>();
  const usernameId = useId();
  return <div className="vault-editor">
    <label>Item name<input value={draft.name} disabled={disabled} maxLength={256} onChange={e => change({ ...draft, name: e.target.value })}/></label>
    <div className="choice-field"><span>Folder</span><ThemedSelect label="Folder"
      value={folders.some(folder => folder.key === draft.folder) ? draft.folder : ''} disabled={disabled}
      options={[{ value: '', label: 'No folder' }, ...folders.map(folder => ({ value: folder.key, label: folder.name }))]}
      onChange={folder => change({ ...draft, folder })}/></div>
    <label className="vault-check"><input type="checkbox" checked={draft.favorite} disabled={disabled} onChange={e => change({ ...draft, favorite: e.target.checked })}/>Favorite</label>
    {itemKeys(type).map(key => {
      const label = labelFor(key);
      const value = draft.values[key] ?? '', set = (value: string) => change({ ...draft, values: { ...draft.values, [key]: value } });
      if (type === 4 && key === 'title') return <div className="choice-field" key={key}><span>{label}</span>
        <ThemedSelect label={label} value={value} disabled={disabled} onChange={set}
          options={[{ value: '', label: 'Select a title' }, ...IDENTITY_TITLES.map(title => ({ value: title, label: title })),
            ...(value && !IDENTITY_TITLES.includes(value) ? [{ value, label: value }] : [])]}/></div>;
      if (type === 1 && key === 'username') return <div className="vault-field" key={key}>
        <label htmlFor={usernameId}>{label}</label>
        <div className="input-with-actions"><input id={usernameId} value={value} disabled={disabled}
          onChange={event => set(event.target.value)} autoComplete="off" spellCheck={false}/>
          <div className="field-actions"><GenerateButton kind="username" disabled={disabled} open={() => setGenerator('username')}/></div>
        </div></div>;
      return secretFields.has(key) ? <SecretInput key={key} label={label} value={value} change={set} disabled={disabled} copy={copy} multiline={key === 'privateKey'}
        generate={type === 1 && key === 'password' ? () => setGenerator('password') : undefined}/>
        : <label key={key}>{label}<input value={value} disabled={disabled} onChange={e => set(e.target.value)} spellCheck={false}/></label>;
    })}
    {type === 1 && <Websites urls={draft.urls} change={urls => change({ ...draft, urls })} disabled={disabled}/>}
    {type !== 2 && <label>Notes<textarea spellCheck={false} autoCorrect="off" value={draft.notes} disabled={disabled} onChange={e => change({ ...draft, notes: e.target.value })}/></label>}
    <CustomFields fields={draft.fields} change={fields => change({ ...draft, fields })} type={type} values={draft.values}
      disabled={disabled} copy={copy} generatorHistory={generatorHistory}/>
    {generator && <GeneratorDialog target={generator} history={generatorHistory} close={() => setGenerator(undefined)} apply={value => {
      change({ ...draft, values: { ...draft.values, [generator]: value } });
      setGenerator(undefined);
    }}/>}
  </div>;
}
