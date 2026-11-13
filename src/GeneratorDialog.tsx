import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { Icon } from './Icon';
import { Toast } from './Toast';
import { CHARACTER_SETS, generatePassphrase, generatePassword, generateUsername, PASSWORD_DEFAULTS, type GeneratedSecret } from './generator';
import type { HistoryAction, HistoryEntry } from './generator-history';
import { copyToClipboard, readClipboardTimeout } from './clipboard';

const GROUPS = [
  ['upper', 'A–Z'], ['lower', 'a–z'], ['digits', '0–9'], ['symbols', CHARACTER_SETS.symbols],
] as const;
export type GeneratorTarget = 'password' | 'username';

export function GeneratorDialog({ target = 'password', apply, close, history }: {
  target?: GeneratorTarget; apply?: (value: string) => void; close: () => void;
  history: (action: HistoryAction) => Promise<HistoryEntry[]>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const title = useId();
  const [mode, setMode] = useState<GeneratorTarget | 'passphrase'>(target);
  const [password, setPassword] = useState(PASSWORD_DEFAULTS);
  const [words, setWords] = useState({ count: 6, separator: '-', capitalize: false, includeNumber: false });
  const [result, setResult] = useState<GeneratedSecret>();
  const [error, setError] = useState('');
  const [copyState, setCopyState] = useState<{ message: string; failed?: boolean }>();
  const [revision, regenerate] = useState(0);
  const historyOpen = useRef(false);
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [historyError, setHistoryError] = useState('');
  const [revealed, setRevealed] = useState<string>();
  const standalone = !apply;
  const modes = standalone ? ['password', 'passphrase', 'username'] as const : ['password', 'passphrase'] as const;
  useLayoutEffect(() => {
    const element = dialog.current!;
    element.showModal();
    return () => element.close();
  }, []);
  useEffect(() => {
    setCopyState(undefined);
    try {
      const generated = mode === 'password' ? generatePassword(password) : mode === 'username' ? generateUsername(words) : generatePassphrase(words);
      setResult(generated);
      setError('');
      void history({ type: 'add', kind: mode, value: generated.value }).then(async () => {
        if (historyOpen.current) {
          const values = await history({ type: 'list' });
          if (historyOpen.current) setEntries(values);
        }
        setHistoryError('');
      }).catch(() => setHistoryError('Could not update generator history.'));
    } catch (reason) {
      setResult(undefined);
      setError(reason instanceof Error ? reason.message : 'Could not generate a value.');
    }
  }, [mode, password, words, revision, history]);

  return <dialog ref={dialog} className={`folder-dialog generator-dialog${standalone ? ' generator-standalone' : ''}`} aria-labelledby={title}
    onCancel={event => { event.preventDefault(); close(); }}>
    <div className="folder-dialog-heading"><h2 id={title}>Generator</h2>
      <button type="button" className="icon-button" aria-label="Close generator" onClick={close}><Icon name="close"/></button></div>
    <div className="generator-body">
      {(standalone || target === 'password') && <div className="generator-modes" role="group" aria-label="Generator type">
        {modes.map(value => <button key={value} type="button" aria-pressed={mode === value} onClick={() => setMode(value)}>
          {value === 'password' ? 'Password' : value === 'passphrase' ? 'Passphrase' : 'Username'}
        </button>)}
      </div>}
      <div className="generator-result">
        <output aria-label="Generated value">{result?.value}</output>
        <button type="button" className="icon-button" aria-label="Regenerate" data-tooltip="Regenerate" onClick={() => regenerate(value => value + 1)}><Icon name="refresh"/></button>
        <button type="button" className="icon-button" aria-label="Copy generated value" data-tooltip="Copy" disabled={!result}
          onClick={async () => {
            if (!result) return;
            setCopyState(undefined);
            try { await copyToClipboard(result.value, readClipboardTimeout()); setCopyState({ message: 'Copied.' }); }
            catch { setCopyState({ message: 'Could not copy.', failed: true }); }
          }}><Icon name="copy"/></button>
      </div>
      {mode === 'password' ? <fieldset className="generator-options"><legend>Options</legend>
        <div className="generator-length">
          <label>Length<input type="number" min={5} max={128} value={Number.isNaN(password.length) ? '' : password.length}
            onChange={event => setPassword({ ...password, length: event.target.valueAsNumber })}/></label>
          {standalone && <p className="fine">5 to 128 characters.</p>}
        </div>
        <div className="generator-characters">
          {standalone && <p className="generator-include">Include</p>}
          <div className="generator-checks">{GROUPS.map(([key, label]) =>
            <label className="vault-check" key={key}><input type="checkbox" checked={password[key]} onChange={event => setPassword({ ...password, [key]: event.target.checked })}/>{label}</label>)}</div>
          <div className="generator-numbers">
            <label>Minimum numbers<input type="number" min={0} max={128} value={Number.isNaN(password.minimumDigits) ? '' : password.minimumDigits}
              disabled={!password.digits} onChange={event => setPassword({ ...password, minimumDigits: event.target.valueAsNumber })}/></label>
            <label>Minimum symbols<input type="number" min={0} max={128} value={Number.isNaN(password.minimumSymbols) ? '' : password.minimumSymbols}
              disabled={!password.symbols} onChange={event => setPassword({ ...password, minimumSymbols: event.target.valueAsNumber })}/></label>
          </div>
          <label className="vault-check"><input type="checkbox" checked={password.avoidAmbiguous}
            onChange={event => setPassword({ ...password, avoidAmbiguous: event.target.checked })}/>Avoid ambiguous characters</label>
        </div>
        {result?.bits !== undefined && result.bits < 64 && <p className="warning">Use more characters or a broader character set for a stronger password.</p>}
      </fieldset> : <fieldset className="generator-options"><legend>Options</legend>
        {mode === 'passphrase' && <div className="generator-numbers">
          <label>Number of words<input type="number" min={3} max={20} value={Number.isNaN(words.count) ? '' : words.count}
            onChange={event => setWords({ ...words, count: event.target.valueAsNumber })}/></label>
          <label>Word separator<input maxLength={8} value={words.separator} onChange={event => setWords({ ...words, separator: event.target.value })}/></label>
        </div>}
        {mode === 'passphrase' && words.count < 6 && <p className="warning">Use six words or more for a stronger passphrase.</p>}
        <label className="vault-check"><input type="checkbox" checked={words.capitalize}
          onChange={event => setWords({ ...words, capitalize: event.target.checked })}/>Capitalize</label>
        <label className="vault-check"><input type="checkbox" checked={words.includeNumber}
          onChange={event => setWords({ ...words, includeNumber: event.target.checked })}/>Include a number</label>
      </fieldset>}
      <details className="generator-history" onToggle={event => {
        historyOpen.current = event.currentTarget.open;
        if (!historyOpen.current) { setEntries([]); setRevealed(undefined); return; }
        void history({ type: 'list' }).then(result => {
          if (historyOpen.current) setEntries(result);
          setHistoryError('');
        }).catch(() => setHistoryError('Could not open generator history.'));
      }}>
        <summary>Generator history<Icon name="chevron"/></summary>
        {entries.length === 0 ? <p className="fine">No generated values yet.</p> : <>
          <div className="generator-history-entries">{entries.map(entry => <div className="generator-history-entry" key={entry.id}>
            <span>{entry.kind} · <time dateTime={new Date(entry.at).toISOString()}>{new Date(entry.at).toLocaleString()}</time></span>
            <button type="button" onClick={() => setRevealed(revealed === entry.id ? undefined : entry.id)}>{revealed === entry.id ? 'Hide' : 'Show'}</button>
            {revealed === entry.id && <code>{entry.value}</code>}
          </div>)}</div>
          <button type="button" className="danger" onClick={() => {
            void history({ type: 'clear' }).then(() => {
              setEntries([]); setRevealed(undefined); setHistoryError('');
            }).catch(() => setHistoryError('Could not clear generator history.'));
          }}>Clear history</button>
        </>}
      </details>
    </div>
    <div className="button-row folder-dialog-actions">
      {apply && <button type="button" className="primary" disabled={!result} onClick={() => result && apply(result.value)}>Use this {mode}</button>}
      <button type="button" onClick={close}>{standalone ? 'Close' : 'Cancel'}</button>
    </div>
    {error || historyError ? <Toast key={error || historyError} message={error || historyError} kind="error"/>
      : copyState && <Toast key={copyState.message} message={copyState.message} kind={copyState.failed ? 'error' : 'status'}/>}
  </dialog>;
}
