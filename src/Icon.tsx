export type IconName = 'vault' | 'file' | 'settings' | 'lock' | 'arrow' | 'note' | 'check' | 'download'
  | 'plus' | 'search' | 'folder' | 'copy' | 'more' | 'trash' | 'star' | 'edit' | 'chevron' | 'close' | 'login' | 'card' | 'identity' | 'key' | 'refresh'
  | 'eye' | 'eye-off' | 'grip' | 'alert' | 'info';
const paths: Record<IconName, React.ReactNode> = {
  vault: <><rect x="4" y="3" width="16" height="18" rx="3"/><circle cx="12" cy="12" r="3"/><path d="M12 8v8M8 12h8M4 8H2M4 16H2"/></>,
  file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8M8 17h5"/></>,
  settings: <><path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3"/><circle cx="15" cy="17" r="3"/></>,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
  arrow: <path d="m9 5 7 7-7 7M16 12H3"/>,
  note: <><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></>,
  check: <path d="m5 12 4 4L19 6"/>,
  alert: <><circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 3h.01"/></>,
  info: <><circle cx="12" cy="12" r="9"/><path d="M12 17v-5m0-4h.01"/></>,
  download: <><path d="M12 3v12m-4-4 4 4 4-4M4 16v4h16v-4"/></>,
  plus: <path d="M12 5v14M5 12h14"/>,
  search: <><circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/></>,
  folder: <path d="M3 6h7l2 3h9v11H3z"/>,
  copy: <><rect x="8" y="3" width="12" height="15" rx="2"/><path d="M16 21H6a2 2 0 0 1-2-2V7"/></>,
  eye: <><path d="M2 12s3.6-6 10-6 10 6 10 6-3.6 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="2.5"/></>,
  'eye-off': <path d="m3 3 18 18M10 6.2A10 10 0 0 1 12 6c6.4 0 10 6 10 6a15 15 0 0 1-3 3.3m-3 2a10 10 0 0 1-4 .7c-6.4 0-10-6-10-6a15 15 0 0 1 4.5-4.3"/>,
  grip: <g fill="currentColor" stroke="none">{[6, 12, 18].map(y => <g key={y}><circle cx="9" cy={y} r="1.8"/><circle cx="15" cy={y} r="1.8"/></g>)}</g>,
  more: <g fill="currentColor" stroke="none"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></g>,
  trash: <path d="M4 6h16M9 6V3h6v3m3 0-1 15H7L6 6m4 4v7m4-7v7"/>,
  star: <path d="m12 3 2.7 5.6 6.2.9-4.5 4.4 1 6.2-5.4-3-5.5 3 1-6.2L3 9.5l6.2-.9Z"/>,
  edit: <path d="m5 16-1 4 4-1L20 7l-3-3L5 16Zm10-10 3 3"/>,
  chevron: <path d="m6 9 6 6 6-6"/>,
  close: <path d="m6 6 12 12M18 6 6 18"/>,
  login: <><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18M12 3c-5 5-5 13 0 18"/></>,
  card: <><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18M7 15h4"/></>,
  identity: <><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="10" r="2"/><path d="M6 16c0-4 6-4 6 0m3-6h3m-3 4h3"/></>,
  key: <path d="M14 8a4 4 0 1 1-4 4l-7 7v-4l6-6a4 4 0 0 1 5-1Z"/>,
  refresh: <path d="M20 8a8 8 0 0 0-14-2L3 9m0-5v5h5m-4 7a8 8 0 0 0 14 2l3-3m0 5v-5h-5"/>,
};
export const itemIcons: Record<number, IconName> = {
  1: 'login', 2: 'note', 3: 'card', 4: 'identity', 5: 'key', 6: 'card', 7: 'identity', 8: 'identity',
};
export function Icon({ name }: { name: IconName }) {
  return <svg className="icon" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
