import { Fragment, useCallback, useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { Icon, type IconName } from './Icon';

type Choice = { label: string; key?: string; action: () => void; icon?: IconName; selected?: boolean; danger?: boolean; divider?: boolean; section?: string };

export function Popup({ label, trigger, choices, disabled, className = '', align = 'end', showLabel = true, fit = false }: {
  label: string; trigger: ReactNode; choices: Choice[]; disabled?: boolean; className?: string;
  align?: 'start' | 'end'; showLabel?: boolean; fit?: boolean;
}) {
  const id = useId(), button = useRef<HTMLButtonElement>(null), panel = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const position = useCallback(() => {
    const target = panel.current, trigger = button.current;
    if (!target || !trigger) return;
    const rect = trigger.getBoundingClientRect();
    const viewportWidth = document.documentElement.clientWidth;
    const viewportHeight = window.innerHeight;
    if (target.matches(':popover-open') &&
      (rect.bottom <= 0 || rect.top >= viewportHeight || rect.right <= 0 || rect.left >= viewportWidth)) {
      target.hidePopover();
      return;
    }
    const width = Math.min(viewportWidth - 16, fit ? Math.max(rect.width, 150) : 210);
    const above = rect.top - 14, below = viewportHeight - rect.bottom - 14;
    const up = below < Math.min(240, choices.length * 39 + 16) && above > below;
    const left = align === 'end' ? rect.right - width : rect.left;
    target.style.width = width + 'px';
    target.style.left = Math.max(8, Math.min(left, viewportWidth - width - 8)) + 'px';
    target.style.top = up ? 'auto' : rect.bottom + 6 + 'px';
    target.style.bottom = up ? viewportHeight - rect.top + 6 + 'px' : 'auto';
    target.style.maxHeight = Math.max(40, up ? above : below) + 'px';
  }, [align, choices.length, fit]);
  useEffect(() => {
    if (!open) return;
    const onScroll = (event: Event) => {
      if (event.target instanceof Node && panel.current?.contains(event.target)) return;
      position();
    };
    position();
    window.addEventListener('scroll', onScroll, { capture: true, passive: true });
    window.addEventListener('resize', position);
    return () => {
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', position);
    };
  }, [open, position]);
  function keys(event: KeyboardEvent) {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    const options = Array.from(panel.current!.querySelectorAll('button'));
    const index = options.indexOf(document.activeElement as HTMLButtonElement);
    const target = event.key === 'Home' ? 0 : event.key === 'End' ? options.length - 1
      : event.key === 'ArrowUp' ? (index - 1 + options.length) % options.length : (index + 1) % options.length;
    event.preventDefault();
    options[target]?.focus();
  }
  return <>
    <button ref={button} type="button" className={className} aria-label={label} title={showLabel ? undefined : label}
      disabled={disabled} popoverTarget={id} onClick={position}>{trigger}</button>
    <div ref={panel} popover="auto" id={id} className="popup-panel" role="group" aria-label={label} onKeyDown={keys}
      onToggle={event => {
        setOpen(event.newState === 'open');
        if (event.newState === 'open') {
          const preferred = panel.current?.querySelector<HTMLButtonElement>('[aria-pressed="true"]') ?? panel.current?.querySelector('button');
          preferred?.focus();
        }
      }}>
      {choices.map(choice => <Fragment key={choice.key ?? choice.label}>
        {choice.section && <div className="popup-section-label">{choice.section}</div>}
        <button type="button" aria-pressed={choice.selected}
        className={`${choice.danger ? 'danger ' : ''}${choice.divider ? 'popup-divider' : ''}`}
        onClick={() => { panel.current?.hidePopover(); button.current?.focus({ preventScroll: true }); choice.action(); }}>
        {choice.icon && <Icon name={choice.icon}/>}<span>{choice.label}</span>
        {choice.selected && <Icon name="check"/>}
        </button>
      </Fragment>)}
    </div>
  </>;
}

export type SelectOption = { value: string; label: string; icon?: IconName; section?: string };
export function ThemedSelect({ label, value, options, onChange, disabled }: {
  label: string; value: string; options: SelectOption[]; onChange: (value: string) => void; disabled?: boolean;
}) {
  const selected = options.find(option => option.value === value);
  return <Popup label={label} disabled={disabled} align="start" fit className="select-trigger"
    trigger={<>{selected?.icon && <Icon name={selected.icon}/>}<span>{selected?.label ?? 'Select'}</span><Icon name="chevron"/></>}
    choices={options.map(option => ({
      key: option.value, label: option.label, icon: option.icon, section: option.section,
      selected: option.value === value, action: () => onChange(option.value),
    }))}/>;
}
