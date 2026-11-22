// Searchable multi-select: chips for the selection, a filter box and an inline list (no portal, so it works inside dialogs).
import { useId, useMemo, useState, type KeyboardEvent, type ReactNode } from 'react'
import { X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'

/** Network → option: name, searchable by zone, ranges and tags. */
export const networkOption = (n: { id: string; name: string; zone: string; ranges: string[]; tags: string[] }): MultiSelectOption => ({
  value: n.id,
  label: n.name,
  detail: [n.zone, n.ranges.join(', '), ...n.tags.map((t) => `#${t}`)].join(' · '),
})

export interface MultiSelectOption {
  value: string
  label: string
  /** Secondary text, also searched (e.g. zone, ranges, tags). */
  detail?: string
}

/** Options rendered at once; the rest is reached by refining the search. */
const MAX_VISIBLE = 50

export function MultiSelect({
  legend,
  options,
  value,
  onChange,
  error,
  placeholder = 'Search…',
  emptyText = 'No options available.',
}: {
  legend: ReactNode
  options: MultiSelectOption[]
  value: string[]
  onChange: (value: string[]) => void
  error?: string
  placeholder?: string
  emptyText?: string
}) {
  const id = useId()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)

  const byValue = useMemo(() => new Map(options.map((o) => [o.value, o])), [options])
  const matches = useMemo(() => {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean)
    return options.filter((o) => terms.every((t) => `${o.label} ${o.detail ?? ''}`.toLowerCase().includes(t)))
  }, [options, query])
  const visible = matches.slice(0, MAX_VISIBLE)
  const unselectedMatches = matches.filter((o) => !value.includes(o.value))

  const toggle = (v: string) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v])
  const optionId = (i: number) => `${id}-option-${i}`

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      setOpen(true)
      setActive((a) => Math.max(0, Math.min(visible.length - 1, a + (e.key === 'ArrowDown' ? 1 : -1))))
    } else if (e.key === 'Enter' && open && visible[active]) {
      e.preventDefault() // never submit the surrounding form from the search box
      toggle(visible[active].value)
    } else if (e.key === 'Escape' && open) {
      e.stopPropagation() // close the list, not the dialog
      setOpen(false)
    } else if (e.key === 'Backspace' && query === '' && value.length > 0) {
      onChange(value.slice(0, -1))
    }
  }

  return (
    <fieldset className="grid gap-1.5">
      <legend className="mb-1.5 text-sm font-medium">{legend}</legend>
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1" aria-label="Selected">
          {value.map((v) => (
            <Badge key={v} variant="secondary" className="gap-1 pr-1">
              {byValue.get(v)?.label ?? v}
              <button
                type="button"
                className="hover:bg-muted-foreground/20 rounded-sm"
                aria-label={`Remove ${byValue.get(v)?.label ?? v}`}
                onClick={() => toggle(v)}
              >
                <X className="size-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
      <Input
        role="combobox"
        aria-expanded={open}
        aria-controls={`${id}-list`}
        aria-activedescendant={open && visible[active] ? optionId(active) : undefined}
        aria-invalid={error ? true : undefined}
        aria-label={typeof legend === 'string' ? `Search ${legend.toLowerCase()}` : 'Search'}
        placeholder={options.length === 0 ? emptyText : placeholder}
        disabled={options.length === 0}
        value={query}
        onChange={(e) => {
          setQuery(e.target.value)
          setActive(0)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKeyDown}
      />
      {open && options.length > 0 && (
        <div className="rounded-md border">
          <div className="text-muted-foreground flex items-center justify-between border-b px-2 py-1 text-xs">
            <span>
              {matches.length} of {options.length}
              {matches.length > MAX_VISIBLE && ` (showing ${MAX_VISIBLE}; refine the search)`}
            </span>
            <span className="flex gap-2">
              {unselectedMatches.length > 0 && (
                <button type="button" className="hover:text-foreground underline" onClick={() => onChange([...value, ...unselectedMatches.map((o) => o.value)])}>
                  Select {unselectedMatches.length === 1 ? '1 match' : `all ${unselectedMatches.length} matches`}
                </button>
              )}
              <button type="button" className="hover:text-foreground underline" onClick={() => setOpen(false)}>
                Close
              </button>
            </span>
          </div>
          <ul id={`${id}-list`} role="listbox" aria-multiselectable="true" className="max-h-56 overflow-y-auto p-1">
            {visible.length === 0 && <li className="text-muted-foreground px-2 py-1.5 text-sm">No matches.</li>}
            {visible.map((o, i) => {
              const selected = value.includes(o.value)
              return (
                <li
                  key={o.value}
                  id={optionId(i)}
                  role="option"
                  aria-selected={selected}
                  className={cn('flex cursor-pointer items-start gap-2 rounded-sm px-2 py-1.5 text-sm', i === active && 'bg-accent')}
                  onMouseEnter={() => setActive(i)}
                  // mousedown keeps focus in the search box
                  onMouseDown={(e) => {
                    e.preventDefault()
                    toggle(o.value)
                  }}
                >
                  <input type="checkbox" tabIndex={-1} readOnly checked={selected} aria-hidden className="accent-primary mt-0.5 size-4" />
                  <span className="min-w-0">
                    <span className="block">{o.label}</span>
                    {o.detail && <span className="text-muted-foreground block truncate text-xs">{o.detail}</span>}
                  </span>
                </li>
              )
            })}
          </ul>
        </div>
      )}
      {error && (
        <p className="text-destructive text-xs" role="alert">
          {error}
        </p>
      )}
    </fieldset>
  )
}
