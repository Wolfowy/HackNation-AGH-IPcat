import * as React from 'react'
import { cn } from '@/lib/utils'

// ipcat-web tables: a card-like frame, 13px medium headers, rows separated by borders, muted hover.
function Table({ className, ...props }: React.ComponentProps<'table'>) {
  return (
    <div data-slot="table-container" className="bg-card relative w-full overflow-x-auto rounded-lg border">
      <table data-slot="table" className={cn('w-full caption-bottom border-collapse', className)} {...props} />
    </div>
  )
}

function TableHeader({ className, ...props }: React.ComponentProps<'thead'>) {
  return <thead data-slot="table-header" className={cn(className)} {...props} />
}

function TableBody({ className, ...props }: React.ComponentProps<'tbody'>) {
  return <tbody data-slot="table-body" className={cn('[&_tr:last-child_td]:border-b-0', className)} {...props} />
}

function TableRow({ className, ...props }: React.ComponentProps<'tr'>) {
  return <tr data-slot="table-row" className={cn('hover:bg-muted data-[state=selected]:bg-muted', className)} {...props} />
}

function TableHead({ className, ...props }: React.ComponentProps<'th'>) {
  return (
    <th
      data-slot="table-head"
      className={cn('border-b px-3 py-2.5 text-left align-middle text-[13px] font-medium whitespace-nowrap', className)}
      {...props}
    />
  )
}

function TableCell({ className, ...props }: React.ComponentProps<'td'>) {
  return <td data-slot="table-cell" className={cn('border-b px-3 py-2.5 align-middle text-[13.5px]', className)} {...props} />
}

export { Table, TableHeader, TableBody, TableHead, TableRow, TableCell }
