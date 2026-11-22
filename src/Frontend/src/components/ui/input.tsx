import * as React from 'react'
import { cn } from '@/lib/utils'

// ipcat-web fields: 34px, rounded-md, card background, 13px text, outline focus ring.
const fieldClass =
  'border-input bg-card text-foreground placeholder:text-muted-foreground selection:bg-primary selection:text-primary-foreground w-full min-w-0 rounded-md border px-2.5 text-[13px] outline-none disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-ring aria-invalid:border-destructive'

function Input({ className, type, ...props }: React.ComponentProps<'input'>) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(fieldClass, 'h-[34px] file:border-0 file:bg-transparent file:text-[13px] file:font-medium', className)}
      {...props}
    />
  )
}

function Textarea({ className, ...props }: React.ComponentProps<'textarea'>) {
  return <textarea data-slot="textarea" className={cn(fieldClass, 'min-h-20 py-2', className)} {...props} />
}

/** Native select styled like the inputs (accessible and testable without portals). */
function NativeSelect({ className, ...props }: React.ComponentProps<'select'>) {
  return <select data-slot="select" className={cn(fieldClass, 'h-[34px] cursor-pointer pr-8', className)} {...props} />
}

export { Input, Textarea, NativeSelect }
