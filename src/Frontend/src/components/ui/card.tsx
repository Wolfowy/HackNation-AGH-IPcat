import * as React from 'react'
import { cn } from '@/lib/utils'

// ipcat-web .box: 12px radius, border, no shadow; header row 15px/600; tables inside run edge to edge.
function Card({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card"
      className={cn('bg-card text-card-foreground flex flex-col overflow-hidden rounded-lg border', className)}
      {...props}
    />
  )
}

function CardHeader({ className, ...props }: React.ComponentProps<'div'>) {
  return <div data-slot="card-header" className={cn('flex flex-col gap-1 px-4 py-3.5', className)} {...props} />
}

function CardTitle({ className, ...props }: React.ComponentProps<'div'>) {
  return <div data-slot="card-title" className={cn('text-[15px] leading-tight font-semibold', className)} {...props} />
}

function CardDescription({ className, ...props }: React.ComponentProps<'div'>) {
  return <div data-slot="card-description" className={cn('text-muted-foreground text-[12.5px]', className)} {...props} />
}

function CardContent({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-content"
      className={cn(
        'px-4 pb-4 first:pt-4 has-[>[data-slot=table-container]:only-child]:p-0 [&>[data-slot=table-container]]:rounded-none [&>[data-slot=table-container]]:border-x-0 [&>[data-slot=table-container]]:border-b-0',
        className,
      )}
      {...props}
    />
  )
}

export { Card, CardHeader, CardTitle, CardDescription, CardContent }
