import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

// ipcat-web badges: rounded-sm, 12px/500, tinted background from the severity/change tokens.
const badgeVariants = cva(
  'inline-flex items-center justify-center rounded-sm border border-transparent px-2 py-0.5 text-[12px] font-medium w-fit whitespace-nowrap shrink-0 gap-1 [&>svg]:size-3',
  {
    variants: {
      variant: {
        default: 'bg-chg-new-bg text-chg-new-fg',
        secondary: 'bg-muted text-muted-foreground',
        destructive: 'bg-sev-critical-bg text-sev-critical-fg',
        success: 'bg-chg-same-bg text-chg-same-fg',
        warning: 'bg-sev-medium-bg text-sev-medium-fg',
        outline: 'border-border text-foreground',
      },
    },
    defaultVariants: { variant: 'default' },
  },
)

type BadgeVariant = NonNullable<VariantProps<typeof badgeVariants>['variant']>

function Badge({ className, variant, ...props }: React.ComponentProps<'span'> & VariantProps<typeof badgeVariants>) {
  return <span data-slot="badge" className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants, type BadgeVariant }
