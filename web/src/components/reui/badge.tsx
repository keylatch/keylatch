import type { ComponentPropsWithoutRef } from 'react'

type BadgeVariant = 'default' | 'secondary' | 'success-light' | 'warning-light' | 'destructive-light' | 'primary-light'
type BadgeSize = 'sm' | 'default' | 'lg'

interface BadgeProps extends ComponentPropsWithoutRef<'span'> {
  variant?: BadgeVariant
  size?: BadgeSize
}

function cx(...classes: Array<string | false | undefined>) {
  return classes.filter(Boolean).join(' ')
}

export function Badge({
  className,
  variant = 'default',
  size = 'default',
  ...props
}: BadgeProps) {
  return <span className={cx('reui-badge', `reui-badge--${variant}`, `reui-badge--${size}`, className)} {...props} />
}
