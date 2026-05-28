import type { ComponentPropsWithoutRef } from 'react'

type ButtonVariant = 'default' | 'secondary' | 'outline' | 'ghost' | 'primary-outline' | 'destructive'
type ButtonSize = 'sm' | 'default' | 'lg' | 'icon'

interface ButtonProps extends ComponentPropsWithoutRef<'button'> {
  variant?: ButtonVariant
  size?: ButtonSize
}

function cx(...classes: Array<string | false | undefined>) {
  return classes.filter(Boolean).join(' ')
}

export function Button({
  className,
  variant = 'default',
  size = 'default',
  type = 'button',
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      className={cx('reui-button', `reui-button--${variant}`, `reui-button--${size}`, className)}
      {...props}
    />
  )
}
