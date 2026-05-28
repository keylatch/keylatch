import type { ComponentPropsWithoutRef } from 'react'

type DivProps = ComponentPropsWithoutRef<'div'>
type HeadingProps = ComponentPropsWithoutRef<'h3'>
type ParagraphProps = ComponentPropsWithoutRef<'p'>

function cx(...classes: Array<string | false | undefined>) {
  return classes.filter(Boolean).join(' ')
}

export function Card({ className, ...props }: DivProps) {
  return <div className={cx('reui-card', className)} {...props} />
}

export function CardHeader({ className, ...props }: DivProps) {
  return <div className={cx('reui-card__header', className)} {...props} />
}

export function CardTitle({ className, ...props }: HeadingProps) {
  return <h3 className={cx('reui-card__title', className)} {...props} />
}

export function CardDescription({ className, ...props }: ParagraphProps) {
  return <p className={cx('reui-card__description', className)} {...props} />
}

export function CardContent({ className, ...props }: DivProps) {
  return <div className={cx('reui-card__content', className)} {...props} />
}

export function CardFooter({ className, ...props }: DivProps) {
  return <div className={cx('reui-card__footer', className)} {...props} />
}
