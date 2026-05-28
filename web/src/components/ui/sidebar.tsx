import type { ComponentPropsWithoutRef } from 'react'

type DivProps = ComponentPropsWithoutRef<'div'>
type NavProps = ComponentPropsWithoutRef<'nav'>

function cx(...classes: Array<string | false | undefined>) {
  return classes.filter(Boolean).join(' ')
}

export function Sidebar({ className, ...props }: NavProps) {
  return <nav className={cx('ui-sidebar', className)} {...props} />
}

export function SidebarHeader({ className, ...props }: DivProps) {
  return <div className={cx('ui-sidebar__header', className)} {...props} />
}

export function SidebarContent({ className, ...props }: DivProps) {
  return <div className={cx('ui-sidebar__content', className)} {...props} />
}

export function SidebarGroup({ className, ...props }: DivProps) {
  return <div className={cx('ui-sidebar__group', className)} {...props} />
}

export function SidebarGroupLabel({ className, ...props }: DivProps) {
  return <div className={cx('ui-sidebar__group-label', className)} {...props} />
}

export function SidebarMenu({ className, ...props }: DivProps) {
  return <div className={cx('ui-sidebar__menu', className)} {...props} />
}

export function SidebarMenuItem({ className, ...props }: DivProps) {
  return <div className={cx('ui-sidebar__menu-item', className)} {...props} />
}

export function SidebarFooter({ className, ...props }: DivProps) {
  return <div className={cx('ui-sidebar__footer', className)} {...props} />
}
