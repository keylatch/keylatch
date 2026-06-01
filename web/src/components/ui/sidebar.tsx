import { cn } from '@/lib/utils'
import type { ComponentPropsWithoutRef } from 'react'

type DivProps = ComponentPropsWithoutRef<'div'>
type NavProps = ComponentPropsWithoutRef<'nav'>

export function Sidebar({ className, ...props }: NavProps) {
  return (
    <nav
      className={cn('flex h-full w-[220px] flex-col bg-sidebar border-r border-sidebar-border', className)}
      {...props}
    />
  )
}

export function SidebarHeader({ className, ...props }: DivProps) {
  return (
    <div
      className={cn('flex h-14 items-center px-4 border-b border-border', className)}
      {...props}
    />
  )
}

export function SidebarContent({ className, ...props }: DivProps) {
  return (
    <div className={cn('flex-1 overflow-y-auto py-2', className)} {...props} />
  )
}

export function SidebarGroup({ className, ...props }: DivProps) {
  return <div className={cn('px-2 py-1', className)} {...props} />
}

export function SidebarGroupLabel({ className, ...props }: DivProps) {
  return (
    <div
      className={cn('mb-1 px-2 py-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground', className)}
      {...props}
    />
  )
}

export function SidebarMenu({ className, ...props }: DivProps) {
  return <div className={cn('space-y-0.5', className)} {...props} />
}

export function SidebarMenuItem({ className, ...props }: DivProps) {
  return <div className={cn('', className)} {...props} />
}

export function SidebarFooter({ className, ...props }: DivProps) {
  return (
    <div
      className={cn('px-4 py-3 border-t border-border', className)}
      {...props}
    />
  )
}
