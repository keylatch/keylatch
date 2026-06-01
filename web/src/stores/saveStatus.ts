import { create } from 'zustand'

type SavePhase = 'idle' | 'saving' | 'saved' | 'error'

interface SaveStatusState {
  phase: SavePhase
  setSaving: () => void
  setSaved: () => void
  setError: () => void
  reset: () => void
}

export const useSaveStatus = create<SaveStatusState>((set) => ({
  phase: 'idle',
  setSaving: () => set({ phase: 'saving' }),
  setSaved: () => set({ phase: 'saved' }),
  setError: () => set({ phase: 'error' }),
  reset: () => set({ phase: 'idle' }),
}))
