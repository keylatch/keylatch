package broker

import "context"

// OnVaultLock implements vault.VaultLockSubscriber.
// Flushes cache synchronously — returns only after flush completes (FIND2-004).
func (b *BrokerImpl) OnVaultLock(_ context.Context) {
	b.locked.Store(true)
	b.cache.flush()
}

// OnVaultUnlock clears the locked flag so Exchange can proceed again.
func (b *BrokerImpl) OnVaultUnlock(_ context.Context) {
	b.locked.Store(false)
}
