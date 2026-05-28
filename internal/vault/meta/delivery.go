package meta

// AppendDelivery appends dr to vm.LastDeliveries. If the resulting slice
// exceeds MaxDeliveryRecords, the oldest entry (index 0) is evicted before
// appending (FIFO cap).
func AppendDelivery(vm *VersionMeta, dr DeliveryRecord) {
	if len(vm.LastDeliveries) >= MaxDeliveryRecords {
		// Evict oldest entry.
		vm.LastDeliveries = vm.LastDeliveries[1:]
	}
	vm.LastDeliveries = append(vm.LastDeliveries, dr)
}
