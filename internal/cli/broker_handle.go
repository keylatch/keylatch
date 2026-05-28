package cli

import "github.com/keylatch/keylatch/internal/broker"

// brokerHandleFactory is the function CLI broker commands call to obtain a
// BrokerHandle. It defaults to broker.NewBrokerHandle(nil) which uses the
// in-process singleton.
//
// Tests override this variable to inject a specific BrokerImpl.
var brokerHandleFactory = func() broker.BrokerHandle {
	return broker.NewBrokerHandle(nil)
}
