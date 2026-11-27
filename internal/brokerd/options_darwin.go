package brokerd

import "os"

func (o *Options) applyPlatform() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	o.applyMac(self, &Codesign{Run: ExecRunner{}, Stat: statFile})
	return nil
}
