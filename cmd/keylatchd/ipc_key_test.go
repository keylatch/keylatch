package main

import (
	"bytes"
	"os"
	"testing"
)

func TestIPCKeyPipeRequiresCompleteKeyAndRejectsFiles(t *testing.T) {
	for _, size := range []int{12, 32} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		input := bytes.Repeat([]byte{0x42}, size)
		if _, err := writer.Write(input); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		key, err := readHMACKeyFromPipe(reader)
		if size == 32 {
			if err != nil || !bytes.Equal(key, input) {
				t.Fatalf("complete pipe key failed: %v", err)
			}
			clear(key)
		} else if err == nil || key != nil {
			t.Fatal("incomplete pipe key was accepted")
		}
		if _, err := reader.Stat(); err == nil {
			t.Fatal("key pipe remained open")
		}
	}
	file, err := os.CreateTemp(t.TempDir(), "key")
	if err != nil {
		t.Fatal(err)
	}
	if key, err := readHMACKeyFromPipe(file); err == nil || key != nil {
		t.Fatal("regular file was accepted as an inherited IPC pipe")
	}
}
