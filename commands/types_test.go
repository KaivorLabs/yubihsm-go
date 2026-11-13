package commands

import "testing"

func TestOfficialMessageSizeLimits(t *testing.T) {
	// Independent numeric expectations from Yubico check_buffer_len and
	// SCP03 framing, not an identity derived from the constants under test.
	if MaxMessageLength != 3136 || MaxSessionMessageDataLength != 3120 || MaxCommandDataLength != 3116 {
		t.Fatalf("incorrect frame/ciphertext/inner limits: %d/%d/%d", MaxMessageLength, MaxSessionMessageDataLength, MaxCommandDataLength)
	}
}

func TestCapabilityPrimitiveFromSlice(t *testing.T) {
	got := CapabilityPrimitiveFromSlice([]uint64{CapabilityWrapData, CapabilityUnwrapData, CapabilityWrapData})
	want := CapabilityWrapData | CapabilityUnwrapData
	if got != want {
		t.Fatalf("capability primitive = 0x%x, want 0x%x", got, want)
	}
}
