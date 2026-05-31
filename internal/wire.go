package internal

// WireApp wires the application with the real world adapter.
//
//nolint:iface // Intentionally returning a port interface for wire.go.
func WireApp(bpfObj []byte) App {
	return NewApp(RealWorld{}, bpfObj)
}
