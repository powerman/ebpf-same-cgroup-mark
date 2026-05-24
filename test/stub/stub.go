// Package stub provides a reflect-based method override queue for mock objects.
//
// Instead of one generic type per function signature, the internal mechanism
// uses a single queue of reflect-callable functions. Thin wrappers handle
// result extraction for common patterns:
//
//	StubE    — for methods returning (error)
//	StubRE   — for methods returning (R, error)
//	StubR    — for methods returning R
//	StubV    — for void methods (no return values)
//
// Usage in mock methods:
//
//	func (m *mockWorld) OsMkdirAll(path string, perm os.FileMode) error {
//	    return m.mkdirStub.Call(path, perm)
//	}
//
// Usage in tests:
//
//	t.World.mkdirStub.Fail(errWorldMkdir)         // return error
//	t.World.mkdirStub.Returns()                   // return nil (success)
//	t.World.mkdirStub.Default()                   // run default once
//	t.World.statStub.Returns(fi, nil)             // return (fi, nil)
//	t.World.statStub.Fail(errWorldBpftool)        // return (nil, err)
//	t.World.geteuidStub.Returns(1000)             // return 1000
package stub

import "reflect"

// ---------------------------------------------------------------------------
// Internal queue
// ---------------------------------------------------------------------------

type stubEntry struct {
	call func([]reflect.Value) []reflect.Value
}

type stub struct {
	queue   []stubEntry
	defCall func([]reflect.Value) []reflect.Value
}

func (s *stub) callNext(args []reflect.Value) []reflect.Value {
	e := s.queue[0]
	s.queue = s.queue[1:]
	return e.call(args)
}

func (s *stub) values(args ...any) []reflect.Value {
	r := make([]reflect.Value, len(args))
	for i, a := range args {
		r[i] = reflect.ValueOf(a)
	}
	return r
}

func (s *stub) len() int { return len(s.queue) }

// Default queues the default implementation for the next call.
func (s *stub) Default() { s.queue = append(s.queue, stubEntry{call: s.defCall}) }

func extractError(out []reflect.Value) error {
	if len(out) > 0 {
		if err, _ := out[len(out)-1].Interface().(error); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// StubE — for methods with signature f(args) error
// ---------------------------------------------------------------------------

// Err provides override queues for methods returning (error).
type Err struct{ stub }

// NewErr creates a StubE with the given default implementation.
// The def argument must be a function matching f(args) error.
func NewErr(def any) Err {
	return Err{stub: stub{defCall: reflect.ValueOf(def).Call}}
}

// Fail queues a handler that returns err and skips the default implementation.
func (s *Err) Fail(err error) {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value {
			return []reflect.Value{reflect.ValueOf(err)}
		},
	})
}

// Returns queues a handler that returns a nil error (success).
func (s *Err) Returns() {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value {
			return []reflect.Value{reflect.Zero(reflect.TypeFor[error]())}
		},
	})
}

// Call invokes the next queued handler with the given args,
// or falls back to the default implementation if the queue is empty.
func (s *Err) Call(args ...any) error {
	if s.len() > 0 {
		return extractError(s.callNext(s.values(args...)))
	}
	return extractError(s.defCall(s.values(args...)))
}

// ---------------------------------------------------------------------------
// StubRE — for methods with signature f(args) (R, error)
// ---------------------------------------------------------------------------

// ResErr provides override queues for methods returning (R, error).
type ResErr[R any] struct {
	stub
	resultZero reflect.Value
}

// NewResErr creates a StubRE with the given default implementation.
// The def argument must be a function matching f(args) (R, error).
func NewResErr[R any](def any) ResErr[R] {
	var z R
	return ResErr[R]{
		stub:       stub{defCall: reflect.ValueOf(def).Call},
		resultZero: reflect.ValueOf(&z).Elem(),
	}
}

// Fail queues a handler that returns (zero, err).
func (s *ResErr[R]) Fail(err error) {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value {
			return []reflect.Value{s.resultZero, reflect.ValueOf(err)}
		},
	})
}

// Returns queues a handler that returns the given values.
// It expects exactly 2 values: (result, error).
// A nil error is replaced with a nil error interface.
func (s *ResErr[R]) Returns(vals ...any) {
	if len(vals) != 2 {
		panic("StubRE.Returns expects exactly 2 values: (result, error)")
	}
	out := make([]reflect.Value, 2)
	for i, v := range vals {
		if v == nil {
			if i == 0 {
				out[i] = s.resultZero
			} else {
				out[i] = reflect.Zero(reflect.TypeFor[error]())
			}
		} else {
			out[i] = reflect.ValueOf(v)
		}
	}
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value { return out },
	})
}

// Call invokes the next queued handler with the given args,
// or falls back to the default implementation if the queue is empty.
func (s *ResErr[R]) Call(args ...any) (R, error) {
	var r R
	var out []reflect.Value
	if s.len() > 0 {
		out = s.callNext(s.values(args...))
	} else {
		out = s.defCall(s.values(args...))
	}
	if len(out) > 0 {
		r, _ = out[0].Interface().(R)
	}
	if len(out) > 1 {
		if err, _ := out[len(out)-1].Interface().(error); err != nil {
			return r, err
		}
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// StubR — for methods with signature f(args) R
// ---------------------------------------------------------------------------

// Res provides override queues for methods returning R.
type Res[R any] struct {
	stub
	resultZero reflect.Value
}

// NewRes creates a StubR with the given default implementation.
// The def argument must be a function matching f(args) R.
func NewRes[R any](def any) Res[R] {
	var z R
	return Res[R]{
		stub:       stub{defCall: reflect.ValueOf(def).Call},
		resultZero: reflect.ValueOf(&z).Elem(),
	}
}

// Returns queues a handler that returns v.
func (s *Res[R]) Returns(v R) {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value {
			return []reflect.Value{reflect.ValueOf(v)}
		},
	})
}

// Call invokes the next queued handler with the given args,
// or falls back to the default implementation if the queue is empty.
func (s *Res[R]) Call(args ...any) R {
	var r R
	if s.len() > 0 {
		out := s.callNext(s.values(args...))
		if len(out) > 0 {
			r, _ = out[0].Interface().(R)
		}
		return r
	}
	out := s.defCall(s.values(args...))
	if len(out) > 0 {
		r, _ = out[0].Interface().(R)
	}
	return r
}

// ---------------------------------------------------------------------------
// StubV — for void methods f(args)
// ---------------------------------------------------------------------------

// Void provides override queues for void methods.
type Void struct{ stub }

// NewVoid creates a StubV with the given default implementation.
// The def argument must be a function matching f(args).
func NewVoid(def any) *Void {
	return &Void{stub: stub{defCall: reflect.ValueOf(def).Call}}
}

// Returns queues a handler that does nothing (skips the default).
func (s *Void) Returns() {
	s.queue = append(s.queue, stubEntry{
		call: func(_ []reflect.Value) []reflect.Value { return nil },
	})
}

// Call invokes the next queued handler with the given args,
// or falls back to the default implementation if the queue is empty.
func (s *Void) Call(args ...any) {
	if s.len() > 0 {
		s.callNext(s.values(args...))
		return
	}
	s.defCall(s.values(args...))
}
