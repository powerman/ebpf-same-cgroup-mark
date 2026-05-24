package stub_test

import (
	"errors"
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/ebpf-same-cgroup-mark/test/stub"
)

var (
	errTest = errors.New("test error")
	errFail = errors.New("fail error")
)

func TestStubE(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("EmptyQueueUsesDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewErr(func() error { return nil })
		t.Nil(s.Call())
	})

	t.Run("FailReturnsError", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewErr(func() error { return nil })
		s.Fail(errFail)
		t.Err(s.Call(), errFail)
	})

	t.Run("ReturnsSucceeds", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewErr(func() error { return errFail })
		s.Returns()
		t.Nil(s.Call())
	})

	t.Run("DefaultAfterFailUsesDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewErr(func() error { return nil })
		s.Fail(errFail)
		s.Default()
		t.Err(s.Call(), errFail)
		t.Nil(s.Call())
	})

	t.Run("MultipleCallsConsumeQueue", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewErr(func() error { return nil })
		s.Fail(errFail)
		s.Fail(errFail)
		s.Fail(errFail)
		t.Err(s.Call(), errFail)
		t.Err(s.Call(), errFail)
		t.Err(s.Call(), errFail)
		t.Nil(s.Call())
		t.Nil(s.Call())
	})

	t.Run("DefaultThenFailThenDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewErr(func() error { return nil })
		s.Default()
		s.Fail(errFail)
		s.Default()
		t.Nil(s.Call())
		t.Err(s.Call(), errFail)
		t.Nil(s.Call())
	})

	t.Run("ArgsPassedToDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		var gotArg string
		s := stub.NewErr(func(v string) error {
			gotArg = v
			return nil
		})
		t.Nil(s.Call("hello"))
		t.Equal(gotArg, "hello")
	})
}

func TestStubRE(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("EmptyQueueUsesDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewResErr[string](func() (string, error) { return "hello", nil })
		r, err := s.Call()
		t.Nil(err)
		t.Equal(r, "hello")
	})

	t.Run("FailReturnsZeroAndError", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewResErr[string](func() (string, error) { return "hello", nil })
		s.Fail(errFail)
		r, err := s.Call()
		t.Err(err, errFail)
		t.Equal(r, "")
	})

	t.Run("ReturnsValues", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewResErr[string](func() (string, error) { return "hello", nil })
		s.Returns("world", nil)
		r, err := s.Call()
		t.Nil(err)
		t.Equal(r, "world")
	})

	t.Run("FailTwiceThenDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewResErr[string](func() (string, error) { return "hello", nil })
		s.Fail(errFail)
		s.Fail(errTest)
		r, err := s.Call()
		t.Err(err, errFail)
		t.Equal(r, "")
		r, err = s.Call()
		t.Err(err, errTest)
		t.Equal(r, "")
		r, err = s.Call()
		t.Nil(err)
		t.Equal(r, "hello")
	})

	t.Run("ReturnsError", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewResErr[string](func() (string, error) { return "hello", nil })
		s.Returns("", errFail)
		r, err := s.Call()
		t.Err(err, errFail)
		t.Equal(r, "")
	})

	t.Run("MixedFailReturnsDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewResErr[string](func() (string, error) { return "hello", nil })
		s.Fail(errFail)
		s.Returns("world", nil)
		s.Default()
		r, err := s.Call()
		t.Err(err, errFail)
		t.Equal(r, "")
		r, err = s.Call()
		t.Nil(err)
		t.Equal(r, "world")
		r, err = s.Call()
		t.Nil(err)
		t.Equal(r, "hello")
	})
}

func TestStubR(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("EmptyQueueUsesDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewRes[int](func() int { return 42 })
		t.Equal(s.Call(), 42)
	})

	t.Run("ReturnsValue", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewRes[int](func() int { return 42 })
		s.Returns(100)
		t.Equal(s.Call(), 100)
	})

	t.Run("ReturnsTwiceThenDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewRes[int](func() int { return 42 })
		s.Returns(100)
		s.Returns(200)
		t.Equal(s.Call(), 100)
		t.Equal(s.Call(), 200)
		t.Equal(s.Call(), 42)
	})

	t.Run("DefaultAfterReturns", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		s := stub.NewRes[int](func() int { return 42 })
		s.Returns(100)
		s.Default()
		t.Equal(s.Call(), 100)
		t.Equal(s.Call(), 42)
	})
}

func TestStubV(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	t.Run("EmptyQueueUsesDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		called := false
		s := stub.NewVoid(func() { called = true })
		s.Call()
		t.True(called)
	})

	t.Run("ReturnsSkipsDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		called := false
		s := stub.NewVoid(func() { called = true })
		s.Returns()
		s.Call()
		t.False(called)
	})

	t.Run("ReturnsThenDefault", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		var calls int
		s := stub.NewVoid(func() { calls++ })
		s.Returns()
		s.Default()
		s.Call()
		t.Equal(calls, 0)
		s.Call()
		t.Equal(calls, 1)
		s.Call()
		t.Equal(calls, 2)
	})
}
