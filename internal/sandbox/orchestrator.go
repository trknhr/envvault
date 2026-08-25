package sandbox

import (
	"context"
	"errors"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
)

type Orchestrator struct {
	CleanupTimeout time.Duration
}

type RunRequest struct {
	Runtime        Runtime
	RuntimeChecked bool
	Spec           Spec
	Signals        <-chan Signal
	Resources      []Resource
	OnCreated      func(id string, level connection.SecurityLevel)
	OnStarted      func(id string, ports []PublishedPort)
}

type RunResult struct {
	SandboxID      string
	ExitCode       int
	Interrupted    bool
	SecurityLevel  connection.SecurityLevel
	PublishedPorts []PublishedPort
}

func (o Orchestrator) Run(ctx context.Context, request RunRequest) (result RunResult, runErr error) {
	result.SecurityLevel = request.Spec.SecurityLevel
	resourcesClosed := false
	closeResources := func() []error {
		if resourcesClosed {
			return nil
		}
		resourcesClosed = true
		var errs []error
		for i := len(request.Resources) - 1; i >= 0; i-- {
			resource := request.Resources[i]
			if resource == nil {
				continue
			}
			if err := o.cleanupCall(resource.Close); err != nil {
				errs = append(errs, err)
			}
		}
		return errs
	}
	defer func() {
		runErr = joinPrimary(runErr, closeResources()...)
	}()

	if request.Runtime == nil {
		return result, clerr.New(clerr.RuntimeUnavailable, "sandbox runtime is required")
	}
	if err := request.Spec.Validate(); err != nil {
		return result, err
	}
	if !request.RuntimeChecked {
		if err := request.Runtime.Check(ctx); err != nil {
			return result, err
		}
	}
	instance, err := request.Runtime.Create(ctx, request.Spec)
	if err != nil {
		return result, err
	}
	if instance == nil {
		return result, clerr.New(clerr.RuntimeUnavailable, "sandbox runtime returned no instance")
	}
	result.SandboxID = instance.ID()
	if result.SandboxID == "" {
		return result, joinPrimary(clerr.New(clerr.RuntimeUnavailable, "sandbox runtime returned an empty id"), o.cleanupCall(instance.Remove))
	}
	if request.OnCreated != nil {
		request.OnCreated(result.SandboxID, result.SecurityLevel)
	}

	remove := func() error {
		return o.cleanupCall(instance.Remove)
	}
	defer func() {
		runErr = joinPrimary(runErr, remove())
	}()
	stop := func() error {
		return o.cleanupCall(instance.Stop)
	}

	if err := instance.Start(ctx); err != nil {
		return result, joinPrimary(err, stop())
	}
	if len(request.Spec.PublishedPorts) > 0 {
		publisher, ok := instance.(PortPublisher)
		if !ok {
			return result, joinPrimary(clerr.New(clerr.RuntimeIncompatible, "sandbox runtime cannot report published ports"), stop())
		}
		ports, err := publisher.PublishedPorts(ctx)
		if err != nil {
			return result, joinPrimary(err, stop())
		}
		result.PublishedPorts = append([]PublishedPort(nil), ports...)
	}
	if request.OnStarted != nil {
		request.OnStarted(result.SandboxID, append([]PublishedPort(nil), result.PublishedPorts...))
	}

	waitCtx, cancelWait := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWait()
	waited := make(chan waitResult, 1)
	go func() {
		exit, err := instance.Wait(waitCtx)
		waited <- waitResult{exit: exit, err: err}
	}()

	signals := request.Signals
	for {
		select {
		case waitedResult := <-waited:
			result.ExitCode = waitedResult.exit.Code
			if waitedResult.err != nil {
				return result, joinPrimary(waitedResult.err, stop())
			}
			return result, nil
		case received, ok := <-signals:
			if !ok {
				signals = nil
				continue
			}
			if received != nil {
				result.Interrupted = true
			}
			stopErr := stop()
			waitedResult, waitErr := o.waitAfterStop(waitCtx, cancelWait, waited)
			result.ExitCode = waitedResult.exit.Code
			return result, joinPrimary(stopErr, waitErr, waitedResult.err)
		case <-ctx.Done():
			stopErr := stop()
			waitedResult, waitErr := o.waitAfterStop(waitCtx, cancelWait, waited)
			result.ExitCode = waitedResult.exit.Code
			return result, joinPrimary(ctx.Err(), stopErr, waitErr, waitedResult.err)
		}
	}
}

type waitResult struct {
	exit ExitResult
	err  error
}

func (o Orchestrator) waitAfterStop(waitCtx context.Context, cancel context.CancelFunc, waited <-chan waitResult) (waitResult, error) {
	timeout := o.timeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-waited:
		return result, nil
	case <-timer.C:
		cancel()
		return waitResult{}, clerr.New(clerr.CleanupFailed, "sandbox wait did not finish after stop")
	case <-waitCtx.Done():
		return waitResult{}, waitCtx.Err()
	}
}

func (o Orchestrator) cleanupCall(call func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout())
	defer cancel()
	return call(ctx)
}

func (o Orchestrator) timeout() time.Duration {
	if o.CleanupTimeout > 0 {
		return o.CleanupTimeout
	}
	return 5 * time.Second
}

func joinPrimary(primary error, additional ...error) error {
	errs := make([]error, 0, len(additional)+1)
	if primary != nil {
		errs = append(errs, primary)
	}
	for _, err := range additional {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
