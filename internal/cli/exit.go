package cli

// ExitError maps a failure to a Unix exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}

	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	return e.Err
}
