package cli

import "fmt"

type ExitCodeError struct {
	Code int
}

func (e *ExitCodeError) Error() string {
	return fmt.Sprintf("audited command exited with code %d", e.Code)
}
