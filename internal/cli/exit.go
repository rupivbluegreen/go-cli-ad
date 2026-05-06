package cli

const (
	ExitAuth    = 1 // invalid credentials / auth failure
	ExitNetwork = 2 // connection / network error
	ExitToken   = 3 // device code timeout / token expired
	ExitConfig  = 4 // config not found or invalid
	ExitQuery   = 5 // post-auth query error (LDAP search, Graph call)
)

// codedError lets a command return a specific exit code along with its error.
type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

func withCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}
