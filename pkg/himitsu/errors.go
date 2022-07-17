package himitsu

import "errors"

const (
	// errSecretAlreadyExists is the error returned if a secret already exists.
	errSecretAlreadyExists = Error("secret already exists")

	// errSecretDoesNotExist is the error returned if a secret does not exist.
	errSecretDoesNotExist = Error("secret does not exist")

	// errSecretModified is the error returned when preconditions fail.
	errSecretModified = Error("secret modified between read and write")
)

// Error is an error from Berglas.
type Error string

// Error implements the error interface.
func (e Error) Error() string {
	return string(e)
}

// IsSecretAlreadyExistsErr returns true if the given error means that the
// secret already exists.
func IsSecretAlreadyExistsErr(err error) bool {
	return errors.Is(err, errSecretAlreadyExists)
}

// IsSecretDoesNotExistErr returns true if the given error means that the secret
// does not exist.
func IsSecretDoesNotExistErr(err error) bool {
	return errors.Is(err, errSecretDoesNotExist)
}

// IsSecretModifiedErr returns true if the given error means that the secret
// was modified (CAS failure).
func IsSecretModifiedErr(err error) bool {
	return errors.Is(err, errSecretModified)
}
