package backend

import "errors"

var (
	userSecretDoesNotExistError = errors.New("user secret does not exist")
	userAlreadyExistError       = errors.New("user already exist")
	userDeletedError            = errors.New("user marked as deleted")
	userRestoreError            = errors.New("failed to restore user")
	userRevokeError             = errors.New("failed to revoke user")
	userDeleteError             = errors.New("failed to delete user")
	userIsNotActiveError        = errors.New("user is not active")
	passwordMismatchedError     = errors.New("password mismatched")
	tokenMismatchedError        = errors.New("token mismatched")
	checkAppError               = errors.New("failed to check 2FA app")
	registerAppError            = errors.New("failed to register 2FA app")
	authBackendDisabled         = errors.New("auth backend not enabled yet")
)
