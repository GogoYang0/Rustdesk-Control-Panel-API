package clientbuild

import "errors"

var (
	ErrNotFound            = errors.New("client build resource not found")
	ErrInvalidInput        = errors.New("invalid client build input")
	ErrDuplicateName       = errors.New("client build profile name already exists")
	ErrConflict            = errors.New("client build state conflict")
	ErrDisabled            = errors.New("client build is not enabled")
	ErrServerNotReady      = errors.New("organization server is not deployed")
	ErrQuotaExceeded       = errors.New("client build quota exceeded")
	ErrProfileInUse        = errors.New("client build profile has active builds")
	ErrUnaudited           = errors.New("client build mutation requires an audit recorder")
	ErrTokenInvalid        = errors.New("invalid or expired bundle token")
	ErrArtifactUnavailable = errors.New("client build artifact is unavailable")
)
