package domain

type EventType string

const (
	UserRegisterEvent      EventType = "user.register"
	UserLoginEvent         EventType = "user.login"
	UserResetPasswordEvent EventType = "user.reset_password"
)
