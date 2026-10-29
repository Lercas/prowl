package scan

import "strings"

// These hints carry only an explicit containing namespace, never neighboring object values.
type literalRole struct {
	ui       bool
	provider string
}

func (r literalRole) child(name string) literalRole {
	switch strings.ToLower(name) {
	case "labels", "placeholders", "translations", "i18n", "validation", "errors":
		r.ui = true
	case "assemblyai", "together", "linode", "mistral", "cohere", "deepgram", "elevenlabs", "vultr":
		r.provider = strings.ToLower(name)
	}
	return r
}

func (doc *literalDocument) binding(v *sourceLiteral) string {
	name := v.name
	if role := doc.roles[v.group]; role.provider != "" {
		switch strings.ToLower(name) {
		case "key", "api_key", "apikey", "api-key", "token", "api_token", "api-token":
			name = role.provider + "_" + name
		}
	}
	return name
}

func uiPasswordText(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "password", "passphrase", "пароль", "passwort", "contraseña", "senha",
		"confirm password", "new password", "current password", "enter password", "enter your password",
		"password is required", "password required", "invalid password", "incorrect password", "forgot password?",
		"подтвердите пароль", "новый пароль", "текущий пароль", "введите пароль", "неверный пароль", "пароль обязателен":
		return true
	}
	return false
}

func uiSiblingText(name, value string) bool {
	name, value = strings.ToLower(name), strings.ToLower(strings.TrimSpace(value))
	switch name {
	case "username":
		return value == "username" || value == "имя пользователя"
	case "email":
		return value == "email" || value == "электронная почта"
	case "login", "submit":
		return value == "sign in" || value == "log in" || value == "submit" || value == "войти"
	case "remember_me":
		return value == "remember me" || value == "запомнить меня"
	}
	return false
}
