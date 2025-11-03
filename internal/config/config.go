package config

import (
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type (
	App struct {
		Production bool `koanf:"production"`
	}

	MainDatabase struct {
		Users struct {
			Name string `koanf:"name"`
		} `koanf:"users"`

		Name     string `koanf:"name"`
		Host     string `koanf:"host"`
		Port     string `koanf:"port"`
		User     string `koanf:"user"`
		Password string `koanf:"password"`
	}

	TemporaryDatabase struct {
		TemporaryUsers struct {
			Name string `koanf:"name"`
		} `koanf:"temporary_users"`

		VerificationCodes struct {
			Name string `koanf:"name"`
			User string `koanf:"user"`
		} `koanf:"verification_codes"`

		RefreshTokens struct {
			Name string `koanf:"name"`
			User string `koanf:"user"`
		} `koanf:"refresh_tokens"`

		Blacklist struct {
			Name         string `koanf:"name"`
			AccessTokens string `koanf:"access_tokens"`
		} `koanf:"blacklist"`

		Host     string `koanf:"host"`
		Port     string `koanf:"port"`
		Password string `koanf:"password"`
	}

	Broker struct {
		Host     string `koanf:"host"`
		Port     string `koanf:"port"`
		User     string `koanf:"user"`
		Password string `koanf:"password"`
		VHost    string `koanf:"vhost"`
	}

	Server struct {
		Host string `koanf:"host"`
		Port string `koanf:"port"`
	}

	Auth struct {
		User struct {
			SaltLength int `koanf:"salt_length"`
		} `koanf:"user"`

		TemporaryUser struct {
			TTL time.Duration `koanf:"ttl"`
		} `koanf:"temporary_user"`

		VerificationCode struct {
			Length    int           `koanf:"length"`
			TTL       time.Duration `koanf:"ttl"`
			ResendTTL time.Duration `koanf:"resend_ttl"`
		} `koanf:"verification_code"`

		AccessToken struct {
			TTL time.Duration `koanf:"ttl"`
		} `koanf:"access_token"`

		RefreshToken struct {
			TTL time.Duration `koanf:"ttl"`
		} `koanf:"refresh_token"`
	}

	Config struct {
		App               App               `koanf:"app"`
		MainDatabase      MainDatabase      `koanf:"database"`
		TemporaryDatabase TemporaryDatabase `koanf:"temporary_database"`
		Broker            Broker            `koanf:"broker"`
		Server            Server            `koanf:"server"`
		Auth              Auth              `koanf:"auth"`
	}
)

var k = koanf.New(".")

func New() (*Config, error) {
	config := new(Config)

	if err := k.Load(file.Provider("configs/config.yaml"), yaml.Parser()); err != nil {
		return nil, err
	}

	if err := k.Load(env.Provider("", ".", cb), nil); err != nil {
		return nil, err
	}

	if err := k.Unmarshal("", config); err != nil {
		return nil, err
	}

	return config, nil
}

func cb(s string) string {
	if len(s) >= 10 && s[:9] == "TEMPORARY" {
		s = strings.Replace(s, "_", "$", 1)
	}

	s = strings.ToLower(strings.ReplaceAll(s, "_", "."))

	return strings.Replace(s, "$", "_", 1)
}
