package logging

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"

	"github.com/jackby03/waffynx/internal/config"
)

var log zerolog.Logger

func Setup(cfg config.LoggingConfig, level string) {
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	zerolog.TimeFieldFormat = time.RFC3339Nano

	lvl := cfg.Level
	if level != "" {
		lvl = level
	}

	zLevel, err := zerolog.ParseLevel(lvl)
	if err != nil {
		zLevel = zerolog.InfoLevel
	}

	var output io.Writer = os.Stdout
	if cfg.Output == "stderr" {
		output = os.Stderr
	}

	if cfg.Format == "console" {
		output = zerolog.ConsoleWriter{Out: output, TimeFormat: time.RFC3339}
	}

	log = zerolog.New(output).Level(zLevel).With().Timestamp().Caller().Logger()
}

func Logger() *zerolog.Logger {
	return &log
}

func Debug() *zerolog.Event { return log.Debug() }
func Info() *zerolog.Event  { return log.Info() }
func Warn() *zerolog.Event  { return log.Warn() }
func Error() *zerolog.Event { return log.Error() }
func Fatal() *zerolog.Event { return log.Fatal() }
