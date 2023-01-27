package logger

import (
	"os"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func SetupLogger() {
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		file = short
		return file + ":" + strconv.Itoa(line)
	}
	log.Logger = log.With().Caller().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	var logLevel zerolog.Level
	logLevelEnv := os.Getenv("LOG_LEVEL")
	var err error
	if logLevelEnv != "" {
		logLevel, err = zerolog.ParseLevel(logLevelEnv)
	}
	if err != nil {
		log.Error().Err(err).Msg("couldn't parse LOG_LEVEL.")
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)
}
