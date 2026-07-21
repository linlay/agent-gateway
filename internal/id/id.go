package id

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"time"
)

var encoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

func New(prefix string) string {
	var random [10]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(fmt.Errorf("generate random id: %w", err))
	}
	var timestamp [6]byte
	millis := uint64(time.Now().UnixMilli())
	for i := 5; i >= 0; i-- {
		timestamp[i] = byte(millis)
		millis >>= 8
	}
	raw := append(timestamp[:], random[:]...)
	value := strings.ToLower(encoding.EncodeToString(raw))
	prefix = strings.Trim(strings.ToLower(prefix), "_ ")
	if prefix == "" {
		return value
	}
	return prefix + "_" + value
}

func RandomToken(bytes int) string {
	if bytes < 16 {
		bytes = 16
	}
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		panic(fmt.Errorf("generate random token: %w", err))
	}
	return strings.ToLower(encoding.EncodeToString(raw))
}
