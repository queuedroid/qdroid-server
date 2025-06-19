// SPDX-License-Identifier: GPL-3.0-only

package crypto

import (
	"fmt"
	"qdroid-server/commons"
	"strconv"

	"github.com/alexedwards/argon2id"
)

func NewCrypto() *Crypto {
	var (
		argonTime    uint32
		argonMemory  uint32
		argonThreads uint8
		argonKeyLen  uint32
		argonSaltLen uint32
	)
	if v := commons.GetEnv("ARGON2_TIME", "1"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonTime = uint32(i)
		}
	}
	if v := commons.GetEnv("ARGON2_MEMORY", "65536"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonMemory = uint32(i)
		}
	}
	if v := commons.GetEnv("ARGON2_THREADS", "2"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonThreads = uint8(i)
		}
	}
	if v := commons.GetEnv("ARGON2_KEYLEN", "32"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonKeyLen = uint32(i)
		}
	}
	if v := commons.GetEnv("ARGON2_SALTLEN", "16"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			argonSaltLen = uint32(i)
		}
	}
	return &Crypto{
		ArgonTime:    argonTime,
		ArgonMemory:  argonMemory,
		ArgonThreads: argonThreads,
		ArgonKeyLen:  argonKeyLen,
		ArgonSaltLen: argonSaltLen,
	}
}

func (c *Crypto) HashPassword(password string) (string, error) {
	commons.Logger.Debug("Hashing password")
	params := &argon2id.Params{
		Memory:      c.ArgonMemory,
		Iterations:  c.ArgonTime,
		Parallelism: c.ArgonThreads,
		SaltLength:  c.ArgonSaltLen,
		KeyLength:   c.ArgonKeyLen,
	}
	hash, err := argon2id.CreateHash(password, params)
	if err != nil {
		return "", err
	}
	commons.Logger.Debug("Password hashed")
	return hash, nil
}

func (c *Crypto) VerifyPassword(password, encodedHash string) error {
	commons.Logger.Debug("Verifying password")
	match, err := argon2id.ComparePasswordAndHash(password, encodedHash)
	if err != nil {
		return err
	}
	if !match {
		return fmt.Errorf("password verification failed")
	}
	return nil
}
