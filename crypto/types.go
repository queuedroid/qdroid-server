// SPDX-License-Identifier: GPL-3.0-only

package crypto

type Crypto struct {
	ArgonTime     uint32
	ArgonMemory   uint32
	ArgonThreads  uint8
	ArgonKeyLen   uint32
	ArgonSaltLen  uint32
	EncryptionKey string
	HashingPepper string
}
