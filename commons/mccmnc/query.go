// SPDX-License-Identifier: GPL-3.0-only

package mccmnc

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

func LoadJSON(filePath string) ([]Entry, error) {
	var raw RawData

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return raw.Lookup, nil
}

func BuildIndex(entries []Entry) *LookupIndex {
	idx := &LookupIndex{
		ByPrefix:  make(map[string][]Entry),
		ByMCCMNC:  make(map[string][]Entry),
		ByCountry: make(map[string][]Entry),
		ByNetwork: make(map[string][]Entry),
	}

	for _, e := range entries {
		idx.ByPrefix[strconv.Itoa(e.Prefix)] = append(idx.ByPrefix[strconv.Itoa(e.Prefix)], e)
		idx.ByMCCMNC[strconv.Itoa(e.MCCMNC)] = append(idx.ByMCCMNC[strconv.Itoa(e.MCCMNC)], e)
		idx.ByCountry[strings.ToLower(e.Country)] = append(idx.ByCountry[strings.ToLower(e.Country)], e)
		idx.ByNetwork[strings.ToLower(e.Network)] = append(idx.ByNetwork[strings.ToLower(e.Network)], e)
	}

	return idx
}

func (idx *LookupIndex) LookupByPrefix(prefix string) []Entry {
	return idx.ByPrefix[prefix]
}
