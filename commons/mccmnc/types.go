// SPDX-License-Identifier: GPL-3.0-only

package mccmnc

type Entry struct {
	Prefix          int    `json:"prefix_e164"`
	Country         string `json:"Country"`
	Network         string `json:"Network Description"`
	MCCMNC          int    `json:"mccmnc_e212"`
	MCCMNCSecondary string `json:"mccmnc_secondary"`
}

type RawData struct {
	Lookup []Entry `json:"lookup"`
}

type LookupIndex struct {
	ByPrefix  map[string][]Entry
	ByMCCMNC  map[string][]Entry
	ByCountry map[string][]Entry
	ByNetwork map[string][]Entry
}
