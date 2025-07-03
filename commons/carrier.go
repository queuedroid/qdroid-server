// SPDX-License-Identifier: GPL-3.0-only

package commons

import (
	"path/filepath"
	"qdroid-server/commons/mccmnc"
)

var MCCMNCIndex *mccmnc.LookupIndex

func InitMCCMNC() {
	entries, err := mccmnc.LoadJSON(filepath.Join(".", "mcc_mnc.json"))
	if err != nil {
		Logger.Fatalf("Failed to load MCC/MNC data: %v", err)
	}

	MCCMNCIndex = mccmnc.BuildIndex(entries)
	Logger.Printf("Loaded %d MCC/MNC entries", len(entries))
}
