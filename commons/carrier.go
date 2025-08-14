// SPDX-License-Identifier: GPL-3.0-only

package commons

import (
	"os"
	"path/filepath"
	"qdroid-server/commons/mccmnc"
)

var MCCMNCIndex *mccmnc.LookupIndex

func InitMCCMNC() {
	entries, err := mccmnc.LoadJSON(filepath.Join(".", "mcc_mnc.json"))
	if err != nil {
		Logger.Fatalf("Failed to load MCC/MNC data: %v", err)
	}

	entryMap := make(map[int]mccmnc.Entry)
	for _, entry := range entries {
		entryMap[entry.Prefix] = entry
	}

	overwritePath := filepath.Join(".", "mcc_mnc_overwrite.json")
	if _, err := os.Stat(overwritePath); err == nil {
		overwriteEntries, err := mccmnc.LoadJSON(overwritePath)
		if err != nil {
			Logger.Printf("Warning: Failed to load MCC/MNC overwrite data: %v", err)
		} else {
			for _, entry := range overwriteEntries {
				entryMap[entry.Prefix] = entry
			}
			Logger.Printf("Loaded %d MCC/MNC overwrite entries", len(overwriteEntries))
		}
	}

	mergedEntries := make([]mccmnc.Entry, 0, len(entryMap))
	for _, entry := range entryMap {
		mergedEntries = append(mergedEntries, entry)
	}

	MCCMNCIndex = mccmnc.BuildIndex(mergedEntries)
	Logger.Printf("Loaded %d total MCC/MNC entries", len(mergedEntries))
}
