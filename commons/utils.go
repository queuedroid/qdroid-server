// SPDX-License-Identifier: GPL-3.0-only

package commons

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var envLoaded = false

func LoadEnvFile() {
	if envLoaded {
		return
	}
	args := os.Args[1:]
	for i, arg := range args {
		if arg == "--env-file" && i+1 < len(args) {
			envFile := args[i+1]
			fmt.Printf("Loading environment variables from file: %s\n", envFile)
			file, err := os.Open(envFile)
			if err != nil {
				fmt.Printf("Failed to open env file: %s\n", err)
				return
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				os.Setenv(key, val)
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("Error reading env file: %s\n", err)
			}
			envLoaded = true
			return
		}
	}
	envLoaded = true
}

func GetEnv(key string) string {
	LoadEnvFile()
	return os.Getenv(key)
}
