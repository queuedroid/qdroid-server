// SPDX-License-Identifier: GPL-3.0-only

package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v4"
)

func ServeStaticFile(c echo.Context) error {
	requestedPath := c.Param("*")

	cleanPath := filepath.Clean(requestedPath)
	if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid file path")
	}

	publicDir := "public"
	fullPath := filepath.Join(publicDir, cleanPath)

	absPublicDir, err := filepath.Abs(publicDir)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Unable to resolve public directory")
	}

	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid file path")
	}

	if !strings.HasPrefix(absFullPath, absPublicDir+string(os.PathSeparator)) &&
		absFullPath != absPublicDir {
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	fileInfo, err := os.Stat(absFullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Unable to access file")
	}

	if fileInfo.IsDir() {
		return echo.NewHTTPError(http.StatusForbidden, "Directory listing not allowed")
	}

	allowedExtensions := map[string]bool{
		".png":  true,
		".jpg":  true,
		".jpeg": true,
	}

	ext := strings.ToLower(filepath.Ext(absFullPath))
	if !allowedExtensions[ext] {
		return echo.NewHTTPError(http.StatusForbidden, "File type not allowed")
	}

	c.Response().Header().Set("X-Content-Type-Options", "nosniff")
	c.Response().Header().Set("X-Frame-Options", "DENY")
	c.Response().Header().Set("Cache-Control", "public, max-age=3600")

	return c.File(absFullPath)
}
