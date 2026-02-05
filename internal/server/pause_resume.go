package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// pauseScan pauses a running scan
func (s *Server) pauseScan(c *gin.Context) {
	scanID := c.Param("id")

	if err := s.scanMgr.PauseScan(scanID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"scan_id": scanID,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Scan paused successfully",
		"scan_id": scanID,
	})
}

// resumeScan resumes a paused scan
func (s *Server) resumeScan(c *gin.Context) {
	scanID := c.Param("id")

	if err := s.scanMgr.ResumeScan(scanID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"scan_id": scanID,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Scan resumed successfully",
		"scan_id": scanID,
	})
}
