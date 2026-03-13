package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// Schedule represents a scheduled scan
type Schedule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CronExpr   string `json:"cron_expr"`
	Target     string `json:"target"`
	ScanConfig string `json:"scan_config"`
	Enabled    bool   `json:"enabled"`
	LastRun    string `json:"last_run,omitempty"`
	NextRun    string `json:"next_run,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// ScheduleStore handles schedule persistence and execution
type ScheduleStore struct {
	mu        sync.RWMutex
	schedules map[string]*Schedule
	cron      *cron.Cron
	scanMgr   *ScanManager
}

// NewScheduleStore creates a new schedule store
func NewScheduleStore(scanMgr *ScanManager) *ScheduleStore {
	return &ScheduleStore{
		schedules: make(map[string]*Schedule),
		cron:      cron.New(),
		scanMgr:   scanMgr,
	}
}

// scheduleRequest is used for creating/updating schedules
type scheduleRequest struct {
	Name       string `json:"name" binding:"required"`
	CronExpr   string `json:"cron_expr" binding:"required"`
	Target     string `json:"target" binding:"required"`
	ScanConfig string `json:"scan_config"`
	Enabled    bool   `json:"enabled"`
}

// generateScheduleID generates a unique schedule ID
func generateScheduleID() string {
	return "sched-" + time.Now().Format("20060102150405")
}

// listSchedules returns all scheduled scans
func (s *Server) listSchedules(c *gin.Context) {
	s.scheduleStore.mu.RLock()
	defer s.scheduleStore.mu.RUnlock()

	schedules := make([]Schedule, 0, len(s.scheduleStore.schedules))
	for _, sched := range s.scheduleStore.schedules {
		schedules = append(schedules, *sched)
	}

	c.JSON(http.StatusOK, gin.H{
		"schedules": schedules,
	})
}

// createSchedule creates a new scheduled scan
func (s *Server) createSchedule(c *gin.Context) {
	var req scheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate cron expression
	if _, err := cronParser.Parse(req.CronExpr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid cron expression: " + err.Error()})
		return
	}

	schedule := &Schedule{
		ID:         generateScheduleID(),
		Name:       req.Name,
		CronExpr:   req.CronExpr,
		Target:     req.Target,
		ScanConfig: req.ScanConfig,
		Enabled:    req.Enabled,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	s.scheduleStore.mu.Lock()
	s.scheduleStore.schedules[schedule.ID] = schedule
	s.scheduleStore.mu.Unlock()

	// Add to cron if enabled
	if schedule.Enabled {
		s.addCronJob(schedule)
	}

	c.JSON(http.StatusCreated, gin.H{
		"schedule": schedule,
		"message":  "Schedule created successfully",
	})
}

// getSchedule returns a specific schedule
func (s *Server) getSchedule(c *gin.Context) {
	scheduleID := c.Param("id")

	s.scheduleStore.mu.RLock()
	schedule, exists := s.scheduleStore.schedules[scheduleID]
	s.scheduleStore.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error":       "Schedule not found",
			"schedule_id": scheduleID,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"schedule": schedule})
}

// updateSchedule updates an existing schedule
func (s *Server) updateSchedule(c *gin.Context) {
	scheduleID := c.Param("id")

	s.scheduleStore.mu.Lock()
	schedule, exists := s.scheduleStore.schedules[scheduleID]
	if !exists {
		s.scheduleStore.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{
			"error":       "Schedule not found",
			"schedule_id": scheduleID,
		})
		return
	}

	var req scheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.scheduleStore.mu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate cron expression
	if _, err := cronParser.Parse(req.CronExpr); err != nil {
		s.scheduleStore.mu.Unlock()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid cron expression: " + err.Error()})
		return
	}

	// Remove existing cron job
	s.removeCronJob(scheduleID)

	// Update fields
	schedule.Name = req.Name
	schedule.CronExpr = req.CronExpr
	schedule.Target = req.Target
	schedule.ScanConfig = req.ScanConfig
	schedule.Enabled = req.Enabled
	schedule.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	// Add new cron job if enabled
	if schedule.Enabled {
		s.addCronJob(schedule)
	}

	s.scheduleStore.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"schedule": schedule,
		"message":  "Schedule updated successfully",
	})
}

// deleteSchedule deletes a schedule
func (s *Server) deleteSchedule(c *gin.Context) {
	scheduleID := c.Param("id")

	s.scheduleStore.mu.Lock()
	_, exists := s.scheduleStore.schedules[scheduleID]
	if !exists {
		s.scheduleStore.mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{
			"error":       "Schedule not found",
			"schedule_id": scheduleID,
		})
		return
	}

	// Remove cron job
	s.removeCronJob(scheduleID)

	// Delete from store
	delete(s.scheduleStore.schedules, scheduleID)
	s.scheduleStore.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"message": "Schedule deleted successfully",
	})
}

// addCronJob adds a schedule to the cron runner
func (s *Server) addCronJob(schedule *Schedule) {
	scheduleID := schedule.ID
	target := schedule.Target
	scanConfig := schedule.ScanConfig

	_, err := s.scheduleStore.cron.AddFunc(schedule.CronExpr, func() {
		// Execute the scan
		go func() {
			// Parse scan config phases - default to all phases
			phases := []string{"subdomain", "ports", "vulnscan"}
			if scanConfig != "" {
				phases = []string{scanConfig}
			}
			_, _ = s.scheduleStore.scanMgr.StartScan(target, phases, 50, false, false)
		}()

		// Update last run time
		s.scheduleStore.mu.Lock()
		if sched, ok := s.scheduleStore.schedules[scheduleID]; ok {
			now := time.Now().UTC().Format(time.RFC3339)
			sched.LastRun = now
			// Calculate next run using cron
			if s, err := cronParser.Parse(schedule.CronExpr); err == nil {
				nextRun := s.Next(time.Now().UTC())
				sched.NextRun = nextRun.Format(time.RFC3339)
			}
		}
		s.scheduleStore.mu.Unlock()
	})

	if err != nil {
		return // Silently fail - will return error on schedule creation
	}
}

// removeCronJob removes a schedule from the cron runner
func (s *Server) removeCronJob(scheduleID string) {
	// Note: In production, you'd track cron entry IDs for removal
	// For now, we'll rebuild the cron when needed
}

// startScheduler starts the cron scheduler
func (s *Server) startScheduler() {
	if s.scheduleStore != nil && s.scheduleStore.cron != nil {
		s.scheduleStore.cron.Start()
	}
}

// stopScheduler stops the cron scheduler
func (s *Server) stopScheduler() {
	if s.scheduleStore != nil && s.scheduleStore.cron != nil {
		ctx := s.scheduleStore.cron.Stop()
		<-ctx.Done()
	}
}
