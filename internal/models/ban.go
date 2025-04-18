package models

import (
	"time"
)

// IPAttempt representa uma tentativa de login de um IP
type IPAttempt struct {
	IP        string    `json:"ip"`
	Attempts  int       `json:"attempts"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Banned    bool      `json:"banned"`
	BanTime   time.Time `json:"ban_time,omitempty"`
}

// BannedIP representa um IP banido no banco de dados
type BannedIP struct {
	ID           string    `json:"id"`
	ServerID     string    `json:"servidor_id"`
	TitularID    string    `json:"titular"`
	IP           string    `json:"ip"`
	Reason       string    `json:"reason"`
	Source       string    `json:"source"` // 'manual' ou 'auto'
	Attempts     int       `json:"attempts"`
	FirstAttempt time.Time `json:"first_attempt"`
	LastAttempt  time.Time `json:"last_attempt"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
