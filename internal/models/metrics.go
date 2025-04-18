package models

import "time"

// SystemMetrics representa as métricas do sistema coletadas
type SystemMetrics struct {
	IP        string       `json:"ip"`
	CPU       CPUMetrics   `json:"cpu"`
	Memory    MemMetrics   `json:"memory"`
	Disk      DiskMetrics  `json:"disk"`
	Docker    DockerStats  `json:"docker"`
	Timestamp time.Time    `json:"timestamp"`
}

// CPUMetrics representa as métricas de CPU
type CPUMetrics struct {
	Cores       int     `json:"cores"`
	UsedPercent float64 `json:"used_percent"`
	IdlePercent float64 `json:"idle_percent"`
}

// MemMetrics representa as métricas de memória
type MemMetrics struct {
	TotalGB         float64 `json:"total_gb"`
	UsedGB          float64 `json:"used_gb"`
	UsedPercent     float64 `json:"used_percent"`
	AvailableGB     float64 `json:"available_gb"`
	AvailablePercent float64 `json:"available_percent"`
}

// DiskMetrics representa as métricas de disco
type DiskMetrics struct {
	TotalGB     float64 `json:"total_gb"`
	UsedGB      float64 `json:"used_gb"`
	UsedPercent float64 `json:"used_percent"`
	AvailableGB float64 `json:"available_gb"`
	FreePercent float64 `json:"free_percent"`
}

// DockerStats representa as estatísticas do Docker
type DockerStats struct {
	Containers   int                `json:"containers"`
	Network      NetworkStats       `json:"network"`
	ContainerList []ContainerStats  `json:"container_list"`
}

// NetworkStats representa as estatísticas de rede
type NetworkStats struct {
	TotalRXBytes     int64  `json:"total_rx_bytes"`
	TotalTXBytes     int64  `json:"total_tx_bytes"`
	TotalRXFormatted string `json:"total_rx_formatted"`
	TotalTXFormatted string `json:"total_tx_formatted"`
	TotalBandwidth   string `json:"total_bandwidth"`
}

// ContainerStats representa as estatísticas de um container Docker
type ContainerStats struct {
	// Campos no formato antigo (camelCase)
	ID              string  `json:"ID"`
	Name            string  `json:"Name"`
	PIDs            string  `json:"PIDs"`
	NetIO           string  `json:"NetIO"`
	BlockIO         string  `json:"BlockIO"`
	CPUPerc         string  `json:"CPUPerc"`
	MemPerc         string  `json:"MemPerc"`
	MemUsage        string  `json:"MemUsage"`
	Container       string  `json:"Container"`
	NetIO_RX_Bytes  float64 `json:"NetIO_RX_Bytes"`
	NetIO_TX_Bytes  float64 `json:"NetIO_TX_Bytes"`
	NetIO_RX_Formatted string `json:"NetIO_RX_Formatted"`
	NetIO_TX_Formatted string `json:"NetIO_TX_Formatted"`
	
	// Campos internos para processamento (não serializados)
	CPUPercent   float64 `json:"-"`
	MemPercent   float64 `json:"-"`
	PidsCount    int     `json:"-"`
	NetIORXBytes int64   `json:"-"`
	NetIOTXBytes int64   `json:"-"`
}
