package api

import "net/http"

type infoResponse struct {
	Demo      bool `json:"demo"`      // serving synthetic data, not a real cluster
	Metrics   bool `json:"metrics"`   // Prometheus is configured
	Audit     bool `json:"audit"`     // audit ingestion is enabled
	Processes bool `json:"processes"` // process monitoring is enabled
	Inventory bool `json:"inventory"` // map, workloads, nodes, storage and security routes exist
	Certs     bool `json:"certs"`     // the certificates route exists (cert-manager may still be absent)
}

// info tells the UI which features this server has, so it can hide empty ones.
func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, infoResponse{
		Demo: s.Demo, Metrics: s.Metrics != nil, Audit: s.Audit != nil, Processes: s.Processes != nil,
		Inventory: s.Inventory != nil, Certs: s.Certs != nil,
	})
}
