package box

// Wire document types remain available to independent Go clients. The only
// HTTP implementation is the native Rust/Axum application under root api/.
const APIVersion = 1

type MetricsResponse struct {
	V       int     `json:"v"`
	From    int64   `json:"from"`
	To      int64   `json:"to"`
	Metrics Metrics `json:"metrics"`
}
type ReportResponse struct {
	V      int    `json:"v"`
	Report Report `json:"report"`
}

func (r ReportResponse) Schema() int { return r.V }

type HistoryResponse struct {
	V       int      `json:"v"`
	From    int64    `json:"from"`
	To      int64    `json:"to"`
	Samples []Sample `json:"samples"`
}

func (r HistoryResponse) Schema() int { return r.V }
