package lab

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func registerMeta(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", handleIndex)
	mux.HandleFunc("GET /catalog", handleCatalog)
}

func handleCatalog(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(Catalog()); err != nil {
		return
	}
}

func handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprint(w, "detour lab\n\n")

	for _, ep := range Catalog() {
		id := ep.ID
		if id == "" {
			id = "-"
		}

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", id, ep.Kind, ep.Path, ep.Description)
	}
}
