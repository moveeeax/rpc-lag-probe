package analysis

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// HashObservation is one endpoint's answer to "what is the block hash at this
// exact height". Raw keeps the untouched provider payload so a divergence
// event carries its own proof.
type HashObservation struct {
	Endpoint string          `json:"endpoint"`
	Provider string          `json:"provider,omitempty"`
	Region   string          `json:"region"`
	Height   uint64          `json:"height"`
	Hash     string          `json:"hash,omitempty"`
	Raw      json.RawMessage `json:"raw,omitempty"`
	// ErrClass is set when the endpoint could not answer. Missing answers are
	// never divergence: an endpoint that has not reached the height, or has
	// pruned it, has not disagreed about anything.
	ErrClass string `json:"err_class,omitempty"`
	Err      string `json:"err,omitempty"`
}

// Answered reports whether the observation carries a usable hash.
func (o HashObservation) Answered() bool {
	return o.Hash != "" && (o.ErrClass == "" || o.ErrClass == "ok")
}

// HashCluster is the set of endpoints that agree on one hash.
type HashCluster struct {
	Hash      string          `json:"hash"`
	Endpoints []string        `json:"endpoints"`
	Regions   []string        `json:"regions"`
	Raw       json.RawMessage `json:"raw,omitempty"`
}

// DivergenceEvent records two or more endpoints reporting different hashes for
// the same finalised height.
type DivergenceEvent struct {
	DetectedAt   time.Time     `json:"detected_at"`
	Chain        string        `json:"chain"`
	Height       uint64        `json:"height"`
	Clusters     []HashCluster `json:"clusters"`
	MajorityHash string        `json:"majority_hash"`
	// Minority lists the endpoints that are not on the majority hash. When the
	// split is even there is no majority and every cluster beyond the first is
	// reported as minority.
	Minority []string `json:"minority_endpoints"`
	// Unanswered lists endpoints that could not be compared this round.
	Unanswered []string `json:"unanswered_endpoints,omitempty"`
}

// DetectDivergence clusters observations at one height by hash. It returns an
// event only when at least two endpoints answered and they do not agree.
//
// Callers are responsible for only passing heights that are far enough behind
// the head to be final; see FinalisedHeight. Comparing at the head would turn
// every ordinary reorg into a false positive.
func DetectDivergence(chain string, height uint64, obs []HashObservation, at time.Time) (*DivergenceEvent, bool) {
	byHash := map[string]*HashCluster{}
	var order []string
	var unanswered []string
	answered := 0

	for _, o := range obs {
		if !o.Answered() {
			unanswered = append(unanswered, o.Endpoint)
			continue
		}
		answered++
		h := strings.ToLower(o.Hash)
		c, ok := byHash[h]
		if !ok {
			c = &HashCluster{Hash: h, Raw: o.Raw}
			byHash[h] = c
			order = append(order, h)
		}
		c.Endpoints = append(c.Endpoints, o.Endpoint)
		if o.Region != "" && !contains(c.Regions, o.Region) {
			c.Regions = append(c.Regions, o.Region)
		}
	}

	if answered < 2 || len(byHash) < 2 {
		return nil, false
	}

	clusters := make([]HashCluster, 0, len(byHash))
	for _, h := range order {
		c := byHash[h]
		sort.Strings(c.Endpoints)
		sort.Strings(c.Regions)
		clusters = append(clusters, *c)
	}
	// Largest cluster first; ties broken by hash so output is deterministic.
	sort.SliceStable(clusters, func(i, j int) bool {
		if len(clusters[i].Endpoints) != len(clusters[j].Endpoints) {
			return len(clusters[i].Endpoints) > len(clusters[j].Endpoints)
		}
		return clusters[i].Hash < clusters[j].Hash
	})

	ev := &DivergenceEvent{
		DetectedAt: at.UTC(),
		Chain:      chain,
		Height:     height,
		Clusters:   clusters,
		Unanswered: unanswered,
	}
	// A majority exists only when the top cluster is strictly larger than the
	// runner-up. An even split names no winner: that is the honest reading.
	if len(clusters) >= 2 && len(clusters[0].Endpoints) > len(clusters[1].Endpoints) {
		ev.MajorityHash = clusters[0].Hash
	}
	for i, c := range clusters {
		if ev.MajorityHash != "" && i == 0 {
			continue
		}
		ev.Minority = append(ev.Minority, c.Endpoints...)
	}
	sort.Strings(ev.Minority)
	sort.Strings(ev.Unanswered)
	return ev, true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
