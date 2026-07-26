package analysis

import (
	"encoding/json"
	"testing"
)

const (
	hashA = "0xaaaa000000000000000000000000000000000000000000000000000000000001"
	hashB = "0xbbbb000000000000000000000000000000000000000000000000000000000002"
	hashC = "0xcccc000000000000000000000000000000000000000000000000000000000003"
)

func obs(name, region, hash string) HashObservation {
	return HashObservation{
		Endpoint: name, Region: region, Height: 19999936, Hash: hash,
		Raw: json.RawMessage(`{"hash":"` + hash + `"}`),
	}
}

func TestDetectDivergenceAgreementIsNotAnEvent(t *testing.T) {
	in := []HashObservation{
		obs("a", "eu-central-1", hashA),
		obs("b", "us-east-1", hashA),
		obs("c", "ap-southeast-1", hashA),
	}
	if ev, found := DetectDivergence("ethereum", 19999936, in, at(0)); found {
		t.Fatalf("agreement reported as divergence: %+v", ev)
	}
}

func TestDetectDivergenceMajorityAndMinority(t *testing.T) {
	in := []HashObservation{
		obs("a", "eu-central-1", hashA),
		obs("b", "us-east-1", hashA),
		obs("c", "ap-southeast-1", hashB),
	}
	ev, found := DetectDivergence("ethereum", 19999936, in, at(0))
	if !found {
		t.Fatal("expected a divergence event")
	}
	if ev.MajorityHash != hashA {
		t.Errorf("majority = %s, want %s", ev.MajorityHash, hashA)
	}
	if len(ev.Minority) != 1 || ev.Minority[0] != "c" {
		t.Errorf("minority = %v, want [c]", ev.Minority)
	}
	if len(ev.Clusters) != 2 {
		t.Fatalf("clusters = %d, want 2", len(ev.Clusters))
	}
	if len(ev.Clusters[0].Endpoints) != 2 {
		t.Errorf("largest cluster is not first: %+v", ev.Clusters)
	}
	if len(ev.Clusters[0].Regions) != 2 {
		t.Errorf("cluster regions = %v, want both vantage points", ev.Clusters[0].Regions)
	}
	if len(ev.Clusters[0].Raw) == 0 {
		t.Error("raw payload missing; the event is not self-evidencing without it")
	}
	if ev.Chain != "ethereum" || ev.Height != 19999936 {
		t.Errorf("event identity wrong: %s %d", ev.Chain, ev.Height)
	}
}

func TestDetectDivergenceEvenSplitHasNoMajority(t *testing.T) {
	in := []HashObservation{
		obs("a", "eu-central-1", hashA),
		obs("b", "us-east-1", hashB),
	}
	ev, found := DetectDivergence("ethereum", 19999936, in, at(0))
	if !found {
		t.Fatal("expected a divergence event")
	}
	if ev.MajorityHash != "" {
		t.Errorf("an even split must not name a majority, got %s", ev.MajorityHash)
	}
	if len(ev.Minority) != 2 {
		t.Errorf("minority = %v, want both endpoints", ev.Minority)
	}
}

// An endpoint that has not reached the height, or has pruned it, has not
// disagreed with anyone. Counting that as divergence would make the headline
// finding of the audit worthless.
func TestDetectDivergenceIgnoresUnanswered(t *testing.T) {
	missing := obs("c", "ap-southeast-1", "")
	missing.ErrClass = "not_found"
	in := []HashObservation{
		obs("a", "eu-central-1", hashA),
		obs("b", "us-east-1", hashA),
		missing,
	}
	if _, found := DetectDivergence("ethereum", 19999936, in, at(0)); found {
		t.Fatal("a missing answer was treated as divergence")
	}

	in[1] = obs("b", "us-east-1", hashB)
	ev, found := DetectDivergence("ethereum", 19999936, in, at(0))
	if !found {
		t.Fatal("expected a divergence event")
	}
	if len(ev.Unanswered) != 1 || ev.Unanswered[0] != "c" {
		t.Errorf("unanswered = %v, want [c]", ev.Unanswered)
	}
}

func TestDetectDivergenceNeedsTwoAnswers(t *testing.T) {
	if _, found := DetectDivergence("ethereum", 1, []HashObservation{obs("a", "eu", hashA)}, at(0)); found {
		t.Fatal("a single answer cannot diverge from anything")
	}
	if _, found := DetectDivergence("ethereum", 1, nil, at(0)); found {
		t.Fatal("no observations cannot diverge")
	}
}

func TestDetectDivergenceIsCaseInsensitive(t *testing.T) {
	upper := obs("b", "us-east-1", "0xAAAA000000000000000000000000000000000000000000000000000000000001")
	in := []HashObservation{obs("a", "eu-central-1", hashA), upper}
	if ev, found := DetectDivergence("ethereum", 1, in, at(0)); found {
		t.Fatalf("hash case difference reported as divergence: %+v", ev)
	}
}

func TestDetectDivergenceThreeWaySplitIsDeterministic(t *testing.T) {
	in := []HashObservation{
		obs("a", "eu-central-1", hashC),
		obs("b", "us-east-1", hashB),
		obs("c", "ap-southeast-1", hashA),
	}
	first, _ := DetectDivergence("ethereum", 1, in, at(0))
	second, _ := DetectDivergence("ethereum", 1, []HashObservation{in[2], in[0], in[1]}, at(0))
	if len(first.Clusters) != 3 {
		t.Fatalf("clusters = %d, want 3", len(first.Clusters))
	}
	for i := range first.Clusters {
		if first.Clusters[i].Hash != second.Clusters[i].Hash {
			t.Fatalf("cluster order depends on input order: %v vs %v", first.Clusters, second.Clusters)
		}
	}
}
