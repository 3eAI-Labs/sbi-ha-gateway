// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// counterValue reads the current value of a Counter via the dto.Metric API.
// We avoid the prometheus/testutil package because it is not vendored and
// pulling it in would require a re-vendor cycle (see ADR-CI vendor playbook).
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatalf("counter.Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := g.Write(m); err != nil {
		t.Fatalf("gauge.Write: %v", err)
	}
	return m.GetGauge().GetValue()
}

// histogramSnapshot returns (sampleCount, sampleSum) for a Histogram.
func histogramSnapshot(t *testing.T, h prometheus.Histogram) (uint64, float64) {
	t.Helper()
	m := &dto.Metric{}
	if err := h.Write(m); err != nil {
		t.Fatalf("histogram.Write: %v", err)
	}
	return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
}

// histogramFromVec extracts the concrete Histogram for a label tuple. The
// type assertion is safe: HistogramVec children always implement Histogram.
func histogramFromVec(vec *prometheus.HistogramVec, lvs ...string) prometheus.Histogram {
	return vec.WithLabelValues(lvs...).(prometheus.Histogram)
}

// --- HTTP request metrics ---------------------------------------------------

func TestRecordRequest(t *testing.T) {
	const (
		method = "GET"
		path   = "/test/record-request"
		status = "200"
	)

	RecordRequest(method, path, status, 0.012)
	RecordRequest(method, path, status, 0.34)

	got := counterValue(t, RequestsTotal.WithLabelValues(method, path, status))
	if got != 2 {
		t.Errorf("RequestsTotal = %v, want 2", got)
	}

	count, sum := histogramSnapshot(t, histogramFromVec(RequestDuration, method, path))
	if count != 2 {
		t.Errorf("histogram sample count = %d, want 2", count)
	}
	const wantSum = 0.012 + 0.34
	if delta := sum - wantSum; delta < -1e-9 || delta > 1e-9 {
		t.Errorf("histogram sample sum = %v, want %v", sum, wantSum)
	}

	// Bucket boundaries are part of the dashboard contract. Any change here
	// forces a paired dashboard review (carrier-grade default).
	m := &dto.Metric{}
	_ = histogramFromVec(RequestDuration, method, path).Write(m)
	buckets := m.GetHistogram().GetBucket()
	want := []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}
	if len(buckets) != len(want) {
		t.Fatalf("bucket count = %d, want %d", len(buckets), len(want))
	}
	for i, b := range buckets {
		if b.GetUpperBound() != want[i] {
			t.Errorf("bucket[%d] = %v, want %v", i, b.GetUpperBound(), want[i])
		}
	}
}

// --- NATS metrics -----------------------------------------------------------

func TestRecordNatsRequest(t *testing.T) {
	const (
		subject = "test.subject.nats"
		status  = "ok"
	)
	RecordNatsRequest(subject, status, 0.05)
	RecordNatsRequest(subject, status, 0.10)

	got := counterValue(t, NatsRequestsTotal.WithLabelValues(subject, status))
	if got != 2 {
		t.Errorf("NatsRequestsTotal = %v, want 2", got)
	}
	count, _ := histogramSnapshot(t, histogramFromVec(NatsRequestDuration, subject))
	if count != 2 {
		t.Errorf("NatsRequestDuration count = %d, want 2", count)
	}

	// Bucket contract — NATS path tops out at 2s (no 5s bucket); see metrics.go.
	m := &dto.Metric{}
	_ = histogramFromVec(NatsRequestDuration, subject).Write(m)
	want := []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2}
	buckets := m.GetHistogram().GetBucket()
	if len(buckets) != len(want) {
		t.Fatalf("NatsRequestDuration bucket count = %d, want %d", len(buckets), len(want))
	}
	for i, b := range buckets {
		if b.GetUpperBound() != want[i] {
			t.Errorf("NatsRequestDuration bucket[%d] = %v, want %v", i, b.GetUpperBound(), want[i])
		}
	}
}

func TestSetNatsConnected(t *testing.T) {
	// This is a singleton gauge — read delta-style is not meaningful since
	// Set() overwrites. Just assert the two terminal states.
	SetNatsConnected(true)
	if v := gaugeValue(t, NatsConnectionStatus); v != 1 {
		t.Errorf("after SetNatsConnected(true) = %v, want 1", v)
	}
	SetNatsConnected(false)
	if v := gaugeValue(t, NatsConnectionStatus); v != 0 {
		t.Errorf("after SetNatsConnected(false) = %v, want 0", v)
	}
}

// --- Active request gauge ---------------------------------------------------

func TestActiveRequestsIncDec(t *testing.T) {
	// Singleton gauge — use delta semantics so we don't depend on order with
	// other tests. Restore on cleanup so we're a good neighbour.
	before := gaugeValue(t, ActiveRequests)
	t.Cleanup(func() {
		// Reset to whatever we found, regardless of test outcome.
		ActiveRequests.Set(before)
	})

	IncActiveRequests()
	IncActiveRequests()
	if got := gaugeValue(t, ActiveRequests) - before; got != 2 {
		t.Errorf("after 2x Inc, delta = %v, want 2", got)
	}
	DecActiveRequests()
	if got := gaugeValue(t, ActiveRequests) - before; got != 1 {
		t.Errorf("after Inc Inc Dec, delta = %v, want 1", got)
	}
}

// --- Error counter ----------------------------------------------------------

func TestRecordError(t *testing.T) {
	const (
		errType = "test.errtype"
		cause   = "test.cause"
	)
	RecordError(errType, cause)
	RecordError(errType, cause)
	RecordError(errType, cause)

	got := counterValue(t, ErrorsTotal.WithLabelValues(errType, cause))
	if got != 3 {
		t.Errorf("ErrorsTotal = %v, want 3", got)
	}
}

// --- Callback retry counter -------------------------------------------------

func TestRecordCallbackRetry(t *testing.T) {
	const status = "test.cb.retry"
	RecordCallbackRetry(status)

	if got := counterValue(t, CallbackRetries.WithLabelValues(status)); got != 1 {
		t.Errorf("CallbackRetries[%q] = %v, want 1", status, got)
	}
}

// --- OAuth validation -------------------------------------------------------

func TestRecordOAuthValidation(t *testing.T) {
	// Two distinct (result, reason) tuples to confirm labels route correctly.
	RecordOAuthValidation("ok", "")
	RecordOAuthValidation("ok", "")
	RecordOAuthValidation("fail", "expired")

	if got := counterValue(t, OAuthValidations.WithLabelValues("ok", "")); got != 2 {
		t.Errorf("OAuthValidations[ok,\"\"] = %v, want 2", got)
	}
	if got := counterValue(t, OAuthValidations.WithLabelValues("fail", "expired")); got != 1 {
		t.Errorf("OAuthValidations[fail,expired] = %v, want 1", got)
	}
}

// --- Outbound delivery (HA failover) ----------------------------------------

func TestRecordOutboundDelivery(t *testing.T) {
	const profile = "test.outbound.profile"
	RecordOutboundDelivery(profile, "ok")
	RecordOutboundDelivery(profile, "failover")
	RecordOutboundDelivery(profile, "ok")

	if got := counterValue(t, OutboundDeliveries.WithLabelValues(profile, "ok")); got != 2 {
		t.Errorf("OutboundDeliveries[ok] = %v, want 2", got)
	}
	if got := counterValue(t, OutboundDeliveries.WithLabelValues(profile, "failover")); got != 1 {
		t.Errorf("OutboundDeliveries[failover] = %v, want 1", got)
	}
}

func TestRecordOutboundPosition(t *testing.T) {
	// Singleton histogram — delta-style.
	beforeCount, beforeSum := histogramSnapshot(t, OutboundEndpointPosition)

	RecordOutboundPosition(0)
	RecordOutboundPosition(2)

	gotCount, gotSum := histogramSnapshot(t, OutboundEndpointPosition)
	if gotCount-beforeCount != 2 {
		t.Errorf("OutboundEndpointPosition observation delta = %d, want 2", gotCount-beforeCount)
	}
	if delta := (gotSum - beforeSum) - 2.0; delta < -1e-9 || delta > 1e-9 {
		t.Errorf("OutboundEndpointPosition sum delta = %v, want 2", gotSum-beforeSum)
	}

	// Bucket contract — endpoint position is integer-valued (failover order).
	m := &dto.Metric{}
	_ = OutboundEndpointPosition.Write(m)
	want := []float64{0, 1, 2, 3, 5, 10}
	buckets := m.GetHistogram().GetBucket()
	if len(buckets) != len(want) {
		t.Fatalf("OutboundEndpointPosition bucket count = %d, want %d", len(buckets), len(want))
	}
	for i, b := range buckets {
		if b.GetUpperBound() != want[i] {
			t.Errorf("OutboundEndpointPosition bucket[%d] = %v, want %v", i, b.GetUpperBound(), want[i])
		}
	}
}

// --- SMS (OTA) surfaces ----------------------------------------------------

func TestRecordOtaUecmLookup(t *testing.T) {
	// "not_found" is the *expected* default until UDM client lands — this
	// test pins that expectation so a future contributor can't quietly
	// rename the result string without updating dashboards.
	RecordOtaUecmLookup("not_found")
	RecordOtaUecmLookup("ok")
	RecordOtaUecmLookup("not_found")

	if got := counterValue(t, OtaUecmLookups.WithLabelValues("not_found")); got != 2 {
		t.Errorf("OtaUecmLookups[not_found] = %v, want 2", got)
	}
	if got := counterValue(t, OtaUecmLookups.WithLabelValues("ok")); got != 1 {
		t.Errorf("OtaUecmLookups[ok] = %v, want 1", got)
	}
}

func TestRecordOtaSmsfSend(t *testing.T) {
	for _, result := range []string{"delivered", "failed", "client_error", "bypassed", "not_implemented"} {
		RecordOtaSmsfSend(result)
		if got := counterValue(t, OtaSmsfSends.WithLabelValues(result)); got != 1 {
			t.Errorf("OtaSmsfSends[%s] = %v, want 1", result, got)
		}
	}
}

func TestRecordOtaDeliveryEvent(t *testing.T) {
	for _, status := range []string{"DELIVERED", "FAILED", "PENDING"} {
		RecordOtaDeliveryEvent(status)
		if got := counterValue(t, OtaDeliveryEventsPublished.WithLabelValues(status)); got != 1 {
			t.Errorf("OtaDeliveryEventsPublished[%s] = %v, want 1", status, got)
		}
	}
}

// --- Audit -----------------------------------------------------------------

func TestRecordAuditEvent(t *testing.T) {
	RecordAuditEvent("emitted")
	RecordAuditEvent("emitted")
	RecordAuditEvent("dropped")

	if got := counterValue(t, AuditEvents.WithLabelValues("emitted")); got != 2 {
		t.Errorf("AuditEvents[emitted] = %v, want 2", got)
	}
	if got := counterValue(t, AuditEvents.WithLabelValues("dropped")); got != 1 {
		t.Errorf("AuditEvents[dropped] = %v, want 1", got)
	}
}
