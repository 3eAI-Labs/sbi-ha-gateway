// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	sbiclient "github.com/3eAI-Labs/sbi-ha-gateway-client"
	"github.com/3eAI-Labs/sbi-ha-gateway/internal/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMobilityHandler_RegisterAmf_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	h := handlers.NewMobilityHandler(logger, mockNats, 0)

	r := chi.NewRouter()
	h.RegisterRoutes(r)

	reg := sbiclient.Amf3GppAccessRegistration{
		AmfInstanceId: "amf-1",
		RatType:       "NR",
	}
	body, _ := json.Marshal(reg)

	mockNats.On("Request", mock.Anything, "5g.mobility.registration", mock.Anything, handlers.DefaultRequestTimeout).
		Return([]byte("{}"), nil)

	req := httptest.NewRequest(http.MethodPut, "/nudm-uecm/v1/imsi-12345/registrations/amf-3gpp-access", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	mockNats.AssertExpectations(t)
}

func TestMobilityHandler_UpdateAmf_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	h := handlers.NewMobilityHandler(logger, mockNats, 0)

	r := chi.NewRouter()
	h.RegisterRoutes(r)

	updates := map[string]interface{}{"purgeId": "p1"}
	body, _ := json.Marshal(updates)

	mockNats.On("Request", mock.Anything, "5g.mobility.registration", mock.Anything, handlers.DefaultRequestTimeout).
		Return([]byte("{}"), nil)

	req := httptest.NewRequest(http.MethodPatch, "/nudm-uecm/v1/imsi-12345/registrations/amf-3gpp-access", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	mockNats.AssertExpectations(t)
}

func TestMobilityHandler_RegisterAmf_InvalidJSON(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodPut, "/nudm-uecm/v1/imsi-123456789012345/registrations/amf-3gpp-access", bytes.NewBufferString("invalid"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMobilityHandler_RegisterAmf_NatsError(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte(nil), errors.New("err"))
	body, _ := json.Marshal(sbiclient.Amf3GppAccessRegistration{})
	req := httptest.NewRequest(http.MethodPut, "/nudm-uecm/v1/imsi-123456789012345/registrations/amf-3gpp-access", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
}

func TestMobilityHandler_UpdateAmf_InvalidJSON(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodPatch, "/nudm-uecm/v1/imsi-123456789012345/registrations/amf-3gpp-access", bytes.NewBufferString("invalid"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMobilityHandler_UpdateAmf_NatsError(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte(nil), errors.New("err"))
	req := httptest.NewRequest(http.MethodPatch, "/nudm-uecm/v1/imsi-123456789012345/registrations/amf-3gpp-access", bytes.NewBufferString("{}"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
}

func TestMobilityHandler_GetRegistration_NatsError(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte(nil), errors.New("err"))
	req := httptest.NewRequest(http.MethodGet, "/nudm-uecm/v1/imsi-123456789012345/registrations/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
}

func TestMobilityHandler_GetRegistration_InvalidResponse(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte("invalid"), nil)
	req := httptest.NewRequest(http.MethodGet, "/nudm-uecm/v1/imsi-123456789012345/registrations/", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- SMF (TS 29.503 §5.3.2.4) ---

func TestMobilityHandler_RegisterSmf_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	reg := sbiclient.SmfRegistration{
		SmfInstanceId: "smf-1",
		PduSessionId:  10,
		SingleNssai:   &sbiclient.Snssai{Sst: 1},
	}
	body, _ := json.Marshal(reg)
	mockNats.On("Request", mock.Anything, "5g.mobility.registration", mock.Anything, handlers.DefaultRequestTimeout).
		Return([]byte("{}"), nil)

	req := httptest.NewRequest(http.MethodPut, "/nudm-uecm/v1/imsi-123456789012345/registrations/smf-registrations/10", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	mockNats.AssertExpectations(t)
}

func TestMobilityHandler_UpdateSmf_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	mockNats.On("Request", mock.Anything, "5g.mobility.registration", mock.Anything, handlers.DefaultRequestTimeout).
		Return([]byte("{}"), nil)
	req := httptest.NewRequest(http.MethodPatch, "/nudm-uecm/v1/imsi-123456789012345/registrations/smf-registrations/7", bytes.NewBufferString(`{"dnn":"ims"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestMobilityHandler_DeregisterSmf_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	mockNats.On("Request", mock.Anything, "5g.mobility.registration", mock.Anything, handlers.DefaultRequestTimeout).
		Return([]byte("{}"), nil)
	req := httptest.NewRequest(http.MethodDelete, "/nudm-uecm/v1/imsi-123456789012345/registrations/smf-registrations/7", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestMobilityHandler_RegisterSmf_InvalidJSON(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodPut, "/nudm-uecm/v1/imsi-123456789012345/registrations/smf-registrations/1", bytes.NewBufferString("nope"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMobilityHandler_DeregisterSmf_NatsError(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte(nil), errors.New("err"))
	req := httptest.NewRequest(http.MethodDelete, "/nudm-uecm/v1/imsi-123456789012345/registrations/smf-registrations/1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
}

// --- SMSF (TS 29.503 §5.3.2.2) ---

func TestMobilityHandler_RegisterSmsf_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	body, _ := json.Marshal(sbiclient.SmsfRegistration{SmsfInstanceId: "smsf-1"})
	mockNats.On("Request", mock.Anything, "5g.mobility.registration", mock.Anything, handlers.DefaultRequestTimeout).
		Return([]byte("{}"), nil)

	req := httptest.NewRequest(http.MethodPut, "/nudm-uecm/v1/imsi-123456789012345/registrations/smsf-3gpp-access", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestMobilityHandler_DeregisterSmsf_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	mockNats.On("Request", mock.Anything, "5g.mobility.registration", mock.Anything, handlers.DefaultRequestTimeout).
		Return([]byte("{}"), nil)
	req := httptest.NewRequest(http.MethodDelete, "/nudm-uecm/v1/imsi-123456789012345/registrations/smsf-3gpp-access", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestMobilityHandler_RegisterSmsf_InvalidJSON(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewMobilityHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodPut, "/nudm-uecm/v1/imsi-123456789012345/registrations/smsf-3gpp-access", bytes.NewBufferString("nope"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TS 29.503 Table 6.2.3.1-1 has no DELETE on amf-3gpp-access and no PATCH on
// smsf-3gpp-access: they are not served, and nothing reaches NATS.
func TestMobilityHandler_MethodsNotInSpecification(t *testing.T) {
	mockNats := new(MockNatsClient)
	r := chi.NewRouter()
	handlers.NewMobilityHandler(nil, mockNats, 0).RegisterRoutes(r)
	for _, c := range []struct{ method, path string }{
		{http.MethodDelete, "/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access"},
		{http.MethodPatch, "/nudm-uecm/v1/imsi-001010000000001/registrations/smsf-3gpp-access"},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(c.method, c.path, bytes.NewBufferString(`{}`)))
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, "%s %s", c.method, c.path)
	}
	mockNats.AssertNotCalled(t, "Request")
}

// PUT (TS 29.503): 201 with the registration and its URI when the application created
// it, 200 with the registration when it replaced one.
func TestMobilityHandler_PutCreatedOrUpdated(t *testing.T) {
	for path, body := range map[string]string{
		"/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access":     `{"amfInstanceId":"nf-1"}`,
		"/nudm-uecm/v1/imsi-001010000000001/registrations/smf-registrations/5": `{"smfInstanceId":"nf-1","pduSessionId":5}`,
		"/nudm-uecm/v1/imsi-001010000000001/registrations/smsf-3gpp-access":    `{"smsfInstanceId":"nf-1"}`,
	} {
		for _, c := range []struct {
			reply    string
			status   int
			location string
		}{
			{`{}`, http.StatusCreated, "http://example.com" + path},
			{`{"updated":true}`, http.StatusOK, ""},
		} {
			mockNats := new(MockNatsClient)
			mockNats.On("Request", mock.Anything, "5g.mobility.registration", mock.Anything, mock.Anything).Return([]byte(c.reply), nil)
			r := chi.NewRouter()
			handlers.NewMobilityHandler(nil, mockNats, 0).RegisterRoutes(r)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, path, bytes.NewBufferString(body)))
			assert.Equal(t, c.status, w.Code, "PUT %s replying %s", path, c.reply)
			assert.Equal(t, c.location, w.Header().Get("Location"), "PUT %s replying %s", path, c.reply)
			assert.Contains(t, w.Body.String(), `"nf-1"`, "the registration is the body")
		}
	}
}

// Every Nudm_UECM GET reaches the application with the resource and query it names.
func TestMobilityHandler_Get(t *testing.T) {
	for _, c := range []struct {
		path string
		want sbiclient.MobilityQuery
	}{
		{"/nudm-uecm/v1/imsi-001010000000001/registrations?registration-dataset-names=AMF_3GPP,SMSF_3GPP",
			sbiclient.MobilityQuery{UeId: "imsi-001010000000001", Query: "registration-dataset-names=AMF_3GPP,SMSF_3GPP"}},
		{"/nudm-uecm/v1/msisdn-491711234567/registrations/amf-3gpp-access",
			sbiclient.MobilityQuery{UeId: "msisdn-491711234567", Resource: "amf-3gpp-access"}},
		{"/nudm-uecm/v1/imsi-001010000000001/registrations/smsf-3gpp-access",
			sbiclient.MobilityQuery{UeId: "imsi-001010000000001", Resource: "smsf-3gpp-access"}},
		{"/nudm-uecm/v1/imsi-001010000000001/registrations/smf-registrations?single-nssai=x",
			sbiclient.MobilityQuery{UeId: "imsi-001010000000001", Resource: "smf-registrations", Query: "single-nssai=x"}},
		{"/nudm-uecm/v1/imsi-001010000000001/registrations/smf-registrations/5",
			sbiclient.MobilityQuery{UeId: "imsi-001010000000001", Resource: "smf-registrations/5"}},
	} {
		mockNats := new(MockNatsClient)
		var sent []byte
		mockNats.On("Request", mock.Anything, "5g.mobility.query", mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { sent = args.Get(2).([]byte) }).
			Return([]byte(`{"amfInstanceId":"amf-1"}`), nil)
		r := chi.NewRouter()
		handlers.NewMobilityHandler(nil, mockNats, 0).RegisterRoutes(r)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.path, nil))
		assert.Equal(t, http.StatusOK, w.Code, c.path)
		assert.JSONEq(t, `{"amfInstanceId":"amf-1"}`, w.Body.String(), c.path)
		var got sbiclient.MobilityQuery
		if assert.NoError(t, json.Unmarshal(sent, &got), c.path) {
			assert.Equal(t, c.want, got, c.path)
		}
	}
}

// The route's resource template is filled per request: a second GET on the same router
// names its own PDU session, not the first one's.
func TestMobilityHandler_GetSmfRegistrationPerRequest(t *testing.T) {
	mockNats := new(MockNatsClient)
	var sent []sbiclient.MobilityQuery
	mockNats.On("Request", mock.Anything, "5g.mobility.query", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			var q sbiclient.MobilityQuery
			_ = json.Unmarshal(args.Get(2).([]byte), &q)
			sent = append(sent, q)
		}).
		Return([]byte(`{}`), nil)
	r := chi.NewRouter()
	handlers.NewMobilityHandler(nil, mockNats, 0).RegisterRoutes(r)
	for _, id := range []string{"5", "7"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nudm-uecm/v1/imsi-001010000000001/registrations/smf-registrations/"+id, nil))
		assert.Equal(t, http.StatusOK, w.Code)
	}
	if assert.Len(t, sent, 2) {
		assert.Equal(t, "smf-registrations/5", sent[0].Resource)
		assert.Equal(t, "smf-registrations/7", sent[1].Resource)
	}
}
