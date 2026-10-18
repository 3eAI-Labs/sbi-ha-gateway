// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package handlers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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

func TestDataHandler_HandleGenericRequest_Get_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	h := handlers.NewDataHandler(logger, mockNats, 0)

	r := chi.NewRouter()
	h.RegisterRoutes(r)

	natsResp := sbiclient.DataResponse{
		Payload: json.RawMessage(`{"data":"value"}`),
	}
	respBytes, _ := json.Marshal(natsResp)

	mockNats.On("Request", mock.Anything, "5g.data.query", mock.Anything, handlers.DefaultRequestTimeout).
		Return(respBytes, nil)

	req := httptest.NewRequest(http.MethodGet, "/nudr-dr/v1/subscription-data/imsi-123456789012345/authentication-data", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockNats.AssertExpectations(t)
}

func TestDataHandler_HandleGenericRequest_Post_Success(t *testing.T) {
	mockNats := new(MockNatsClient)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	h := handlers.NewDataHandler(logger, mockNats, 0)

	r := chi.NewRouter()
	h.RegisterRoutes(r)

	payload := map[string]interface{}{"new": "data"}
	body, _ := json.Marshal(payload)

	natsResp := sbiclient.DataResponse{
		Payload: body,
	}
	respBytes, _ := json.Marshal(natsResp)

	mockNats.On("Request", mock.Anything, "5g.data.update", mock.Anything, handlers.DefaultRequestTimeout).
		Return(respBytes, nil)

	req := httptest.NewRequest(http.MethodPost, "/nudr-dr/v1/subscription-data/imsi-123456789012345/authentication-data", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockNats.AssertExpectations(t)
}

func TestDataHandler_HandleGenericRequest_NatsError(t *testing.T) {
	mockNats := new(MockNatsClient)
	h := handlers.NewDataHandler(nil, mockNats, 0)
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	mockNats.On("Request", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]byte(nil), errors.New("err"))
	req := httptest.NewRequest(http.MethodGet, "/nudr-dr/v1/sub/imsi-123456789012345/auth", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
}

// Every data route tells the application which service and resource was called, and
// passes the query string.
func TestDataHandler_DataRequest(t *testing.T) {
	const (
		s     = "imsi-001010000000001"
		gpsi  = "msisdn-491711234567"
		group = "extgroupid-fleet@operator.example"
	)
	cases := []struct {
		method, path, subject string
		want                  sbiclient.DataRequest
	}{
		{"GET", "/nudr-dr/v1/subscription-data/" + s + "/authentication-data/authentication-subscription?supported-features=1", "5g.data.query",
			sbiclient.DataRequest{Service: "nudr-dr", UeId: s, DataSet: "subscription-data", Resource: "authentication-data/authentication-subscription", Method: "GET", Query: "supported-features=1"}},
		{"GET", "/nudm-sdm/v1/" + s + "/am-data?plmn-id=%7B%22mcc%22%3A%22001%22%7D", "5g.data.query",
			sbiclient.DataRequest{Service: "nudm-sdm", UeId: s, Resource: "am-data", Method: "GET", Query: "plmn-id=%7B%22mcc%22%3A%22001%22%7D"}},
		{"GET", "/nudm-sdm/v1/shared-data?shared-data-ids=a&shared-data-ids=b", "5g.data.query",
			sbiclient.DataRequest{Service: "nudm-sdm", Resource: "shared-data", Method: "GET", Query: "shared-data-ids=a&shared-data-ids=b"}},
		{"POST", "/nudm-sdm/v1/" + s + "/sdm-subscriptions", "5g.data.update",
			sbiclient.DataRequest{Service: "nudm-sdm", UeId: s, Resource: "sdm-subscriptions", Method: "POST", Payload: json.RawMessage(`{"a":1}`)}},
		{"DELETE", "/nudm-sdm/v1/" + s + "/sdm-subscriptions/9", "5g.data.update",
			sbiclient.DataRequest{Service: "nudm-sdm", UeId: s, Resource: "sdm-subscriptions/9", Method: "DELETE"}},
		{"GET", "/nudm-pp/v1/" + s + "/pp-data", "5g.data.query",
			sbiclient.DataRequest{Service: "nudm-pp", UeId: s, Resource: "pp-data", Method: "GET"}},
		{"PATCH", "/nudm-pp/v1/" + s + "/pp-data", "5g.data.update",
			sbiclient.DataRequest{Service: "nudm-pp", UeId: s, Resource: "pp-data", Method: "PATCH", Payload: json.RawMessage(`{"a":1}`)}},
		{"POST", "/nudm-ee/v1/" + gpsi + "/ee-subscriptions", "5g.data.update",
			sbiclient.DataRequest{Service: "nudm-ee", UeId: gpsi, Resource: "ee-subscriptions", Method: "POST", Payload: json.RawMessage(`{"a":1}`)}},
		{"DELETE", "/nudm-ee/v1/anyUE/ee-subscriptions/7", "5g.data.update",
			sbiclient.DataRequest{Service: "nudm-ee", UeId: "anyUE", Resource: "ee-subscriptions/7", Method: "DELETE"}},
		{"POST", "/nudm-ee/v1/" + group + "/ee-subscriptions", "5g.data.update",
			sbiclient.DataRequest{Service: "nudm-ee", UeId: group, Resource: "ee-subscriptions", Method: "POST", Payload: json.RawMessage(`{"a":1}`)}},
		{"GET", "/nudm-pp/v1/" + gpsi + "/pp-data", "5g.data.query",
			sbiclient.DataRequest{Service: "nudm-pp", UeId: gpsi, Resource: "pp-data", Method: "GET"}},
		// Resources that answered 404 before: the UE's document and shared data.
		{"GET", "/nudm-sdm/v1/" + s + "?dataset-names=AM,SMF_SEL", "5g.data.query",
			sbiclient.DataRequest{Service: "nudm-sdm", UeId: s, Method: "GET", Query: "dataset-names=AM,SMF_SEL"}},
		{"GET", "/nudr-dr/v1/subscription-data/" + gpsi + "?dataset-names=AM", "5g.data.query",
			sbiclient.DataRequest{Service: "nudr-dr", UeId: gpsi, DataSet: "subscription-data", Method: "GET", Query: "dataset-names=AM"}},
		{"GET", "/nudr-dr/v1/subscription-data/shared-data?shared-data-ids=a", "5g.data.query",
			sbiclient.DataRequest{Service: "nudr-dr", DataSet: "subscription-data", Resource: "shared-data", Method: "GET", Query: "shared-data-ids=a"}},
		{"GET", "/nudr-dr/v1/subscription-data/shared-data/a", "5g.data.query",
			sbiclient.DataRequest{Service: "nudr-dr", DataSet: "subscription-data", Resource: "shared-data/a", Method: "GET"}},
	}
	for _, c := range cases {
		mockNats := new(MockNatsClient)
		var sent []byte
		mockNats.On("Request", mock.Anything, c.subject, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { sent = args.Get(2).([]byte) }).
			Return([]byte(`{"payload":{}}`), nil)
		r := chi.NewRouter()
		handlers.NewDataHandler(nil, mockNats, 0).RegisterRoutes(r)

		var body io.Reader
		if c.want.Payload != nil {
			body = bytes.NewBufferString(`{"a":1}`)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(c.method, c.path, body))

		assert.Equal(t, http.StatusOK, w.Code, "%s %s", c.method, c.path)
		var got sbiclient.DataRequest
		if assert.NoError(t, json.Unmarshal(sent, &got), "%s %s", c.method, c.path) {
			assert.Equal(t, c.want, got, "%s %s", c.method, c.path)
		}
		mockNats.AssertExpectations(t)
	}
}
