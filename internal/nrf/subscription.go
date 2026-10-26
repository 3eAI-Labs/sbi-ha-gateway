// Copyright 2026 3eAI Labs Ltd
// SPDX-License-Identifier: AGPL-3.0-only

package nrf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/nrf/NFMgmt"

	"github.com/3eAI-Labs/sbi-ha-gateway/internal/metrics"
)

// The NFStatusSubscribe, its update and NFStatusUnSubscribe (TS 29.510 clauses 5.2.2.5 and
// 5.2.2.7) go through free5GC's generated NFManagement client, with the access tokens of the
// NFManagement API: its OpenAPI's top-level security, [{}, nnrf-nfm], covers /subscriptions.

// subscribe creates a subscription, as p, to the deregistration and the profile changes of
// the NF instance of type nfType with that ID, notified to callback, asked to last until
// validUntil. It returns the subscription's ID and the validity time the NRF assigned; zero
// when it gave none.
func (c *Client) subscribe(ctx context.Context, p Profile, nfType, instanceID, callback string, validUntil time.Time) (string, time.Time, error) {
	data := models.Nrf_NFMgmt_SubscriptionData{
		NfStatusNotificationUri: callback,
		ReqNfInstanceId:         p.InstanceID,
		ReqNfType:               models.Nrf_NFMgmt_NFType(p.Type),
		SubscrCond:              &models.Nrf_NFMgmt_SubscrCond{NfInstanceId: instanceID},
		ReqNotifEvents: []models.Nrf_NFMgmt_NotificationEventType{
			models.Nrf_NFMgmt_NotificationEventType_DEREGISTERED,
			models.Nrf_NFMgmt_NotificationEventType_PROFILE_CHANGED,
		},
		ValidityTime: &validUntil,
	}
	var rsp *NFMgmt.CreateSubscriptionResponse
	err := c.nfm(ctx, p, "subscribe", func(ctx context.Context, api *NFMgmt.APIClient) error {
		req := &NFMgmt.CreateSubscriptionRequest{}
		req.SetRequestBody(data)
		var err error
		rsp, err = api.SubscriptionsCollectionApi.CreateSubscription(ctx, req)
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	created := rsp.Nrf_NFMgmt_SubscriptionData
	id := ""
	if created != nil {
		id = created.SubscriptionId
	}
	if id == "" && rsp.Location != "" {
		// The resource's URI, {apiRoot}/nnrf-nfm/v1/subscriptions/{subscriptionId}.
		id = path.Base(rsp.Location)
	}
	if id == "" {
		return "", time.Time{}, errors.New("nrf subscribe: the answer names no subscription")
	}
	var granted time.Time
	if created != nil && created.ValidityTime != nil {
		granted = *created.ValidityTime
	}
	return id, granted, nil
}

// renew asks the NRF to keep the subscription until validUntil (clause 5.2.2.5.6) and returns
// the validity time it assigned: validUntil when it accepted it (204), else the one it
// answered with; zero when it gave none.
func (c *Client) renew(ctx context.Context, p Profile, id string, validUntil time.Time) (time.Time, error) {
	var rsp *NFMgmt.UpdateSubscriptionResponse
	err := c.nfm(ctx, p, "subscription_update", func(ctx context.Context, api *NFMgmt.APIClient) error {
		req := &NFMgmt.UpdateSubscriptionRequest{}
		req.SetSubscriptionID(id)
		req.SetRequestBody([]models.PatchItem{{
			Op:    models.PatchOperation_REPLACE,
			Path:  "/validityTime",
			Value: validUntil.UTC().Format(time.RFC3339),
		}})
		var err error
		rsp, err = api.SubscriptionIDDocumentApi.UpdateSubscription(ctx, req)
		return err
	})
	if err != nil {
		return time.Time{}, err
	}
	if s := rsp.Nrf_NFMgmt_SubscriptionData; s != nil {
		if s.ValidityTime != nil {
			return *s.ValidityTime, nil
		}
		return time.Time{}, nil
	}
	return validUntil, nil
}

// unsubscribe removes the subscription (clause 5.2.2.7). A 404 is no error: the NRF no
// longer has it.
func (c *Client) unsubscribe(ctx context.Context, p Profile, id string) error {
	err := c.nfm(ctx, p, "unsubscribe", func(ctx context.Context, api *NFMgmt.APIClient) error {
		req := &NFMgmt.RemoveSubscriptionRequest{}
		req.SetSubscriptionID(id)
		_, err := api.SubscriptionIDDocumentApi.RemoveSubscription(ctx, req)
		return err
	})
	if IsNotFound(err) {
		return nil
	}
	return err
}

// nfm calls the NFManagement API through free5GC's client, as p, with an access token once
// the NRF asked for one; a 401 is answered with a fresh token, once, as Client.do does. An
// answer other than the operation's success is a StatusError.
func (c *Client) nfm(ctx context.Context, p Profile, op string, call func(context.Context, *NFMgmt.APIClient) error) error {
	var token string
	var tokenErr error
	if c.oauth.Load() {
		// Without one the request still goes: the NRF may no longer ask for it.
		token, tokenErr = c.tokens.get(ctx, p, scopeNFManagement, nfTypeNRF, "")
	}
	err := c.nfmSend(ctx, p, op, token, call)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusUnauthorized {
		return err
	}
	c.oauth.Store(true)
	if tokenErr == nil {
		if token != "" {
			c.tokens.drop(p, scopeNFManagement, nfTypeNRF, "", token)
		}
		if token, tokenErr = c.tokens.get(ctx, p, scopeNFManagement, nfTypeNRF, ""); tokenErr == nil {
			return c.nfmSend(ctx, p, op, token, call)
		}
	}
	return fmt.Errorf("nrf %s: HTTP 401, and no %w", op, tokenErr)
}

func (c *Client) nfmSend(ctx context.Context, p Profile, op, token string, call func(context.Context, *NFMgmt.APIClient) error) error {
	status := 0 // the answer's, even when free5GC's client cannot decode its body
	cfg := NFMgmt.NewConfiguration()
	cfg.SetBasePath(c.root) // free5GC's client adds /nnrf-nfm/v1
	cfg.SetHTTPClient(c.tokens.http)
	cfg.SetUserAgent(userAgent(p))
	cfg.SetMetrics(func(_, _ string, s int, _ float64) { status = s })
	if token != "" {
		ctx = context.WithValue(ctx, openapi.ContextAccessToken, token)
	}
	err := call(ctx, NFMgmt.NewAPIClient(cfg))
	result := "error"
	if status != 0 {
		result = strconv.Itoa(status)
	}
	metrics.RecordNRFRequest(p.Type, op, result, err == nil)
	switch {
	case err != nil && status >= 300:
		var ae openapi.GenericOpenAPIError
		body := ""
		if errors.As(err, &ae) {
			body = string(ae.RawBody)
		}
		return response{status: status, body: []byte(body)}.err(op)
	case err != nil:
		return fmt.Errorf("nrf %s: %w", op, err)
	}
	return nil
}
