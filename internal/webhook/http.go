package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	authenticationv1 "k8s.io/api/authentication/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Request struct {
	authenticationv1.TokenReview
}

type Response struct {
	authenticationv1.TokenReview
}

type HandlerFunc func(context.Context, Request) Response

type Handler interface {
	Handle(context.Context, Request) Response
}

// Handle calls f(ctx, req) allowing HandlerFunc to satisfy the Handler interface.
func (f HandlerFunc) Handle(ctx context.Context, req Request) Response {
	return f(ctx, req)
}

func (wh *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Create a logger scoped to this request.
	log := logf.FromContext(r.Context()).WithName("authentication-webhook-http")
	log.Info("Handling request", "method", r.Method, "remoteAddr", r.RemoteAddr)

	// Only POST is allowed as per the TokenReview API semantics.
	if r.Method != http.MethodPost {
		log.Error(nil, "Method not allowed", "method", r.Method)
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode the incoming TokenReview request.
	var review authenticationv1.TokenReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		log.Error(err, "Failed to decode TokenReview")
		http.Error(w, fmt.Sprintf("failed to decode TokenReview: %v", err), http.StatusBadRequest)
		return
	}

	reviewResponse := wh.Handler.Handle(r.Context(), Request{TokenReview: review})

	log.Info("Request processed",
		"authenticated", reviewResponse.TokenReview.Status.Authenticated,
		"username", reviewResponse.TokenReview.Status.User.Username,
		"uid", reviewResponse.TokenReview.Status.User.UID)

	wh.writeResponse(w, reviewResponse)
}

func (wh *Webhook) writeResponse(w http.ResponseWriter, resp Response) {
	log := logf.Log.WithName("authentication-webhook-http")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp.TokenReview); err != nil {
		log.Error(err, "Failed to encode response")
		http.Error(w, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
	log.V(1).Info("Response written", "authenticated", resp.TokenReview.Status.Authenticated)
}
