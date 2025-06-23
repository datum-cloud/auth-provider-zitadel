package httpactionsserver

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ServerConfig holds configuration for the HTTP actions server
// It mirrors the previous ActionsServerConfig that lived under cmd/actionsserver.
type ServerConfig struct {
	Addr                       string
	CertFile                   string
	KeyFile                    string
	DisableHTTP2               bool
	Kubeconfig                 string
	SigningKey                 string
	DisableSignatureValidation bool
}

type ValidateSignatureFunc func(payload []byte, header string, signingKey string) error

// NewServerConfig returns a config initialised with sensible defaults.
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		Addr:                       ":8082",
		DisableSignatureValidation: false,
	}
}

// Server represents the HTTP actions server with Kubernetes client
type Server struct {
	config            *ServerConfig
	k8sClient         client.Client
	validateSignature ValidateSignatureFunc
}

// NewServer creates a new HTTP actions server instance
func NewServer(cfg *ServerConfig, k8sClient client.Client, validateSignatureFunc ValidateSignatureFunc) *Server {
	log := logf.Log.WithName("httpactionsserver")
	log.Info("Creating new HTTP actions server", "addr", cfg.Addr, "tlsEnabled", cfg.CertFile != "" && cfg.KeyFile != "")
	return &Server{
		config:            cfg,
		k8sClient:         k8sClient,
		validateSignature: validateSignatureFunc,
	}
}

// createUserAccountRequest represents the expected JSON payload for the endpoint.
// It matches the structure provided by Zitadel actions.
type createUserAccountRequest struct {
	AggregateID   string `json:"aggregateID"`
	AggregateType string `json:"aggregateType"`
	ResourceOwner string `json:"resourceOwner"`
	InstanceID    string `json:"instanceID"`
	Version       string `json:"version"`
	Sequence      int    `json:"sequence"`
	EventType     string `json:"event_type"`
	CreatedAt     string `json:"created_at"`
	UserID        string `json:"userID"`
	EventPayload  struct {
		UserName          string `json:"userName"`
		FirstName         string `json:"firstName"`
		LastName          string `json:"lastName"`
		DisplayName       string `json:"displayName"`
		PreferredLanguage string `json:"preferredLanguage"`
		Email             string `json:"email"`
		EncodedHash       string `json:"encodedHash"`
		UserAgentID       string `json:"userAgentID"`
	} `json:"event_payload"`
}

// Start starts the HTTP(S) server
func (s *Server) Start() error {
	log := logf.Log.WithName("httpactionsserver")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/actions/create-user-account", s.createUserAccountHandler)

	srv := &http.Server{
		Addr:    s.config.Addr,
		Handler: mux,
	}

	// If TLS cert and key are provided, serve HTTPS
	if s.config.CertFile != "" && s.config.KeyFile != "" {
		log.Info("Configuring TLS",
			"certFile", s.config.CertFile,
			"keyFile", s.config.KeyFile,
			"disableHTTP2", s.config.DisableHTTP2)

		if s.config.DisableHTTP2 {
			// Disable HTTP/2 by restricting the advertised protocols to http/1.1
			srv.TLSConfig = &tls.Config{NextProtos: []string{"http/1.1"}}
			log.Info("HTTP/2 disabled")
		}
		log.Info("Starting HTTPS server", "addr", s.config.Addr)
		return srv.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile)
	}

	log.Info("Starting HTTP server", "addr", s.config.Addr)
	return srv.ListenAndServe()
}

// createUserAccountHandler handles the POST request to create a user account.
func (s *Server) createUserAccountHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("createUserAccountHandler")
	log.Info("Handling create-user-account request", "method", r.Method, "remoteAddr", r.RemoteAddr)

	if r.Method != http.MethodPost {
		log.Error(nil, "Method not allowed", "method", r.Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error(err, "Failed to read request body")
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.validateSignature(bodyBytes, r.Header.Get("Zitadel-Signature"), s.config.SigningKey); err != nil {
		log.Error(err, "Signature validation failed")
		http.Error(w, fmt.Sprintf("signature validation failed: %v", err), http.StatusUnauthorized)
		return
	}
	log.V(1).Info("Request signature validated successfully")

	var req createUserAccountRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		log.Error(err, "Failed to unmarshal request body")
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	log.V(1).Info("Request body unmarshaled successfully")

	// Validate event type
	if req.EventType != "user.human.selfregistered" {
		log.Error(nil, "Unsupported event type", "eventType", req.EventType)
		http.Error(w, fmt.Sprintf("unsupported event type: %s", req.EventType), http.StatusBadRequest)
		return
	}

	log.Info("Processing user account creation",
		"eventType", req.EventType,
		"email", req.EventPayload.Email,
		"zitadelUserId", req.UserID,
	)

	user := &iammiloapiscomv1alpha1.User{
		TypeMeta: metav1.TypeMeta{
			Kind:       "User",
			APIVersion: "iam.miloapis.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: req.AggregateID,
		},
		Spec: iammiloapiscomv1alpha1.UserSpec{
			Email:      req.EventPayload.Email,
			GivenName:  req.EventPayload.FirstName,
			FamilyName: req.EventPayload.LastName,
		},
	}

	if err := s.k8sClient.Create(r.Context(), user); err != nil {
		log.Error(err, "Failed to create user resource",
			"zitadelUserId", req.UserID,
			"email", req.EventPayload.Email,
		)
		http.Error(w, fmt.Sprintf("failed to create user resource: %v", err), http.StatusInternalServerError)
		return
	}

	log.Info("Successfully created user resource",
		"userName", req.UserID,
		"email", req.EventPayload.Email,
	)

	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte("created"))
}
