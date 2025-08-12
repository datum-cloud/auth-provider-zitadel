package httpactionsserver

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"

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

type EventType string

const (
	EventTypeUserHumanSelfRegistered EventType = "user.human.selfregistered"
	EventTypeUserHumanAdded          EventType = "user.human.added"
)

var SupportedUserCreationEvents = []EventType{EventTypeUserHumanSelfRegistered, EventTypeUserHumanAdded}

// createUserAccountRequest represents the expected JSON payload for the endpoint.
// It matches the structure provided by Zitadel actions.
type createUserAccountRequest struct {
	AggregateID   string    `json:"aggregateID"`
	AggregateType string    `json:"aggregateType"`
	ResourceOwner string    `json:"resourceOwner"`
	InstanceID    string    `json:"instanceID"`
	Version       string    `json:"version"`
	Sequence      int       `json:"sequence"`
	EventType     EventType `json:"event_type"`
	CreatedAt     string    `json:"created_at"`
	UserID        string    `json:"userID"`
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
	mux.HandleFunc("/v1/actions/customize-jwt", s.customizeJwtHandler)

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
	if !slices.Contains(SupportedUserCreationEvents, req.EventType) {
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

type CustomizeJwtHandlerResponse struct {
	SetUserMetadata []*Metadata    `json:"set_user_metadata,omitempty"`
	AppendClaims    []*AppendClaim `json:"append_claims,omitempty"`
}

// CustomizeJWTRequest is the PARTIAL request body for the customize-jwt endpoint.
// It is used to extract the necessary information from the request body.
type CustomizeJwtHandlerRequest struct {
	UserInfo struct {
		Sub string `json:"sub"`
	} `json:"userinfo"`
	Function string `json:"function"`
	User     struct {
		Username string `json:"username"`
		Human    *struct {
			Email string `json:"email"`
		} `json:"human,omitempty"`
	} `json:"user"`
}

type Metadata struct {
	Key   string `json:"key"`
	Value []byte `json:"value"`
}

type AppendClaim struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// customizeJwtHandler is a custom JWT handler that adds a custom email address claim to the JWT.
func (s *Server) customizeJwtHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context()).WithName("customizeJwtHandler")
	log.Info("Handling customize-jwt request", "method", r.Method, "remoteAddr", r.RemoteAddr)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error(err, "Failed to read request body")
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	log.V(1).Info("Successfully read request body")

	if err := s.validateSignature(bodyBytes, r.Header.Get("Zitadel-Signature"), s.config.SigningKey); err != nil {
		log.Error(err, "Signature validation failed")
		http.Error(w, fmt.Sprintf("signature validation failed: %v", err), http.StatusUnauthorized)
		return
	}
	log.V(1).Info("Request signature validated successfully")

	var request CustomizeJwtHandlerRequest
	if err := json.Unmarshal(bodyBytes, &request); err != nil {
		log.Error(err, "Failed to unmarshal request body")
		http.Error(w, "Failed to parse request body", http.StatusBadRequest)
		return
	}
	log.V(1).Info("Successfully unmarshaled request body", "function", request.Function, "userSub", request.UserInfo.Sub)

	if request.Function != "function/preuserinfo" && request.Function != "function/preaccesstoken" {
		log.Error(nil, "Unsupported function", "function", request.Function)
		http.Error(w, fmt.Sprintf("unsupported function: %s", request.Function), http.StatusBadRequest)
		return
	}
	log.V(1).Info("Validated function type", "function", request.Function)

	// Determine email based on user type
	var email string
	if request.User.Human != nil {
		email = request.User.Human.Email
		log.V(1).Info("Processing human user", "email", email)
	} else {
		email = request.User.Username
		log.V(1).Info("Processing machine user", "email", email)
	}

	resp := &CustomizeJwtHandlerResponse{
		SetUserMetadata: []*Metadata{
			{Key: "key", Value: []byte("value")},
		},
		AppendClaims: []*AppendClaim{
			{Key: "email", Value: email},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		log.Error(err, "Failed to marshal response")
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	log.Info("Successfully processed customize-jwt request", "userSub", request.UserInfo.Sub, "email", email)

	_, err = w.Write(data)
	if err != nil {
		log.Error(err, "Failed to write response")
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	log.Info("Successfully wrote response")
}
