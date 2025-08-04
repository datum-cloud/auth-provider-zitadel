package webhook

import (
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Denied(reason string) Response {
	return authenticationResponse(false, "", "", reason)
}

func Errored(err error) Response {
	return authenticationResponse(false, "", "", err.Error())
}

func Allowed(username, uid string) Response {
	return authenticationResponse(true, username, uid, "")
}

func authenticationResponse(authenticated bool, username, uid, evaluationError string) Response {
	return Response{
		TokenReview: authenticationv1.TokenReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "TokenReview",
				APIVersion: authenticationv1.SchemeGroupVersion.String(),
			},
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: authenticated,
				User: authenticationv1.UserInfo{
					Username: username,
					UID:      uid,
				},
				Error: evaluationError,
			},
		},
	}
}
