package webhook

import (
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Denied(reason string) Response {
	return authenticationResponse(false, "", "", reason, "")
}

func Errored(err error) Response {
	return authenticationResponse(false, "", "", err.Error(), "")
}

func Allowed(username, uid string, registrationApproval iammiloapiscomv1alpha1.RegistrationApprovalState) Response {
	return authenticationResponse(true, username, uid, "", registrationApproval)
}

func authenticationResponse(authenticated bool, username, uid, evaluationError string, registrationApproval iammiloapiscomv1alpha1.RegistrationApprovalState) Response {
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
					Extra: map[string]authenticationv1.ExtraValue{
						"iam.miloapis.com/registrationApproval": {string(registrationApproval)},
					},
				},
				Error: evaluationError,
			},
		},
	}
}
