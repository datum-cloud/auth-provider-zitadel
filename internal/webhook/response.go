package webhook

import (
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Denied(reason string) Response {
	return authenticationResponse(false, "", "", reason, iammiloapiscomv1alpha1.RegistrationApprovalStateRejected)
}

func Errored(err error) Response {
	return authenticationResponse(false, "", "", err.Error(), iammiloapiscomv1alpha1.RegistrationApprovalStateRejected)
}

func Allowed(username, uid string) Response {
	return authenticationResponse(true, username, uid, "", iammiloapiscomv1alpha1.RegistrationApprovalStateApproved)
}

func authenticationResponse(authenticated bool, username, uid, evaluationError string, state iammiloapiscomv1alpha1.RegistrationApprovalState) Response {
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
						"iam.miloapis.com/registrationApproval": {string(state)},
					},
				},
				Error: evaluationError,
			},
		},
	}
}
