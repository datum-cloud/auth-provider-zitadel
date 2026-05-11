package sessions

import "testing"

func TestSessionAnnotations(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]string
		want map[string]string
	}{
		{
			name: "nil metadata returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "empty metadata returns nil",
			in:   map[string]string{},
			want: nil,
		},
		{
			name: "only allowlisted keys are surfaced",
			in: map[string]string{
				"maxmind/tracking-token": "tok-abc",
				"unrelated/key":          "ignored",
			},
			want: map[string]string{
				"iam.miloapis.com/maxmind-tracking-token": "tok-abc",
			},
		},
		{
			name: "empty values are dropped",
			in: map[string]string{
				"maxmind/tracking-token": "",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sessionAnnotations(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("annotation %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
