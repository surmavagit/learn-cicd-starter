package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		input   http.Header
		want    string
		wantErr error
	}{
		{
			input:   http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			input:   http.Header{"Authorization": {""}},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			input:   http.Header{"Authorization": {"ApiKey"}},
			want:    "",
			wantErr: ErrMalformedAuthHeader,
		},
		{
			input:   http.Header{"Authorization": {"notApiKey blablabal"}},
			want:    "",
			wantErr: ErrMalformedAuthHeader,
		},
		{
			input:   http.Header{"Authorization": {"ApiKey blablabal"}},
			want:    "blablabal",
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		got, err := GetAPIKey(tc.input)
		if got != tc.want {
			t.Errorf("GetAPIKey(%s) gives '%s', want '%s'", tc.input.Get("Authorization"), got, tc.want)
		}
		if err != tc.wantErr {
			t.Errorf("GetAPIKey(%s) gives error '%s', want error '%s'", tc.input.Get("Authorization"), err, tc.wantErr)
		}
	}
}
