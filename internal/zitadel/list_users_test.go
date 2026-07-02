package zitadel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestListUsersDecodesHumansAndMachines(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/users" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"details": {"totalResult": "2"},
			"result": [
				{"userId": "u1", "state": "USER_STATE_ACTIVE",
				 "human": {"profile": {"givenName": "Jane", "familyName": "Doe"},
				           "email": {"email": "jane@example.com", "isVerified": true}}},
				{"userId": "m1", "state": "USER_STATE_ACTIVE", "machine": {}}
			]}`))
	}))
	defer ts.Close()

	c := NewClientWithTokenSource(ts.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t", TokenType: "Bearer"}))
	resp, err := c.ListUsers(context.Background(), ListUsersRequest{
		Query:   &SearchQuery{Limit: 100, Asc: true},
		Queries: []UserSearchQuery{{TypeQuery: &TypeQuery{Type: UserTypeHuman}}},
	})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(resp.Result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Result))
	}
	human := resp.Result[0]
	if human.Human == nil || human.Human.Profile == nil || human.Human.Email == nil {
		t.Fatalf("human sub-structs not decoded: %+v", human)
	}
	if human.Human.Profile.GivenName != "Jane" || human.Human.Email.Email != "jane@example.com" {
		t.Fatalf("wrong human fields: %+v", human.Human)
	}
	machine := resp.Result[1]
	if machine.Machine == nil || machine.Human != nil {
		t.Fatalf("machine discrimination broken: %+v", machine)
	}
}

func TestListUsersSurfacesServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := NewClientWithTokenSource(ts.URL, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t", TokenType: "Bearer"}))
	if _, err := c.ListUsers(context.Background(), ListUsersRequest{}); err == nil {
		t.Fatal("expected error on 500")
	}
}
