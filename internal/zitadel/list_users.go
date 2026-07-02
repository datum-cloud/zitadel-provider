package zitadel

import (
	"context"
	"net/http"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// UserTypeHuman is the user type filter value for human users.
const UserTypeHuman = "TYPE_HUMAN"

// ListUsersRequest is the request body for the list users endpoint.
type ListUsersRequest struct {
	Query   *SearchQuery      `json:"query,omitempty"`
	Queries []UserSearchQuery `json:"queries,omitempty"`
}

// SearchQuery controls pagination and ordering of the search.
type SearchQuery struct {
	Offset string `json:"offset,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Asc    bool   `json:"asc,omitempty"`
}

// UserSearchQuery is a single filter applied to the user search.
type UserSearchQuery struct {
	TypeQuery  *TypeQuery  `json:"typeQuery,omitempty"`
	StateQuery *StateQuery `json:"stateQuery,omitempty"`
}

// TypeQuery filters users by type (human or machine).
type TypeQuery struct {
	Type string `json:"type"`
}

// StateQuery filters users by state.
type StateQuery struct {
	State UserState `json:"state"`
}

// ListDetails contains pagination metadata for list responses.
type ListDetails struct {
	TotalResult string `json:"totalResult"`
}

// ListUsersResponse is the response body of the list users endpoint.
type ListUsersResponse struct {
	Details ListDetails `json:"details"`
	Result  []User      `json:"result"`
}

// ListUsers searches users via the Zitadel user service v2 (POST /v2/users).
// https://zitadel.com/docs/apis/resources/user_service_v2/user-service-list-users
func (c *Client) ListUsers(ctx context.Context, req ListUsersRequest) (*ListUsersResponse, error) {
	log := logf.FromContext(ctx).WithName("zitadel-client")
	log.V(1).Info("Listing users")

	var resp ListUsersResponse
	if err := c.do(ctx, http.MethodPost, "v2/users", req, &resp); err != nil {
		log.Error(err, "Failed to list users")
		return nil, err
	}
	return &resp, nil
}
