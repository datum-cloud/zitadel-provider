package zitadel

import (
	"context"
	"errors"
	"testing"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
)

// fakeUserService stubs the gRPC UserServiceClient. Only ListUsers is
// implemented; any other call panics via the embedded nil interface.
type fakeUserService struct {
	userv2.UserServiceClient
	listUsers func(ctx context.Context, in *userv2.ListUsersRequest, opts ...grpc.CallOption) (*userv2.ListUsersResponse, error)
}

func (f *fakeUserService) ListUsers(ctx context.Context, in *userv2.ListUsersRequest, opts ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
	return f.listUsers(ctx, in, opts...)
}

func humanUser(id, username, email, given, family string, state userv2.UserState) *userv2.User {
	return &userv2.User{
		UserId:             id,
		Username:           username,
		PreferredLoginName: username,
		State:              state,
		Type: &userv2.User_Human{Human: &userv2.HumanUser{
			Profile: &userv2.HumanProfile{GivenName: given, FamilyName: family},
			Email:   &userv2.HumanEmail{Email: email},
		}},
	}
}

func TestListHumanUsers(t *testing.T) {
	t.Run("maps human users and requests server-side human filter", func(t *testing.T) {
		// Arrange
		var gotReq *userv2.ListUsersRequest
		c := &SDKClient{user: &fakeUserService{
			listUsers: func(_ context.Context, in *userv2.ListUsersRequest, _ ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
				gotReq = in
				return &userv2.ListUsersResponse{Result: []*userv2.User{
					humanUser("u1", "alice", "alice@example.com", "Alice", "Doe", userv2.UserState_USER_STATE_ACTIVE),
					humanUser("u2", "bob", "bob@example.com", "Bob", "Roe", userv2.UserState_USER_STATE_INACTIVE),
				}}, nil
			},
		}}

		// Act
		users, raw, err := c.ListHumanUsers(context.Background(), 40, 20)

		// Assert
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(users) != 2 {
			t.Fatalf("expected 2 users, got %d", len(users))
		}
		if raw != 2 {
			t.Fatalf("expected raw page count 2, got %d", raw)
		}
		want := User{ID: "u1", Username: "alice", Email: "alice@example.com", State: "USER_STATE_ACTIVE", GivenName: "Alice", FamilyName: "Doe"}
		if users[0] != want {
			t.Errorf("user[0] = %+v, want %+v", users[0], want)
		}
		if users[1].State != "USER_STATE_INACTIVE" {
			t.Errorf("user[1].State = %q, want USER_STATE_INACTIVE (state must not filter results)", users[1].State)
		}

		if gotReq.GetQuery().GetOffset() != 40 || gotReq.GetQuery().GetLimit() != 20 || !gotReq.GetQuery().GetAsc() {
			t.Errorf("pagination query = %+v, want offset=40 limit=20 asc=true", gotReq.GetQuery())
		}
		if len(gotReq.GetQueries()) != 1 {
			t.Fatalf("expected exactly 1 search query (type filter), got %d", len(gotReq.GetQueries()))
		}
		tq := gotReq.GetQueries()[0].GetTypeQuery()
		if tq == nil || tq.GetType() != userv2.Type_TYPE_HUMAN {
			t.Errorf("search query = %+v, want TypeQuery TYPE_HUMAN", gotReq.GetQueries()[0])
		}
	})

	t.Run("defensively skips non-human results", func(t *testing.T) {
		// Arrange
		c := &SDKClient{user: &fakeUserService{
			listUsers: func(_ context.Context, _ *userv2.ListUsersRequest, _ ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
				return &userv2.ListUsersResponse{Result: []*userv2.User{
					{UserId: "m1", Username: "robot", State: userv2.UserState_USER_STATE_ACTIVE,
						Type: &userv2.User_Machine{Machine: &userv2.MachineUser{}}},
					humanUser("u1", "alice", "alice@example.com", "Alice", "Doe", userv2.UserState_USER_STATE_ACTIVE),
				}}, nil
			},
		}}

		// Act
		users, raw, err := c.ListHumanUsers(context.Background(), 0, 10)

		// Assert
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(users) != 1 || users[0].ID != "u1" {
			t.Fatalf("expected only the human user u1, got %+v", users)
		}
		if raw != 2 {
			t.Fatalf("raw must count the full server page including skipped rows: want 2, got %d", raw)
		}
	})

	t.Run("propagates API errors", func(t *testing.T) {
		// Arrange
		boom := errors.New("boom")
		c := &SDKClient{user: &fakeUserService{
			listUsers: func(_ context.Context, _ *userv2.ListUsersRequest, _ ...grpc.CallOption) (*userv2.ListUsersResponse, error) {
				return nil, boom
			},
		}}

		// Act
		_, _, err := c.ListHumanUsers(context.Background(), 0, 10)

		// Assert
		if !errors.Is(err, boom) {
			t.Fatalf("expected wrapped boom error, got %v", err)
		}
	})
}
