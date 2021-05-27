package main

import (
	"context"
	"log"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/workflows"
	"github.com/gravitational/teleport/api/types"
)

func main() {
	ctx := context.Background()
	client, err := client.New(ctx, client.Config{
		Credentials: []client.Credentials{
			client.LoadProfile("", ""),
		},
		InsecureAddressDiscovery: true,
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	router := &workflows.Router{}
	router.HandleFunc(
		handleMeRequest,
		workflows.MatchUserTrait("team", "myteam"),
		workflows.MatchUserLabel("group", "security"),
		workflows.MatchUserID("dev"),
	)
	router.HandleFunc(
		handleMyTeamRequest,
		workflows.MatchUserTrait("team", "myteam"),
		workflows.MatchUserLabel("group", "security"),
	)

	srv := workflows.Server{
		Client: client,
		Router: router,
		Filter: &types.AccessRequestFilter{
			State: types.RequestState_PENDING,
		},
	}

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func handleMyTeamRequest(ctx context.Context, req types.AccessRequest) (types.AccessRequestUpdate, error) {
	return types.AccessRequestUpdate{
		RequestID: req.GetName(),
		State:     types.RequestState_DENIED,
		Reason:    "Don't trust my security team",
	}, nil
}

func handleMeRequest(ctx context.Context, req types.AccessRequest) (types.AccessRequestUpdate, error) {
	return types.AccessRequestUpdate{
		RequestID: req.GetName(),
		State:     types.RequestState_APPROVED,
		Reason:    "Trust yourself!",
	}, nil
}
