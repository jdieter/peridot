package keykeeperv1

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	peridotdb "peridot.resf.org/peridot/db"
	"peridot.resf.org/peridot/db/models"
	keykeeperpb "peridot.resf.org/peridot/keykeeper/pb"
	"peridot.resf.org/peridot/keykeeper/v1/store"
	"peridot.resf.org/peridot/keykeeper/v1/store/awssm"
	"peridot.resf.org/peridot/lookaside/s3"
)

type MockDB struct {
	mock.Mock
	peridotdb.Access
}

func (m *MockDB) GetKeyByName(name string) (*models.Key, error) {
	return &models.Key{
		Name:         name,
		EncKey:       hex.EncodeToString([]byte("test-key-contents")),
		Nonce:        hex.EncodeToString([]byte("something")),
		ExtStoreType: "awssm",
	}, nil
}

func newTestServer(t *testing.T) *Server {
	mockDB := new(MockDB)

	sm, err := awssm.New()
	require.NoError(t, err)

	storage, err := s3.New(osfs.New("/"))
	require.NoError(t, err)

	server := &Server{
		db:           mockDB,
		storage:      storage,
		log:          logrus.New(),
		stores:       map[string]store.Store{"awssm": sm},
		keys:         &sync.Map{},
		defaultStore: "awssm",
	}

	return server
}

func TestServer_SignRPM(t *testing.T) {
	server := newTestServer(t)

	keyName := "test-key"

	// TODO: add real rpm content here
	rpmContent := []byte("dummy rpm content")

	// Store a key so we dont need to do a lookup in store
	server.keys.Store(keyName, &LoadedKey{keyUuid: uuid.New()})

	req := &keykeeperpb.SignRPMRequest{
		KeyName: keyName,
		Rpm:     rpmContent,
	}

	resp, err := server.SignRPM(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.SignedRpm)
}

func TestServer_SignRPM_KeyNotFound(t *testing.T) {
	server := newTestServer(t)

	keyName := "test-key"
	rpmContent := []byte("dummy rpm content")

	req := &keykeeperpb.SignRPMRequest{
		KeyName: keyName,
		Rpm:     rpmContent,
	}

	resp, err := server.SignRPM(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
}
