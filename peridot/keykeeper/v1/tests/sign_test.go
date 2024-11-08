package keykeeperv1

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	keykeeperpb "peridot.resf.org/peridot/keykeeper/pb"
)

type MockDB struct {
	mock.Mock
}

type Server struct {
	db *MockDB
}

func TestServer_SignRPM(t *testing.T) {
	mockDB := new(MockDB)
	server := &Server{
		db: mockDB,
	}

	keyName := "test-key"
	rpmContent := []byte("dummy rpm content")

	mockDB.On("EnsureGPGKey", keyName).Return(&LoadedKey{keyUuid: uuid.New()}, nil)

	req := &keykeeperpb.SignRPMRequest{
		KeyName: keyName,
		Rpm:     rpmContent,
	}

	resp, err := server.SignRPM(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.SignedRpm)
}

func TestServer_SignRPM_KeyNotFound(t *testing.T) {
	mockDB := new(MockDB)
	server := &Server{
		db: mockDB,
	}

	keyName := "test-key"
	rpmContent := []byte("dummy rpm content")

	mockDB.On("EnsureGPGKey", keyName).Return(nil, errors.New("key not found"))

	req := &keykeeperpb.SignRPMRequest{
		KeyName: keyName,
		Rpm:     rpmContent,
	}

	resp, err := server.SignRPM(context.Background(), req)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestServer_SignRPM_FailToCreateTempFile(t *testing.T) {
	mockDB := new(MockDB)
	server := &Server{
		db: mockDB,
	}

	keyName := "test-key"
	rpmContent := []byte("dummy rpm content")

	mockDB.On("EnsureGPGKey", keyName).Return(&LoadedKey{keyUuid: uuid.New()}, nil)

	// Simulate failure to create temp file
	osCreateTemp = func(dir, pattern string) (*os.File, error) {
		return nil, errors.New("failed to create temp file")
	}
	defer func() { osCreateTemp = os.CreateTemp }()

	req := &keykeeperpb.SignRPMRequest{
		KeyName: keyName,
		Rpm:     rpmContent,
	}

	resp, err := server.SignRPM(context.Background(), req)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}
