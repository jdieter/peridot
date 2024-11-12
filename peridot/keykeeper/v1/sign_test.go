package keykeeperv1

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
)

type MockDB struct {
	mock.Mock
	peridotdb.Access
}

type FakeServer struct {
	*Server
}

var KeyDB = map[string]map[string]string{
	"clear-key": {
		"ID":    "ecfdb268-9d24-4d62-94d3-29ac071074de",
		"Name":  "clear-key",
		"GPGID": "C292F1309ECC2D8D47E38D7DD975447E3215114A",
	},
	"encrypted-key": {
		"ID":    "d0148b46-253c-4053-8ef2-af1a7966ac81",
		"Name":  "encrypted-key",
		"GPGID": "CC1CD8BECFC3E3A32FC7C5877E56BAF2C24C581C",
	},
}

func (fs *FakeServer) EnsureGPGKey(key string) (*LoadedKey, error) {
	keyData := KeyDB[key]

	if keyData == nil {
		return nil, fmt.Errorf("key not found")
	}

	keyUUID, _ := uuid.Parse(keyData["ID"])

	return &LoadedKey{
		keyUuid: keyUUID,
		gpgId:   keyData["GPGID"],
	}, nil
}

func (m *MockDB) GetKeyByName(name string) (*models.Key, error) {
	return &models.Key{
		Name: name,
	}, nil
}

func newTestServer(t *testing.T) *FakeServer {
	mockDB := new(MockDB)

	sm, err := awssm.New()
	require.NoError(t, err)

	tmpDir, err := os.MkdirTemp("", "keykeeper_test")
	require.NoError(t, err)

	server := &FakeServer{
		Server: &Server{
			db:           mockDB,
			log:          logrus.New(),
			stores:       map[string]store.Store{"awssm": sm},
			keys:         &sync.Map{},
			defaultStore: "awssm",
			workingDir:   tmpDir,
		},
	}
	server.keykeeperServer = server

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return server
}

func copyDir(src string, dst string) error {
	cwd, _ := os.Getwd()
	fmt.Println("Current working directory: ", cwd)

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}
		if strings.HasPrefix(info.Name(), ".#") || strings.HasSuffix(info.Name(), ".lock") {
			return nil
		}
		dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer dstFile.Close()
		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()
		_, err = io.Copy(dstFile, srcFile)
		return err
	})
}

func (s *FakeServer) SetUp(t *testing.T) {
	srcDir := "test_data/.gnupg"
	destDir := fmt.Sprintf("%s/keykeeper/gpg", s.workingDir)

	err := os.MkdirAll(destDir, 0700)
	require.NoError(t, err)

	err = copyDir(srcDir, destDir)
	require.NoError(t, err)

	rpmmacrosContent := `%__gpg_sign_cmd %{__gpg} \
    gpg --batch --no-verbose --no-armor --pinentry-mode loopback --passphrase %{_peridot_keykeeper_key} \
    %{?_gpg_digest_algo:--digest-algo %{_gpg_digest_algo}} \
    --no-secmem-warning \
    -u "%{_gpg_name}" -sbo %{__signature_filename} %{__plaintext_filename}`

	rpmmacrosPath := filepath.Join(s.workingDir, ".rpmmacros")
	err = os.WriteFile(rpmmacrosPath, []byte(rpmmacrosContent), 0644)
	require.NoError(t, err)
}

func verifySignedRPM(t *testing.T, signedRPMContent []byte, gpgKeyID string) bool {
	// Write the file to disk, then call rpm -K to verify that it is signed.

	tmpfile, err := os.CreateTemp("", "signed-*.rpm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(signedRPMContent); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("rpm", "-qip", tmpfile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("rpm --checksig failed: %v, output: %s", err, output)
	}

	if strings.Contains(string(output), "Signature: (none)") {
		t.Errorf("rpm is not signed: %s", output)
	} else {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Signature:") {
				if !strings.HasSuffix(line, gpgKeyID[len(gpgKeyID)-16:]) {
					t.Errorf("rpm is not signed with the correct key: %s", line)
				}
				break
			}
		}
	}

	return true
}

func TestServer_SignRPM(t *testing.T) {
	server := newTestServer(t)
	server.SetUp(t)

	tester := func(name string, file string) {
		runme := func(t *testing.T) {
			keyName := name

			rpmContent, err := os.ReadFile(file)
			require.NoError(t, err)

			req := &keykeeperpb.SignRPMRequest{
				KeyName: keyName,
				Rpm:     rpmContent,
			}

			resp, err := server.SignRPM(context.Background(), req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.NotEmpty(t, resp.SignedRpm)

			// Check that the rpm is signed
			require.True(t, verifySignedRPM(t, resp.SignedRpm, KeyDB[keyName]["GPGID"]))
		}
		t.Run(fmt.Sprintf("TestServer_SignRPM sign %s with %s", filepath.Base(file), name), runme)
	}

	rpms := []string{
		"test_data/signme-c7.rpm",
		"test_data/signme-r8.rpm",
		"test_data/signme-r9.rpm",
	}
	for _, rpm := range rpms {
		tester("clear-key", rpm)
	}

	t.Run("TestServer_SignRPM_KeyNotFound", func(t *testing.T) {

		keyName := "unknown-key"
		rpmContent := []byte("dummy rpm content")

		req := &keykeeperpb.SignRPMRequest{
			KeyName: keyName,
			Rpm:     rpmContent,
		}

		resp, err := server.SignRPM(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, resp)
		require.Equal(t, codes.Internal, status.Code(err))
	})

}
