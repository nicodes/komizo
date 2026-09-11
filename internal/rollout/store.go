package rollout

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Store is an operator-private, persistent journal protected by an OS lock.
// The directory must not be shared with application containers or the monitor.
type Store struct {
	root *os.Root
	lock *os.File
}

func OpenStore(ctx context.Context, directory string, poll time.Duration) (*Store, error) {
	if !filepath.IsAbs(directory) || poll <= 0 {
		return nil, errors.New("journal needs an absolute private directory and poll interval")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errors.New("cannot create private journal directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrent(info) {
		return nil, errors.New("journal directory must be private and not a symlink")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("cannot open private journal directory")
	}
	file, err := root.OpenFile("lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		root.Close()
		return nil, errors.New("cannot open rollout lock")
	}
	info, err = file.Stat()
	link, linkErr := root.Lstat("lock")
	if err != nil || linkErr != nil || !info.Mode().IsRegular() || !link.Mode().IsRegular() || !os.SameFile(info, link) || info.Mode().Perm()&0o077 != 0 {
		file.Close()
		root.Close()
		return nil, errors.New("rollout lock must be a private regular file")
	}
	if err := lockFile(ctx, file, poll); err != nil {
		file.Close()
		root.Close()
		return nil, err
	}
	return &Store{root: root, lock: file}, nil
}

func (s *Store) Close() error {
	return errors.Join(s.lock.Close(), s.root.Close())
}

func (s *Store) Load() (*State, error) {
	file, err := s.root.Open("state.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot open rollout journal")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 32<<20 {
		return nil, errors.New("invalid rollout journal file")
	}
	d := json.NewDecoder(io.LimitReader(file, 32<<20+1))
	d.DisallowUnknownFields()
	var state State
	if err := d.Decode(&state); err != nil || state.Version != 1 {
		return nil, errors.New("invalid rollout journal contents")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("rollout journal contains trailing data")
	}
	return &state, nil
}

func (s *Store) Save(state *State) error {
	data, err := json.Marshal(state)
	if err != nil || len(data) > 32<<20 {
		return errors.New("cannot encode bounded rollout journal")
	}
	return s.WritePrivate("state.json", data)
}

// WritePrivate uses same-directory rename and fsync of both file and directory.
// Never overwrite a mounted individual file and expect a container bind mount
// to follow the new inode; mount the dedicated configuration directory instead.
func (s *Store) WritePrivate(name string, data []byte) error {
	if name != filepath.Base(name) || name == "." || name == ".." {
		return errors.New("invalid private artifact name")
	}
	temporary := ".next-" + rand.Text()
	file, err := s.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("cannot create private journal checkpoint")
	}
	defer s.root.Remove(temporary)
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if errors.Join(writeErr, syncErr, closeErr) != nil {
		return errors.New("cannot persist private journal checkpoint")
	}
	if err := s.root.Rename(temporary, name); err != nil {
		return errors.New("cannot publish private journal checkpoint")
	}
	directory, err := s.root.Open(".")
	if err != nil {
		return errors.New("cannot open journal directory for synchronization")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("cannot synchronize journal directory")
	}
	return nil
}

func (s *Store) Path(name string) string { return filepath.Join(s.root.Name(), name) }

// PublishGateway isolates routing-only data from the private release journal.
// A gateway container may mount this subdirectory, never the journal directory.
func (s *Store) PublishGateway(data []byte) error {
	if err := s.root.MkdirAll("gateway", 0o700); err != nil {
		return errors.New("cannot create gateway configuration directory")
	}
	child, err := s.root.OpenRoot("gateway")
	if err != nil {
		return errors.New("cannot open gateway configuration directory")
	}
	defer child.Close()
	return (&Store{root: child}).WritePrivate("config.json", data)
}
