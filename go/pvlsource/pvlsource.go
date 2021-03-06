// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package pvlsource

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"sync"
	"time"

	"golang.org/x/net/context"

	"github.com/keybase/client/go/libkb"
)

// Older than this will try to refresh merkle root.
// Measures time since merkle root fetched, not time since published.
const tShouldRefresh time.Duration = 1 * time.Hour

// Older than this is too old to use. All identifies will fail.
// Measures time since merkle root fetched, not time since published.
const tRequireRefresh time.Duration = 24 * time.Hour

var dbKey = libkb.DbKey{
	Typ: libkb.DBPvl,
	Key: "active",
}

// Bump this to ignore existing cache entries.
const dbVersion = 1

type entry struct {
	DBVersion int
	Hash      string
	PvlKit    string
}

// PvlSource is the way to get active pvl.
// Talks to MerkleClient
// Has an in-memory and LocalDB cache.
type PvlSourceImpl struct {
	libkb.Contextified
	sync.Mutex

	mem *entry
}

var _ libkb.PvlSource = (*PvlSourceImpl)(nil)

// NewPvlSource creates a new source and installs it into G.
func NewPvlSourceAndInstall(g *libkb.GlobalContext) libkb.PvlSource {
	s := &PvlSourceImpl{
		Contextified: libkb.NewContextified(g),
	}
	g.SetPvlSource(s)
	return s
}

type pvlKitT struct {
	KitVersion int                     `json:"kit_version"`
	Ctime      int                     `json:"ctime"`
	Tab        map[int]json.RawMessage `json:"tab"`
}

// Get PVL to use.
func (s *PvlSourceImpl) GetPVL(ctx context.Context, pvlVersion int) (string, error) {
	kitJSON, err := s.GetKitString(ctx)
	if err != nil {
		return "", err
	}

	var kit pvlKitT
	err = json.Unmarshal([]byte(kitJSON), &kit)
	if err != nil {
		return "", libkb.NewPvlSourceError("unmarshalling kit: %s", err)
	}

	sub, ok := kit.Tab[pvlVersion]
	if !ok {
		return "", libkb.NewPvlSourceError("missing pvl for version: %d", pvlVersion)
	}
	if len(sub) == 0 {
		return "", libkb.NewPvlSourceError("empty pvl for version: %d", pvlVersion)
	}

	return string(sub), nil
}

// Get pvl kit as a string.
// First it makes sure that the merkle root is recent enough.
// Using the pvl hash from that, it fetches from in-memory falling back to db
// falling back to server.
func (s *PvlSourceImpl) GetKitString(ctx context.Context) (string, error) {

	// Use a file instead if specified.
	if len(s.G().Env.GetPvlKitFilename()) > 0 {
		return s.readFile(s.G().Env.GetPvlKitFilename())
	}

	mc := s.G().GetMerkleClient()
	if mc == nil {
		return "", libkb.NewPvlSourceError("no MerkleClient available")
	}

	s.Lock()
	defer s.Unlock()

	root := mc.LastRoot()
	// The time that the root was fetched is used rather than when the
	// root was published so that we can continue to operate even if
	// the root has not been published in a long time.
	if (root == nil) || s.pastDue(ctx, root.Fetched(), tShouldRefresh) {
		s.G().Log.CDebugf(ctx, "PvlSource: merkle root should refresh")

		// Attempt a refresh if the root is old or nil.
		err := s.refreshRoot(ctx)
		if err != nil {
			s.G().Log.CWarningf(ctx, "PvlSource: could not refresh merkle root: %s", err)
		} else {
			root = mc.LastRoot()
		}
	}

	if root == nil {
		return "", libkb.NewPvlSourceError("no merkle root")
	}

	if s.pastDue(ctx, root.Fetched(), tRequireRefresh) {
		// The root is still too old, even after an attempted refresh.
		s.G().Log.CDebugf(ctx, "PvlSource: merkle root too old")
		return "", libkb.NewPvlSourceError("merkle root too old: %v %s", seqnoWrap(root.Seqno()), root.Fetched())
	}

	// This is the hash we are being instructed to use.
	hash := root.PvlHash()

	if hash == "" {
		return "", libkb.NewPvlSourceError("merkle root has empty pvl hash: %v", seqnoWrap(root.Seqno()))
	}

	// If multiple Get's occur, these mem/db gets and sets may race.
	// But it shouldn't affect correctness, worst that could happen is an old write and/or cache miss.
	// And pvl updates so infrequently it's very unlikely to have multiple outstanding writes.

	// Use in-memory cache if it matches
	fromMem := s.memGet(hash)
	if fromMem != nil {
		s.G().Log.CDebugf(ctx, "PvlSource: mem cache hit")
		s.G().Log.CDebugf(ctx, "PvlSource: using hash: %s", hash)
		return *fromMem, nil
	}

	// Use db cache if it matches
	fromDB := s.dbGet(ctx, hash)
	if fromDB != nil {
		s.G().Log.CDebugf(ctx, "PvlSource: db cache hit")

		// Store to memory
		s.memSet(hash, *fromDB)

		s.G().Log.CDebugf(ctx, "PvlSource: using hash: %s", hash)
		return *fromDB, nil
	}

	// Fetch from the server
	// This validates the hash
	pvl, err := s.fetch(ctx, hash)
	if err != nil {
		return "", err
	}

	// Store to memory
	s.memSet(hash, pvl)

	// Schedule a db write
	go s.dbSet(context.Background(), hash, pvl)

	s.G().Log.CDebugf(ctx, "PvlSource: using hash: %s", hash)
	return pvl, nil
}

type pvlServerRes struct {
	Status  libkb.AppStatus `json:"status"`
	KitJSON string          `json:"kit_json"`
}

func (r *pvlServerRes) GetAppStatus() *libkb.AppStatus {
	return &r.Status
}

// Fetch pvl and check the hash.
func (s *PvlSourceImpl) fetch(ctx context.Context, hash string) (string, error) {
	s.G().Log.CDebugf(ctx, "PvlSource: fetching from server: %s", hash)
	var res pvlServerRes
	err := s.G().API.GetDecode(libkb.APIArg{
		Endpoint:    "merkle/pvl",
		NeedSession: false,
		NetContext:  ctx,
		Args: libkb.HTTPArgs{
			"hash": libkb.S{Val: hash},
		},
	}, &res)
	if err != nil {
		return "", libkb.NewPvlSourceError(err.Error())
	}
	if res.KitJSON == "" {
		return "", libkb.NewPvlSourceError("server returned empty pvl")
	}
	if s.hash(res.KitJSON) != hash {
		s.G().Log.CWarningf(ctx, "pvl hash mismatch: got:%s expected:%s", s.hash(res.KitJSON), hash)
		return "", libkb.NewPvlSourceError("server returned wrong pvl")
	}
	return res.KitJSON, nil
}

// updateRoot kicks MerkleClient to update its merkle root
// by doing a LookupUser on some arbitrary user.
func (s *PvlSourceImpl) refreshRoot(ctx context.Context) error {
	q := libkb.NewHTTPArgs()
	// The user lookup here is unecessary. It is done because that is what
	// is easy with MerkleClient.
	// The user lookuped up is you if known, otherwise arbitrarily t_alice.
	// If t_alice is removed, this path will break.
	uid := s.G().GetMyUID()
	if len(uid) == 0 {
		// Use t_alice's uid.
		uid = libkb.TAliceUID
	}
	q.Add("uid", libkb.UIDArg(uid))
	_, err := s.G().MerkleClient.LookupUser(ctx, q, nil)
	return err
}

func (s *PvlSourceImpl) memGet(hash string) *string {
	if s.mem != nil {
		if s.mem.Hash == hash {
			ret := s.mem.PvlKit
			return &ret
		}
	}
	return nil
}

func (s *PvlSourceImpl) memSet(hash string, pvl string) {
	s.mem = &entry{
		DBVersion: dbVersion,
		Hash:      hash,
		PvlKit:    pvl,
	}
}

// Get from local db. Can return nil.
func (s *PvlSourceImpl) dbGet(ctx context.Context, hash string) *string {
	db := s.G().LocalDb
	if db == nil {
		return nil
	}
	var ent entry
	found, err := db.GetInto(&ent, dbKey)
	if err != nil {
		s.G().Log.CWarningf(ctx, "PvlSource: error reading from db: %s", err)
		return nil
	}
	if !found {
		return nil
	}
	if ent.DBVersion != ent.DBVersion {
		return nil
	}
	if ent.Hash == hash {
		return &ent.PvlKit
	}
	return nil
}

// Run in a goroutine.
// Logs errors.
func (s *PvlSourceImpl) dbSet(ctx context.Context, hash string, pvl string) {
	db := s.G().LocalDb
	if db == nil {
		s.G().Log.CErrorf(ctx, "storing pvl: no db")
		return
	}
	ent := entry{
		DBVersion: dbVersion,
		Hash:      hash,
		PvlKit:    pvl,
	}
	err := db.PutObj(dbKey, nil, ent)
	if err != nil {
		s.G().Log.CErrorf(ctx, "storing pvl: %s", err)
	}
}

// hex of sha512
func (s *PvlSourceImpl) hash(in string) string {
	buf := sha512.Sum512([]byte(in))
	out := hex.EncodeToString(buf[:])
	return out
}

func (s *PvlSourceImpl) pastDue(ctx context.Context, event time.Time, limit time.Duration) bool {
	diff := s.G().Clock().Now().Sub(event)
	overdue := diff > limit
	if overdue {
		s.G().Log.CDebugf(ctx, "PvlSource: pastDue diff:(%s) t1:(%s) limit:(%s)", diff, event, limit)
	}
	return overdue
}

func (s *PvlSourceImpl) readFile(path string) (string, error) {
	buf, err := ioutil.ReadFile(path)
	return string(buf), err
}

func seqnoWrap(x *libkb.Seqno) int64 {
	if x == nil {
		return 0
	}
	return int64(*x)
}
