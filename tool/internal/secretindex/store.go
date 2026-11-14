package secretindex

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
	_ "modernc.org/sqlite" // Pure-Go driver preserves static release builds.
)

const applicationID = 0x5052574c

type Store struct {
	db       *sql.DB
	identity *Identity
	readOnly bool
}

// Open opens an index container. Read-only inspection never creates a key,
// database, schema, or replacement identity.
func Open(ctx context.Context, directory string, readOnly bool) (_ *Store, err error) {
	id, err := LoadIdentity(directory, !readOnly)
	if err != nil {
		return nil, err
	}
	path, err := indexPath(directory)
	if err != nil {
		return nil, err
	}
	info, statErr := os.Lstat(path)
	newDB := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && (!newDB || readOnly) {
		return nil, statErr
	}
	if !newDB && (!info.Mode().IsRegular() || !privatePermissions(info.Mode()) || !singleLink(info)) {
		return nil, errors.New("index database must be a private regular file with one hard link")
	}
	if !newDB {
		if err := checkPlatformPrivacy(path, info); err != nil {
			return nil, err
		}
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		side := path + suffix
		info, err := os.Lstat(side)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || !privatePermissions(info.Mode()) || !singleLink(info) {
			return nil, errors.New("index sidecar must be a private regular file with one hard link")
		}
		if err := checkPlatformPrivacy(side, info); err != nil {
			return nil, err
		}
	}
	if newDB {
		f, openErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if openErr != nil {
			return nil, openErr
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	}
	uriPath := filepath.ToSlash(path)
	if len(uriPath) > 1 && uriPath[1] == ':' {
		uriPath = "/" + uriPath
	} // canonical Windows file:///C:/... URI
	u := url.URL{Scheme: "file", Path: uriPath}
	query := url.Values{"mode": {"rw"}, "_pragma": {"busy_timeout(5000)", "foreign_keys(1)"}}
	if readOnly {
		query.Set("mode", "ro")
	}
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, identity: id, readOnly: readOnly}
	defer func() {
		if err != nil {
			err = errors.Join(err, db.Close())
		}
	}()
	var app, version int
	if err = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return nil, err
	}
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if !readOnly && app == 0 && version == 0 && (newDB || info.Size() == 0) {
		err = s.initialize(ctx)
		if err != nil {
			return nil, err
		}
	} else if app != applicationID || version != 1 {
		return nil, errors.New("not a supported Prowl index database")
	}
	var storedKey string
	if err = db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE name='key_id'").Scan(&storedKey); err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(storedKey), []byte(id.keyID())) {
		return nil, errors.New("index key does not match the database")
	}
	return s, nil
}

func (s *Store) initialize(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `
CREATE TABLE metadata(name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE scans(id INTEGER PRIMARY KEY, scope TEXT NOT NULL, at_ns INTEGER NOT NULL, complete INTEGER NOT NULL CHECK(complete IN(0,1)));
CREATE TABLE sightings(scan_id INTEGER NOT NULL REFERENCES scans(id), value_id TEXT NOT NULL, location_id TEXT NOT NULL,
type TEXT NOT NULL, source TEXT NOT NULL, path TEXT NOT NULL, line INTEGER NOT NULL, col INTEGER NOT NULL,
verdict INTEGER NOT NULL CHECK(verdict IN(-1,0,1)), PRIMARY KEY(scan_id,value_id,location_id));
CREATE INDEX sightings_value ON sightings(value_id,scan_id);
PRAGMA application_id=1347573580;
PRAGMA user_version=1;`)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO metadata(name,value) VALUES('key_id',?)", s.identity.keyID()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Close() error        { return s.db.Close() }
func (s *Store) Identity() *Identity { return s.identity }

type Scan struct {
	ID       int64     `json:"id"`
	Scope    string    `json:"scope"`
	At       time.Time `json:"at"`
	Complete bool      `json:"complete"`
}

type Location struct {
	Scope    string `json:"scope"`
	ValueID  string `json:"value_id"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Source   string `json:"source"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	Verified *bool  `json:"verified,omitempty"`
}

type observation struct {
	valueID  string
	location Location
	verdict  int
}

func mergeVerdict(a, b int) int {
	if a == 1 || b == 1 {
		return 1
	}
	if a == 0 && b == 0 {
		return 0
	}
	return -1
}

func verdict(v *bool) int {
	if v == nil {
		return -1
	}
	if *v {
		return 1
	}
	return 0
}

func checkedBool(v int) *bool {
	if v < 0 {
		return nil
	}
	b := v == 1
	return &b
}

// Record atomically records accepted, ML-filtered observations before display
// suppression. Only the keyed identity and explicit source metadata are stored.
// No field reads Redacted, Context, URL, Rationale, or an unredacted value.
func (s *Store) Record(ctx context.Context, scope string, at time.Time, complete bool, findings []model.Finding) (int64, error) {
	if s.readOnly {
		return 0, errors.New("index is read-only")
	}
	if strings.TrimSpace(scope) == "" || len(scope) > 512 || at.IsZero() {
		return 0, errors.New("index scope and observation time are required")
	}
	observations := map[string]observation{}
	for _, f := range findings {
		if model.IsIncompleteFinding(f) {
			complete = false
			continue
		}
		if !validFingerprint(f.ValueFingerprint) || !strings.HasPrefix(f.ValueFingerprint, fingerprintPrefix+s.identity.keyID()+":") {
			return 0, errors.New("finding has no keyed value fingerprint for this index")
		}
		if !validIdentity(f.IndexLocationID, locationPrefix) || !strings.HasPrefix(f.IndexLocationID, locationPrefix+s.identity.keyID()+":") {
			return 0, errors.New("finding has no keyed location identity for this index")
		}
		if len(f.IndexPath) > 32768 || len(f.IndexSource) > 128 || len(f.IndexType) > 256 || f.Line < 0 || f.Col < 0 {
			return 0, errors.New("invalid index location metadata")
		}
		// A source path is meaningful within a caller-declared acquisition scope.
		// Identical relative filenames in different repositories must not collapse.
		locID := s.identity.Location("prowl:scope:"+scope, f.IndexLocationID, 0, 0)
		o := observation{valueID: f.ValueFingerprint, location: Location{ValueID: f.ValueFingerprint, ID: locID, Type: f.IndexType, Source: f.IndexSource, Path: f.IndexPath, Line: f.Line, Col: f.Col}, verdict: verdict(f.Verified)}
		key := f.ValueFingerprint + locID
		if previous, ok := observations[key]; ok {
			o.verdict = mergeVerdict(previous.verdict, o.verdict)
			if previous.location.Type < o.location.Type {
				o.location.Type = previous.location.Type
			}
		}
		observations[key] = o
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, "INSERT INTO scans(scope,at_ns,complete) VALUES(?,?,?)", scope, at.UTC().UnixNano(), complete)
	if err != nil {
		return 0, err
	}
	scanID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	statement, err := tx.PrepareContext(ctx, "INSERT INTO sightings(scan_id,value_id,location_id,type,source,path,line,col,verdict) VALUES(?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return 0, err
	}
	defer statement.Close()
	for _, o := range observations {
		l := o.location
		if _, err = statement.ExecContext(ctx, scanID, o.valueID, l.ID, l.Type, l.Source, l.Path, l.Line, l.Col, o.verdict); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return scanID, nil
}

func (s *Store) Scans(ctx context.Context, scope string) ([]Scan, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,scope,at_ns,complete FROM scans WHERE (?='' OR scope=?) ORDER BY id", scope, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scan{}
	for rows.Next() {
		var r Scan
		var at int64
		if err := rows.Scan(&r.ID, &r.Scope, &at, &r.Complete); err != nil {
			return nil, err
		}
		r.At = time.Unix(0, at).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

type Transition struct {
	From                  string    `json:"from"`
	To                    string    `json:"to"`
	ObservedAt            time.Time `json:"observed_at"`
	SecondsSinceFirstLive *float64  `json:"seconds_since_first_live,omitempty"`
}

type Secret struct {
	ValueID            string       `json:"value_id"`
	FirstSeen          time.Time    `json:"first_seen"`
	LastSeen           time.Time    `json:"last_seen"`
	Locations          []Location   `json:"locations"`
	LocationCount      int          `json:"location_count"`
	LastConfirmedState string       `json:"last_confirmed_state"`
	LastConfirmedAt    *time.Time   `json:"last_confirmed_at,omitempty"`
	Transitions        []Transition `json:"transitions"`
}

type indexedObservation struct {
	observation
	scan Scan
}

func (s *Store) observations(ctx context.Context, scope string, through int64) ([]indexedObservation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id,s.scope,s.at_ns,s.complete,f.value_id,f.location_id,f.type,f.source,f.path,f.line,f.col,f.verdict FROM sightings f JOIN scans s ON s.id=f.scan_id WHERE (?='' OR s.scope=?) AND s.id<=? ORDER BY s.at_ns,s.id,f.value_id,f.location_id`, scope, scope, through)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []indexedObservation{}
	for rows.Next() {
		var o indexedObservation
		var at int64
		l := &o.location
		r := &o.scan
		if err := rows.Scan(&r.ID, &r.Scope, &at, &r.Complete, &o.valueID, &l.ID, &l.Type, &l.Source, &l.Path, &l.Line, &l.Col, &o.verdict); err != nil {
			return nil, err
		}
		r.At = time.Unix(0, at).UTC()
		l.Scope = r.Scope
		l.ValueID = o.valueID
		l.Verified = checkedBool(o.verdict)
		out = append(out, o)
	}
	return out, rows.Err()
}

// Secrets reports historical locations and separately dated provider evidence.
// An absent or unverified observation never becomes proof of revocation.
func (s *Store) Secrets(ctx context.Context, scope string) ([]Secret, error) {
	return s.SecretsThrough(ctx, scope, 1<<63-1)
}

// SecretsThrough provides an append-only snapshot consistent with a previously
// read list of scan IDs even when another process records a newer scan.
func (s *Store) SecretsThrough(ctx context.Context, scope string, through int64) ([]Secret, error) {
	rows, err := s.observations(ctx, scope, through)
	if err != nil {
		return nil, err
	}
	groups := map[string][]indexedObservation{}
	for _, r := range rows {
		groups[r.valueID] = append(groups[r.valueID], r)
	}
	out := []Secret{}
	for id, observations := range groups {
		r := Secret{ValueID: id, FirstSeen: observations[0].scan.At, LastConfirmedState: "unknown", Transitions: []Transition{}}
		locations := map[string]Location{}
		var firstLive time.Time
		for n := 0; n < len(observations); {
			current := observations[n].scan
			valueVerdict := observations[n].verdict
			j := n
			for ; j < len(observations) && observations[j].scan.ID == current.ID; j++ {
				o := observations[j]
				locations[o.location.ID] = o.location
				if j > n {
					valueVerdict = mergeVerdict(valueVerdict, o.verdict)
				}
			}
			r.LastSeen = current.At
			if current.Complete && valueVerdict >= 0 {
				state := "dead"
				if valueVerdict == 1 {
					state = "live"
				}
				if state != r.LastConfirmedState {
					if state == "live" {
						firstLive = current.At
					}
					if r.LastConfirmedState != "unknown" {
						event := Transition{From: r.LastConfirmedState, To: state, ObservedAt: current.At}
						if state == "dead" && !firstLive.IsZero() {
							seconds := current.At.Sub(firstLive).Seconds()
							if seconds >= 0 {
								event.SecondsSinceFirstLive = &seconds
							}
						}
						r.Transitions = append(r.Transitions, event)
					}
				}
				r.LastConfirmedState = state
				at := current.At
				r.LastConfirmedAt = &at
			}
			n = j
		}
		r.Locations = []Location{}
		for _, l := range locations {
			r.Locations = append(r.Locations, l)
		}
		sort.Slice(r.Locations, func(i, j int) bool { return r.Locations[i].ID < r.Locations[j].ID })
		r.LocationCount = len(r.Locations)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ValueID < out[j].ValueID })
	return out, nil
}

type Diff struct {
	From                Scan                 `json:"from"`
	To                  Scan                 `json:"to"`
	NewValues           []string             `json:"new_values"`
	NotSeenValues       []string             `json:"not_seen_values"`
	NewLocations        []Location           `json:"new_locations"`
	NotSeenLocations    []Location           `json:"not_seen_locations"`
	VerificationChanges []VerificationChange `json:"verification_changes"`
}

type VerificationChange struct {
	ValueID string `json:"value_id"`
	From    string `json:"from"`
	To      string `json:"to"`
}

func (s *Store) Diff(ctx context.Context, from, to int64) (Diff, error) {
	r := Diff{NewValues: []string{}, NotSeenValues: []string{}, NewLocations: []Location{}, NotSeenLocations: []Location{}, VerificationChanges: []VerificationChange{}}
	if from >= to {
		return r, errors.New("diff requires increasing scan IDs")
	}
	for n, id := range []int64{from, to} {
		var at int64
		var scan Scan
		if err := s.db.QueryRowContext(ctx, "SELECT id,scope,at_ns,complete FROM scans WHERE id=?", id).Scan(&scan.ID, &scan.Scope, &at, &scan.Complete); err != nil {
			return r, err
		}
		scan.At = time.Unix(0, at).UTC()
		if !scan.Complete {
			return r, errors.New("cannot compare absence using an incomplete scan")
		}
		if n == 0 {
			r.From = scan
		} else {
			r.To = scan
		}
	}
	if r.From.Scope != r.To.Scope {
		return r, errors.New("cannot compare different index scopes")
	}
	rows, err := s.observations(ctx, r.From.Scope, to)
	if err != nil {
		return r, err
	}
	values := [2]map[string]int{{}, {}}
	locations := [2]map[string]Location{{}, {}}
	for _, o := range rows {
		var valueSide map[string]int
		var locationSide map[string]Location
		if o.scan.ID == from {
			valueSide, locationSide = values[0], locations[0]
		}
		if o.scan.ID == to {
			valueSide, locationSide = values[1], locations[1]
		}
		if valueSide == nil {
			continue
		}
		v, ok := valueSide[o.valueID]
		if ok {
			v = mergeVerdict(v, o.verdict)
		} else {
			v = o.verdict
		}
		valueSide[o.valueID] = v
		locationSide[o.valueID+o.location.ID] = o.location
	}
	for id, v := range values[1] {
		previous, ok := values[0][id]
		if !ok {
			r.NewValues = append(r.NewValues, id)
		} else if v >= 0 && previous >= 0 && v != previous {
			a, b := "dead", "live"
			if previous == 1 {
				a, b = b, a
			}
			r.VerificationChanges = append(r.VerificationChanges, VerificationChange{id, a, b})
		}
	}
	for id := range values[0] {
		if _, ok := values[1][id]; !ok {
			r.NotSeenValues = append(r.NotSeenValues, id)
		}
	}
	for key, l := range locations[1] {
		if _, ok := locations[0][key]; !ok {
			r.NewLocations = append(r.NewLocations, l)
		}
	}
	for key, l := range locations[0] {
		if _, ok := locations[1][key]; !ok {
			r.NotSeenLocations = append(r.NotSeenLocations, l)
		}
	}
	sort.Strings(r.NewValues)
	sort.Strings(r.NotSeenValues)
	sort.Slice(r.NewLocations, func(i, j int) bool { return r.NewLocations[i].ID < r.NewLocations[j].ID })
	sort.Slice(r.NotSeenLocations, func(i, j int) bool { return r.NotSeenLocations[i].ID < r.NotSeenLocations[j].ID })
	sort.Slice(r.VerificationChanges, func(i, j int) bool { return r.VerificationChanges[i].ValueID < r.VerificationChanges[j].ValueID })
	return r, nil
}
