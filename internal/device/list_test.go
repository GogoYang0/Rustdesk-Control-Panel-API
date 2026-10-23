package device_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// deviceDialectSeq keeps memory-database names unique across tests: a shared
// cache database is process-global, so a fixed DSN would leak rows between
// tests and hide scoping bugs.
var deviceDialectSeq atomic.Int64

// openDeviceStore opens the database a dialect-sensitive device test runs
// against. CI's test-db job exports TEST_POSTGRES_DSN / TEST_MYSQL_DSN, and
// these tests must run on those dialects too: the reset path uses an
// expression UPDATE whose affected-row count differs between MySQL and SQLite.
func openDeviceStore(t *testing.T) *store.Store {
	t.Helper()
	switch {
	case os.Getenv("TEST_POSTGRES_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "postgres", DSN: os.Getenv("TEST_POSTGRES_DSN")})
		require.NoError(t, err)
		return s
	case os.Getenv("TEST_MYSQL_DSN") != "":
		s, err := store.Open(config.DatabaseConfig{Driver: "mysql", DSN: os.Getenv("TEST_MYSQL_DSN")})
		require.NoError(t, err)
		return s
	}
	s, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:dev_dialect_%d?mode=memory&cache=shared", deviceDialectSeq.Add(1)),
	})
	require.NoError(t, err)
	return s
}

func newListFixture(t *testing.T) (*store.Store, *device.Service, model.Organization) {
	t.Helper()
	st := openDeviceStore(t)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.Device{}, &model.DeviceHeartbeat{},
	))
	org := model.Organization{Name: "list-org"}
	require.NoError(t, st.DB.Create(&org).Error)
	return st, device.NewService(st.DB, nil), org
}

func seedDevice(t *testing.T, st *store.Store, orgID uint, rustdeskID, name, boundUUID string) model.Device {
	t.Helper()
	d := model.Device{OrganizationID: orgID, RustdeskID: rustdeskID, Name: name, BoundUUID: boundUUID}
	if boundUUID != "" {
		d.BindingGeneration = 1
	}
	require.NoError(t, st.DB.Create(&d).Error)
	return d
}

func boolPtr(v bool) *bool { return &v }

func TestList_ScopedAndSorted(t *testing.T) {
	st, svc, org := newListFixture(t)
	ctx := context.Background()

	other := model.Organization{Name: "other-org"}
	require.NoError(t, st.DB.Create(&other).Error)
	seedDevice(t, st, org.ID, "1001", "first", "")
	seedDevice(t, st, org.ID, "1002", "second", "")
	seedDevice(t, st, org.ID, "1003", "third", "")
	seedDevice(t, st, other.ID, "2001", "foreign", "")

	items, total, err := svc.List(ctx, org.ID, device.DeviceFilter{})
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, items, 3)
	require.Equal(t, "first", items[0].Name)
	require.Equal(t, "second", items[1].Name)
	require.Equal(t, "third", items[2].Name)
	require.True(t, items[0].ID < items[1].ID && items[1].ID < items[2].ID, "id ASC order")
}

func TestList_QueryIsCaseInsensitiveSubstring(t *testing.T) {
	st, svc, org := newListFixture(t)
	ctx := context.Background()

	seedDevice(t, st, org.ID, "1001", "Web-01", "")
	seedDevice(t, st, org.ID, "1002", "web-02", "")
	seedDevice(t, st, org.ID, "2001", "db-01", "")

	items, total, err := svc.List(ctx, org.ID, device.DeviceFilter{Query: "WEB"})
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, items, 2)

	items, total, err = svc.List(ctx, org.ID, device.DeviceFilter{Query: "01"})
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, items, 2, "name matches: Web-01 and db-01")

	// A whitespace-only query must be ignored rather than filter everything out.
	items, total, err = svc.List(ctx, org.ID, device.DeviceFilter{Query: "   "})
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, items, 3)
}

func TestList_QueryTreatsWildcardsLiterally(t *testing.T) {
	st, svc, org := newListFixture(t)
	ctx := context.Background()

	seedDevice(t, st, org.ID, "1001", "100%", "")
	seedDevice(t, st, org.ID, "1002", "a_b", "")
	seedDevice(t, st, org.ID, "1003", "axb", "")
	seedDevice(t, st, org.ID, "1004", "a!b", "")

	items, total, err := svc.List(ctx, org.ID, device.DeviceFilter{Query: "%"})
	require.NoError(t, err)
	require.EqualValues(t, 1, total, "% must be literal, not a wildcard")
	require.Len(t, items, 1)
	require.Equal(t, "100%", items[0].Name)

	items, total, err = svc.List(ctx, org.ID, device.DeviceFilter{Query: "a_b"})
	require.NoError(t, err)
	require.EqualValues(t, 1, total, "_ must be literal, not a single-character wildcard")
	require.Len(t, items, 1)
	require.Equal(t, "a_b", items[0].Name)

	items, total, err = svc.List(ctx, org.ID, device.DeviceFilter{Query: "!"})
	require.NoError(t, err)
	require.EqualValues(t, 1, total, "the escape character itself must be searchable")
	require.Len(t, items, 1)
	require.Equal(t, "a!b", items[0].Name)
}

func TestList_BoundFilter(t *testing.T) {
	st, svc, org := newListFixture(t)
	ctx := context.Background()

	seedDevice(t, st, org.ID, "1001", "bound", "uuid-1")
	seedDevice(t, st, org.ID, "1002", "unbound", "")

	items, total, err := svc.List(ctx, org.ID, device.DeviceFilter{Bound: boolPtr(true)})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, items, 1)
	require.Equal(t, "bound", items[0].Name)

	items, total, err = svc.List(ctx, org.ID, device.DeviceFilter{Bound: boolPtr(false)})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, items, 1)
	require.Equal(t, "unbound", items[0].Name)
}

func TestList_PaginationClamps(t *testing.T) {
	st, svc, org := newListFixture(t)
	ctx := context.Background()

	seedDevice(t, st, org.ID, "1001", "one", "")
	seedDevice(t, st, org.ID, "1002", "two", "")
	seedDevice(t, st, org.ID, "1003", "three", "")

	filter := device.DeviceFilter{Page: 0, PageSize: 999}
	page, pageSize := filter.NormalisedPagination()
	require.Equal(t, 1, page)
	require.Equal(t, 200, pageSize)

	zero := device.DeviceFilter{PageSize: 0}
	_, size := zero.NormalisedPagination()
	require.Equal(t, 50, size)

	items, total, err := svc.List(ctx, org.ID, device.DeviceFilter{Page: 2, PageSize: 2})
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, items, 1, "second page holds the remaining row")
	require.Equal(t, "three", items[0].Name)
}

func TestList_RequiresOrg(t *testing.T) {
	_, svc, _ := newListFixture(t)
	_, _, err := svc.List(context.Background(), 0, device.DeviceFilter{})
	require.ErrorIs(t, err, device.ErrInvalidInput)
}
