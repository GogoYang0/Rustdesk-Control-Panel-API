package audit

import (
	"time"

	"gorm.io/gorm"
)

// timeCondition compares a timestamp column to t by instant. SQLite stores
// time.Time as text and orders it lexicographically, so a row written with the
// server's local offset does not compare correctly against a UTC bound. Both
// sides are passed through julianday on SQLite; other dialects compare native
// timestamp columns normally. column and op are internal constants.
func timeCondition(query *gorm.DB, column, op string, t time.Time) *gorm.DB {
	if query.Name() == "sqlite" {
		return query.Where("julianday("+column+") "+op+" julianday(?)", t)
	}
	return query.Where(column+" "+op+" ?", t)
}
