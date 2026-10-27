package app

import (
	"context"

	"github.com/kirank55/keman/internal/model"
)

// SetSpendSaverForTest replaces the spend flush so tests can fail it.
func (a *App) SetSpendSaverForTest(fn func(context.Context, []model.SpendRow) error) {
	if fn == nil {
		a.saveSpend = a.store.SaveSpend
		return
	}
	a.saveSpend = fn
}

// FlushSpendForTest runs one spend flush.
func (a *App) FlushSpendForTest() { a.flush(context.Background()) }
