package store

import (
	"context"
	"errors"
)

// MemoShare is an access grant that permits read-only access to a memo via a bearer token.
type MemoShare struct {
	ID        int32
	UID       string
	MemoID    int32
	CreatorID int32
	CreatedTs int64
	ExpiresTs *int64 // nil means the share never expires
	Policy    *MemoWritePolicy
}

// FindMemoShare is used to filter memo shares in list/get queries.
type FindMemoShare struct {
	ID        *int32
	UID       *string
	MemoID    *int32
	CreatorID *int32
}

// DeleteMemoShare identifies a share grant to remove.
type DeleteMemoShare struct {
	ID     *int32
	UID    *string
	MemoID *int32
	// Policy is required for transport-facing revocation and is revalidated in
	// the same transaction as the delete.
	Policy *MemoWritePolicy
}

// CreateMemoShare creates a new share grant.
func (s *Store) CreateMemoShare(ctx context.Context, create *MemoShare) (*MemoShare, error) {
	if create == nil {
		return nil, errors.New("memo share is required")
	}
	if err := validateMemoWritePolicy(create.Policy); err != nil {
		return nil, err
	}
	if create.Policy == nil {
		return s.driver.CreateMemoShare(ctx, create)
	}
	return s.driver.CreateMemoShare(ctx, create)
}

// ListMemoShares returns all share grants matching the filter.
func (s *Store) ListMemoShares(ctx context.Context, find *FindMemoShare) ([]*MemoShare, error) {
	return s.driver.ListMemoShares(ctx, find)
}

// GetMemoShare returns the first share grant matching the filter, or nil if none found.
// Lookups by token are cached: every asset on a public share page resolves the
// same token, so one page view would otherwise cost a query per attachment.
func (s *Store) GetMemoShare(ctx context.Context, find *FindMemoShare) (*MemoShare, error) {
	if find.UID != nil {
		if cached, ok := s.memoShareCache.Get(ctx, *find.UID); ok {
			if ms, ok := cached.(*MemoShare); ok {
				return ms, nil
			}
		}
	}
	ms, err := s.driver.GetMemoShare(ctx, find)
	if err != nil {
		return nil, err
	}
	if ms != nil {
		s.memoShareCache.Set(ctx, ms.UID, ms)
	}
	return ms, nil
}

// DeleteExpiredMemoShares removes every share grant that expired before the
// given unix timestamp and returns how many were removed. Grants without an
// expiry are kept.
func (s *Store) DeleteExpiredMemoShares(ctx context.Context, before int64) (int64, error) {
	return s.driver.DeleteExpiredMemoShares(ctx, before)
}

// DeleteMemoShare removes a share grant.
func (s *Store) DeleteMemoShare(ctx context.Context, delete *DeleteMemoShare) error {
	if delete == nil {
		return errors.New("memo share deletion is required")
	}
	if delete.ID == nil && delete.UID == nil {
		return errors.New("memo share deletion requires id or uid")
	}
	if err := validateMemoWritePolicy(delete.Policy); err != nil {
		return err
	}
	if delete.Policy != nil && (delete.MemoID == nil || *delete.MemoID <= 0) {
		return errors.New("authorized memo share deletion requires memo")
	}
	if delete.UID != nil {
		s.memoShareCache.Delete(ctx, *delete.UID)
	}
	return s.driver.DeleteMemoShare(ctx, delete)
}
