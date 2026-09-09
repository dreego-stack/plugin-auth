package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestArgon2idHasherRoundTripAndRehash(t *testing.T) {
	fast := Argon2idParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	hasher, err := NewArgon2idHasher(fast)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := hasher.Verify(hash, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("Verify() = %v, %v", ok, err)
	}
	ok, err = hasher.Verify(hash, "wrong")
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v", ok, err)
	}
	stronger, err := NewArgon2idHasher(Argon2idParams{Memory: 16 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	if !stronger.NeedsRehash(hash) {
		t.Fatal("stronger parameters must require a rehash")
	}
}

func TestMemoryStoreCodeAttemptsAreAtomicAndBounded(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now()
	code := OneTimeCode{ID: "code-1", UserID: "user-1", Proof: []byte("right"), ExpiresAt: now.Add(time.Minute), MaxAttempts: 2}
	if err := store.SaveCode(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	if _, matched, err := store.AttemptCode(context.Background(), code.ID, []byte("wrong"), now); err != nil || matched {
		t.Fatalf("first attempt = matched %v, err %v", matched, err)
	}
	if _, matched, err := store.AttemptCode(context.Background(), code.ID, []byte("wrong"), now); !errors.Is(err, ErrAttemptsExceeded) || matched {
		t.Fatalf("second attempt = matched %v, err %v", matched, err)
	}
	if _, _, err := store.AttemptCode(context.Background(), code.ID, []byte("right"), now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed code error = %v", err)
	}
}

func TestMemoryStorePasskeyCounterCompareAndSwap(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.CreateUser(context.Background(), NewUser{ID: "user-1", Identifier: "user", WebAuthnID: []byte("webauthn-user-1")}); err != nil {
		t.Fatal(err)
	}
	credential := PasskeyCredential{ID: []byte("credential"), SignCount: 4}
	if err := store.SavePasskey(context.Background(), "user-1", credential); err != nil {
		t.Fatal(err)
	}
	credential.SignCount = 5
	if err := store.UpdatePasskey(context.Background(), "user-1", credential, 4); err != nil {
		t.Fatal(err)
	}
	credential.SignCount = 6
	if err := store.UpdatePasskey(context.Background(), "user-1", credential, 4); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale counter error = %v", err)
	}
}

func TestMemoryChallengeStoreConsumesOnce(t *testing.T) {
	store := NewMemoryChallengeStore()
	now := time.Now()
	challenge := Challenge{ID: "challenge-1", ExpiresAt: now.Add(time.Minute), Payload: []byte("payload")}
	if err := store.Put(context.Background(), challenge); err != nil {
		t.Fatal(err)
	}
	got, err := store.Take(context.Background(), challenge.ID, now)
	if err != nil || string(got.Payload) != "payload" {
		t.Fatalf("Take() = %+v, %v", got, err)
	}
	if _, err := store.Take(context.Background(), challenge.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Take() error = %v", err)
	}
}
