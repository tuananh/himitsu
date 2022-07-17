package himitsu

import (
	"bytes"
	"fmt"
	"testing"
)

func TestClient_Resolve_secretManager(t *testing.T) {
	testAcc(t)

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		project, name := testProject(t), testName(t)
		ref := fmt.Sprintf("sm://%s/%s#%s", project, name, "12")

		if _, err := client.Resolve(ctx, ref); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("basic", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		project, name := testProject(t), testName(t)
		plaintext := []byte("my secret plaintext")

		secret, err := client.Create(ctx, &SecretManagerCreateRequest{
			Project:   project,
			Name:      name,
			Plaintext: plaintext,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer testSecretManagerCleanup(t, project, name)

		ref := fmt.Sprintf("sm://%s/%s#%s", project, name, secret.Version)

		b, err := client.Resolve(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}

		if act, exp := b, plaintext; !bytes.Equal(act, exp) {
			t.Errorf("expected %q to be %q", act, exp)
		}
	})
}

func TestClient_Resolve_storage(t *testing.T) {
	testAcc(t)

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		bucket, object := testBucket(t), testName(t)
		ref := fmt.Sprintf("berglas://%s/%s#%d", bucket, object, 21324253)

		if _, err := client.Resolve(ctx, ref); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("basic", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		bucket, object, key := testBucket(t), testName(t), testKey(t)
		plaintext := []byte("my secret plaintext")

		secret, err := client.Create(ctx, &StorageCreateRequest{
			Bucket:    bucket,
			Object:    object,
			Key:       key,
			Plaintext: plaintext,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer testStorageCleanup(t, bucket, object)

		ref := fmt.Sprintf("berglas://%s/%s#%s", bucket, object, secret.Version)

		b, err := client.Resolve(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}

		if act, exp := b, plaintext; !bytes.Equal(act, exp) {
			t.Errorf("expected %q to be %q", act, exp)
		}
	})
}
