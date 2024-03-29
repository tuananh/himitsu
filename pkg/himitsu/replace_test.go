package himitsu

import (
	"fmt"
	"os"
	"testing"
)

func TestClient_Replace_secretManager(t *testing.T) {
	testAcc(t)

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		project, name, env := testProject(t), testName(t), testName(t)

		os.Setenv(env, fmt.Sprintf("sm://%s/%s", project, name))

		if err := client.Replace(ctx, env); err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("replaces", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		project, name, env := testProject(t), testName(t), testName(t)
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
		os.Setenv(env, ref)

		if err := client.Replace(ctx, env); err != nil {
			t.Fatal(err)
		}

		if act, exp := os.Getenv(env), string(plaintext); act != exp {
			t.Errorf("expected %q to be %q", act, exp)
		}
	})
}

func TestClient_Replace_storage(t *testing.T) {
	testAcc(t)

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		bucket, object, env := testBucket(t), testName(t), testName(t)

		os.Setenv(env, fmt.Sprintf("berglas://%s/%s", bucket, object))

		if err := client.Replace(ctx, env); err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("replaces", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		bucket, object, key, env := testBucket(t), testName(t), testKey(t), testName(t)
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

		ref := fmt.Sprintf("berglas://%s/%s#%d", bucket, object, secret.Generation)
		os.Setenv(env, ref)

		if err := client.Replace(ctx, env); err != nil {
			t.Fatal(err)
		}

		if act, exp := os.Getenv(env), string(plaintext); act != exp {
			t.Errorf("expected %q to be %q", act, exp)
		}
	})
}
