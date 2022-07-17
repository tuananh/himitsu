package himitsu

import (
	"reflect"
	"testing"
)

func TestClient_Create_secretManager(t *testing.T) {
	testAcc(t)

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		project, name := testProject(t), testName(t)
		plaintext := []byte("my secret value")

		createResp, err := client.Create(ctx, &SecretManagerCreateRequest{
			Project:   project,
			Name:      name,
			Plaintext: plaintext,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer testSecretManagerCleanup(t, project, name)

		readResp, err := client.Read(ctx, &SecretManagerReadRequest{
			Project: project,
			Name:    name,
		})
		if err != nil {
			t.Fatal(err)
		}

		if createResp.Locations != nil {
			t.Errorf("expected %#v to be %#v", createResp.Locations, nil)
		}
		if !reflect.DeepEqual(createResp, readResp) {
			t.Errorf("expected %#v to be %#v", createResp, readResp)
		}
	})

	t.Run("custom-locations", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		project, name := testProject(t), testName(t)
		plaintext := []byte("my secret value")

		createResp, err := client.Create(ctx, &SecretManagerCreateRequest{
			Project:   project,
			Name:      name,
			Plaintext: plaintext,
			Locations: []string{"europe-west1", "europe-west4"},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer testSecretManagerCleanup(t, project, name)

		readResp, err := client.Read(ctx, &SecretManagerReadRequest{
			Project: project,
			Name:    name,
		})
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(createResp.Locations, []string{"europe-west1", "europe-west4"}) {
			t.Errorf("expected the locations to be set to `nil`, got %+v", createResp.Locations)
		}
		if !reflect.DeepEqual(createResp, readResp) {
			t.Errorf("expected %#v to be %#v", createResp, readResp)
		}
	})

	t.Run("exists", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		project, name := testProject(t), testName(t)
		plaintext := []byte("my secret value")

		if _, err := client.Create(ctx, &SecretManagerCreateRequest{
			Project:   project,
			Name:      name,
			Plaintext: plaintext,
		}); err != nil {
			t.Fatal(err)
		}
		defer testSecretManagerCleanup(t, project, name)

		if _, err := client.Create(ctx, &SecretManagerCreateRequest{
			Project:   project,
			Name:      name,
			Plaintext: plaintext,
		}); !IsSecretAlreadyExistsErr(err) {
			t.Errorf("expected %q to be %q", err, errSecretAlreadyExists)
		}
	})
}

func TestClient_Create_storage(t *testing.T) {
	testAcc(t)

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		bucket, object, key := testBucket(t), testName(t), testKey(t)
		plaintext := []byte("my secret value")

		createResp, err := client.Create(ctx, &StorageCreateRequest{
			Bucket:    bucket,
			Object:    object,
			Key:       key,
			Plaintext: plaintext,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer testStorageCleanup(t, bucket, object)

		readResp, err := client.Read(ctx, &StorageReadRequest{
			Bucket:     bucket,
			Object:     object,
			Generation: createResp.Generation,
		})
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(createResp, readResp) {
			t.Errorf("expected %#v to be %#v", createResp, readResp)
		}
	})

	t.Run("exists", func(t *testing.T) {
		t.Parallel()

		client, ctx := testClient(t)
		bucket, object, key := testBucket(t), testName(t), testKey(t)
		plaintext := []byte("my secret value")

		if _, err := client.Create(ctx, &StorageCreateRequest{
			Bucket:    bucket,
			Object:    object,
			Key:       key,
			Plaintext: plaintext,
		}); err != nil {
			t.Fatal(err)
		}
		defer testStorageCleanup(t, bucket, object)

		if _, err := client.Create(ctx, &StorageCreateRequest{
			Bucket:    bucket,
			Object:    object,
			Key:       key,
			Plaintext: plaintext,
		}); !IsSecretAlreadyExistsErr(err) {
			t.Errorf("expected %q to be %q", err, errSecretAlreadyExists)
		}
	})
}
