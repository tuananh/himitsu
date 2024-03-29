package himitsu_test

import (
	"context"
	"log"
	"os"

	"github.com/tuananh/himitsu/pkg/himitsu"
)

var (
	ctx       = context.Background()
	client, _ = himitsu.New(ctx)

	err          error
	secret       *himitsu.Secret
	plaintext    []byte
	listResponse *himitsu.ListResponse

	project = os.Getenv("GOOGLE_CLOUD_PROJECT")
	bucket  = os.Getenv("GOOGLE_CLOUD_BUCKET")
	key     = os.Getenv("GOOGLE_CLOUD_KMS_KEY")
)

func ExampleNew() {
	client, err = himitsu.New(ctx)
}

func ExampleClient_Access_secretManager() {
	plaintext, err = client.Access(ctx, &himitsu.SecretManagerAccessRequest{
		Project: project,
		Name:    "my-secret",
	})

	log.Println(plaintext) // "abcd1234"
}

func ExampleClient_Access_storage() {
	plaintext, err = client.Access(ctx, &himitsu.StorageAccessRequest{
		Bucket: bucket,
		Object: "my-secret",
	})

	log.Println(plaintext) // "abcd1234"
}

func ExampleClient_Bootstrap_secretManager() {
	// This is a noop - there's nothing to bootstrap with Secret Manager
	err = client.Bootstrap(ctx, &himitsu.SecretManagerBootstrapRequest{})
}

func ExampleClient_Bootstrap_storage() {
	err = client.Bootstrap(ctx, &himitsu.StorageBootstrapRequest{
		ProjectID:      "my-project",
		Bucket:         bucket,
		BucketLocation: "US",
		KMSLocation:    "global",
		KMSKeyRing:     "berglas",
		KMSCryptoKey:   "berglas-key",
	})
}

func ExampleClient_Create_secretManager() {
	secret, err = client.Create(ctx, &himitsu.SecretManagerCreateRequest{
		Project:   project,
		Name:      "my-secret",
		Plaintext: []byte("my secret data"),
	})

	log.Printf("%v\n", secret)
}

func ExampleClient_Create_storage() {
	secret, err = client.Create(ctx, &himitsu.StorageCreateRequest{
		Bucket:    bucket,
		Object:    "my-secret",
		Key:       key,
		Plaintext: []byte("my secret data"),
	})

	log.Printf("%v\n", secret)
}

func ExampleClient_Delete_secretManager() {
	err = client.Delete(ctx, &himitsu.SecretManagerDeleteRequest{
		Project: project,
		Name:    "my-secret",
	})
}

func ExampleClient_Delete_storage() {
	err = client.Delete(ctx, &himitsu.StorageDeleteRequest{
		Bucket: bucket,
		Object: "my-secret",
	})
}

func ExampleClient_Grant_secretManager() {
	err = client.Grant(ctx, &himitsu.SecretManagerGrantRequest{
		Project: project,
		Name:    "my-secret",
		Members: []string{
			"serviceAccount:builder@my-project.iam.gserviceaccount.com",
		},
	})
}

func ExampleClient_Grant_storage() {
	err = client.Grant(ctx, &himitsu.StorageGrantRequest{
		Bucket: bucket,
		Object: "my-secret",
		Members: []string{
			"serviceAccount:builder@my-project.iam.gserviceaccount.com",
		},
	})
}

func ExampleClient_List_secretManager() {
	listResponse, err = client.List(ctx, &himitsu.SecretManagerListRequest{
		Project: project,
	})

	log.Println(listResponse) // [&Secret{...}]
}

func ExampleClient_List_storage() {
	listResponse, err = client.List(ctx, &himitsu.StorageListRequest{
		Bucket: bucket,
	})

	log.Println(listResponse) // [&Secret{...}]
}

func ExampleClient_Read_secretManager() {
	secret, err = client.Read(ctx, &himitsu.SecretManagerReadRequest{
		Project: project,
		Name:    "my-secret",
		Version: "12",
	})

	log.Println(secret) // &Secret{...}
}

func ExampleClient_Read_storage() {
	secret, err = client.Read(ctx, &himitsu.StorageReadRequest{
		Bucket:     bucket,
		Object:     "my-secret",
		Generation: secret.Generation,
	})

	log.Println(secret) // &Secret{...}
}

func ExampleClient_Revoke_secretManager() {
	err = client.Revoke(ctx, &himitsu.SecretManagerRevokeRequest{
		Project: project,
		Name:    "my-secret",
		Members: []string{
			"serviceAccount:builder@my-project.iam.gserviceaccount.com",
		},
	})
}

func ExampleClient_Revoke_storage() {
	err = client.Revoke(ctx, &himitsu.StorageRevokeRequest{
		Bucket: bucket,
		Object: "my-secret",
		Members: []string{
			"serviceAccount:builder@my-project.iam.gserviceaccount.com",
		},
	})
}

func ExampleClient_Replace_secretManager() {
	// MY_ENVVAR = "sm://my-project/my-secret#12"
	err = client.Replace(ctx, "MY_ENVVAR")
}

func ExampleClient_Replace_storage() {
	// MY_ENVVAR = "berglas://my-bucket/my-object#12248904892"
	err = client.Replace(ctx, "MY_ENVVAR")
}

func ExampleClient_Resolve_secretManager() {
	plaintext, err = client.Resolve(ctx, "sm://my-project/my-secret")
	log.Println(plaintext) // "my secret data"
}

func ExampleClient_Resolve_storage() {
	plaintext, err = client.Resolve(ctx, "berglas://my-bucket/my-object")
	log.Println(plaintext) // "my secret data"
}

func ExampleClient_Update_secretManager() {
	secret, err = client.Update(ctx, &himitsu.SecretManagerUpdateRequest{
		Project:   project,
		Name:      "my-secret",
		Plaintext: []byte("my updated secret data"),
	})

	log.Println(secret) // [&Secret{"my updated secret data"...}]
}

func ExampleClient_Update_storage() {
	secret, err = client.Update(ctx, &himitsu.StorageUpdateRequest{
		Bucket:         bucket,
		Object:         "my-secret",
		Generation:     secret.Generation,
		Key:            secret.KMSKey,
		Metageneration: secret.Metageneration,
		Plaintext:      []byte("my updated secret data"),
	})

	log.Println(secret) // [&Secret{"my updated secret data"...}]
}
