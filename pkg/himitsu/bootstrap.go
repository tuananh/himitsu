package himitsu

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go/aws"
	awskms "github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/googleapi"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type bootstrapRequest interface {
	isBootstrapRequest()
}

// StorageBootstrapRequest is used as input to bootstrap Cloud Storage and Cloud
// KMS.
type StorageBootstrapRequest struct {
	// ProjectID is the ID of the project where the bucket should be created.
	ProjectID string

	// Bucket is the name of the bucket where the secret lives.
	Bucket string

	// BucketLocation is the location where the bucket should live.
	BucketLocation string

	// KMSLocation is the location where the KMS key ring should live.
	KMSLocation string

	// KMSKeyRing is the name of the KMS key ring.
	KMSKeyRing string

	// KMSCryptoKey is the name of the KMS crypto key.
	KMSCryptoKey string
}

func (r *StorageBootstrapRequest) isBootstrapRequest() {}

// BootstrapRequest is an alias for StorageBootstrapRequest for
// backwards-compatibility. New clients should use StorageBootstrapRequest.
type BootstrapRequest = StorageBootstrapRequest

// SecretManagerBootstrapRequest is used as input to bootstrap Secret Manager.
// This is a noop.
type SecretManagerBootstrapRequest struct{}

func (r *SecretManagerBootstrapRequest) isBootstrapRequest() {}

// Bootstrap is a top-level package that creates a Cloud Storage bucket and
// Cloud KMS key with the proper IAM permissions.
func Bootstrap(ctx context.Context, i bootstrapRequest) error {
	client, err := New(ctx)
	if err != nil {
		return err
	}
	return client.Bootstrap(ctx, i)
}

// Bootstrap adds IAM permission to the given entity to the storage object and the
// underlying KMS key.
func (c *Client) Bootstrap(ctx context.Context, i bootstrapRequest) error {
	if i == nil {
		return fmt.Errorf("missing request")
	}

	switch t := i.(type) {
	case *SecretManagerBootstrapRequest:
		return c.secretManagerBootstrap(ctx, t)
	case *StorageBootstrapRequest:
		return c.storageBootstrap(ctx, t)
	default:
		return fmt.Errorf("unknown bootstrap type %T", t)
	}
}

func (c *Client) secretManagerBootstrap(ctx context.Context, i *SecretManagerBootstrapRequest) error {
	return nil // noop
}

func (c *Client) storageBootstrap(ctx context.Context, i *StorageBootstrapRequest) error {
	projectID := i.ProjectID
	// if projectID == "" {
	// 	return fmt.Errorf("missing project ID")
	// }

	bucket := i.Bucket
	if bucket == "" {
		return fmt.Errorf("missing bucket name")
	}

	bucketLocation := strings.ToUpper(i.BucketLocation)
	if bucketLocation == "" {
		bucketLocation = "US"
	}

	kmsLocation := i.KMSLocation
	if kmsLocation == "" {
		kmsLocation = "global"
	}

	kmsKeyRing := i.KMSKeyRing
	if kmsKeyRing == "" {
		kmsKeyRing = "berglas"
	}

	kmsCryptoKey := i.KMSCryptoKey
	if kmsCryptoKey == "" {
		kmsCryptoKey = "berglas-key"
	}

	logger := c.Logger().WithFields(logrus.Fields{
		"project_id":      projectID,
		"bucket":          bucket,
		"bucket_location": bucketLocation,
		"kms_location":    kmsLocation,
		"kms_key_ring":    kmsKeyRing,
		"kms_crypto_key":  kmsCryptoKey,
	})

	logger.Debug("bootstrap.start")
	defer logger.Debug("bootstrap.finish")

	// Create AWS KMS key ring
	logger.Debug("creating AWS KMS key ring")
	createKeyInput := &awskms.CreateKeyInput{}
	if _, err := c.awsKmsClient.CreateKeyWithContext(ctx, createKeyInput); err != nil {
		logger.WithError(err).Error("failed to create AWS KMS key ring")

		return fmt.Errorf("failed to create AWS KMS key ring %s: %w", kmsKeyRing, err)
	}

	// Create the KMS key ring
	logger.Debug("creating KMS key ring")

	if _, err := c.kmsClient.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s",
			projectID, kmsLocation),
		KeyRingId: kmsKeyRing,
	}); err != nil {
		logger.WithError(err).Error("failed to create KMS key ring")

		terr, ok := grpcstatus.FromError(err)
		if !ok || terr.Code() != grpccodes.AlreadyExists {
			return fmt.Errorf("failed to create KMS key ring %s: %w", kmsKeyRing, err)
		}
	}

	// Create the KMS crypto key
	logger.Debug("creating KMS crypto key")

	rotationPeriod := 30 * 24 * time.Hour
	if _, err := c.kmsClient.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s",
			projectID, kmsLocation, kmsKeyRing),
		CryptoKeyId: kmsCryptoKey,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			RotationSchedule: &kmspb.CryptoKey_RotationPeriod{
				RotationPeriod: &durationpb.Duration{
					Seconds: int64(rotationPeriod.Seconds()),
				},
			},
			NextRotationTime: &timestamppb.Timestamp{
				Seconds: time.Now().Add(time.Duration(rotationPeriod)).Unix(),
			},
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
				ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			},
		},
	}); err != nil {
		logger.WithError(err).Error("failed to create KMS crypto key")

		terr, ok := grpcstatus.FromError(err)
		if !ok || terr.Code() != grpccodes.AlreadyExists {
			return fmt.Errorf("failed to create KMS crypto key %s: %w", kmsCryptoKey, err)
		}
	}

	// Create S3 bucket
	logger.Debug("creating S3 bucket")
	input := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
		// ACL:    &s3.BucketCannedACLPrivate,
		CreateBucketConfiguration: &s3.CreateBucketConfiguration{
			// TODO: (tuananh) remove hardcode region
			// enable versioning, private by default and other stuff
			LocationConstraint: aws.String(bucketLocation),
		},
	}

	if _, err := c.s3Client.CreateBucketWithContext(ctx, input); err != nil {
		logger.WithError(err).Error("failed to create S3 bucket")
		return fmt.Errorf("failed to create storage bucket %s: %w", bucket, err)
	}

	putInput := &s3.PutBucketTaggingInput{
		Bucket: aws.String(bucket),
		Tagging: &s3.Tagging{
			TagSet: []*s3.Tag{
				{
					Key:   aws.String("purpose"),
					Value: aws.String("himitsu"),
				},
			},
		},
	}
	if _, err := c.s3Client.PutBucketTaggingWithContext(ctx, putInput); err != nil {
		logger.WithError(err).Error("failed to put S3 bucket tagging")
		return fmt.Errorf("failed to S3 bucket tagging %s: %w", bucket, err)
	}

	// Set the bucket to private

	aclInput := &s3.PutBucketAclInput{
		Bucket: aws.String(bucket),
		ACL:    aws.String(s3.BucketCannedACLPrivate),
	}

	if _, err := c.s3Client.PutBucketAclWithContext(ctx, aclInput); err != nil {
		logger.WithError(err).Error("failed to put S3 bucket ACL")
		return fmt.Errorf("failed to S3 bucket ACL %s: %w", bucket, err)
	}

	// Create the storage bucket
	logger.Debug("creating bucket")

	if err := c.storageClient.Bucket(bucket).Create(ctx, projectID, &storage.BucketAttrs{
		PredefinedACL:              "private",
		PredefinedDefaultObjectACL: "private",
		Location:                   bucketLocation,
		VersioningEnabled:          true,
		Lifecycle: storage.Lifecycle{
			Rules: []storage.LifecycleRule{
				{
					Action: storage.LifecycleAction{
						Type: "Delete",
					},
					Condition: storage.LifecycleCondition{
						NumNewerVersions: 10,
					},
				},
			},
		},
		Labels: map[string]string{
			"purpose": "berglas",
		},
	}); err != nil {
		logger.WithError(err).Error("failed to create bucket")

		if !isBucketAlreadyExistsError(err) {
			return fmt.Errorf("failed to create storage bucket %s: %w", bucket, err)
		}
	}

	return nil
}

// isBucketAlreadyExistsError returns true if the given error corresponds to the
// error that occurs when a bucket already exists.
func isBucketAlreadyExistsError(err error) bool {
	terr, ok := err.(*googleapi.Error)
	if !ok {
		return false
	}
	return terr.Code == 409 && strings.Contains(terr.Message, "You already own this bucket")
}
