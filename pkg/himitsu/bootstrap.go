package himitsu

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/kms"
	awskms "github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/sirupsen/logrus"
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

	keyAlreadyExists := false
	if _, err := c.awsKmsClient.DescribeKey(&awskms.DescribeKeyInput{
		KeyId: aws.String(fmt.Sprintf("alias/%s", kmsCryptoKey)),
	}); err == nil {
		keyAlreadyExists = true
	}
	if keyAlreadyExists {
		logger.Debug("KMS key alias/%s already exists. skipping", kmsCryptoKey)
	} else {
		logger.Debug("creating AWS KMS key ring")
		createKeyInput := &awskms.CreateKeyInput{
			KeyUsage:    aws.String(awskms.KeyUsageTypeEncryptDecrypt),
			Description: aws.String(kmsKeyRing),
			Tags: []*kms.Tag{
				{
					TagKey:   aws.String("created-by"),
					TagValue: aws.String("himitsu"),
				},
			},
		}
		createKeyOutput, err := c.awsKmsClient.CreateKeyWithContext(ctx, createKeyInput)
		if err != nil {
			logger.WithError(err).Error("failed to create AWS KMS key ring")
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() != awskms.ErrCodeAlreadyExistsException {
					return fmt.Errorf("failed to create KMS crypto key %s: %w", kmsKeyRing, err)
				}
			}
		}

		createAliasInput := &awskms.CreateAliasInput{
			AliasName:   aws.String(fmt.Sprintf("alias/%s", kmsCryptoKey)),
			TargetKeyId: aws.String(*createKeyOutput.KeyMetadata.KeyId),
		}

		if _, err := c.awsKmsClient.CreateAliasWithContext(ctx, createAliasInput); err != nil {
			logger.WithError(err).Error("failed to create alias for KMS key")
			if aerr, ok := err.(awserr.Error); ok {
				if aerr.Code() != awskms.ErrCodeAlreadyExistsException {
					return fmt.Errorf("failed to create alias for KMS key %s: %w", kmsKeyRing, err)
				}
			}
		}
	}

	// // Create the KMS key ring
	// logger.Debug("creating KMS key ring")

	// if _, err := c.kmsClient.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
	// 	Parent: fmt.Sprintf("projects/%s/locations/%s",
	// 		projectID, kmsLocation),
	// 	KeyRingId: kmsKeyRing,
	// }); err != nil {
	// 	logger.WithError(err).Error("failed to create KMS key ring")

	// 	terr, ok := grpcstatus.FromError(err)
	// 	if !ok || terr.Code() != grpccodes.AlreadyExists {
	// 		return fmt.Errorf("failed to create KMS key ring %s: %w", kmsKeyRing, err)
	// 	}
	// }

	// Create the KMS crypto key
	// logger.Debug("creating KMS crypto key")
	// datakeyInput := &kms.GenerateDataKeyInput{
	// 	KeyId: &kmsCryptoKey,
	// }
	// if _, err := c.awsKmsClient.GenerateDataKeyWithContext(ctx, datakeyInput); err != nil {
	// 	logger.WithError(err).Error("failed to create KMS data key")
	// 	return fmt.Errorf("failed to create KMS data key %s: %w", kmsCryptoKey, err)
	// }

	// ...
	// rotationPeriod := 30 * 24 * time.Hour
	// if _, err := c.kmsClient.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
	// 	Parent: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s",
	// 		projectID, kmsLocation, kmsKeyRing),
	// 	CryptoKeyId: kmsCryptoKey,
	// 	CryptoKey: &kmspb.CryptoKey{
	// 		Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
	// 		RotationSchedule: &kmspb.CryptoKey_RotationPeriod{
	// 			RotationPeriod: &durationpb.Duration{
	// 				Seconds: int64(rotationPeriod.Seconds()),
	// 			},
	// 		},
	// 		NextRotationTime: &timestamppb.Timestamp{
	// 			Seconds: time.Now().Add(time.Duration(rotationPeriod)).Unix(),
	// 		},
	// 		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
	// 			Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
	// 			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	// 		},
	// 	},
	// }); err != nil {
	// 	logger.WithError(err).Error("failed to create KMS crypto key")

	// 	terr, ok := grpcstatus.FromError(err)
	// 	if !ok || terr.Code() != grpccodes.AlreadyExists {
	// 		return fmt.Errorf("failed to create KMS crypto key %s: %w", kmsCryptoKey, err)
	// 	}
	// }

	// Create S3 bucket
	logger.Debug("creating S3 bucket")
	createBucketInput := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
		ACL:    aws.String(s3.BucketCannedACLPrivate),
		CreateBucketConfiguration: &s3.CreateBucketConfiguration{
			// TODO: (tuananh) fix this hardcode region
			LocationConstraint: aws.String("ap-southeast-1"),
		},
	}

	if _, err := c.s3Client.CreateBucketWithContext(ctx, createBucketInput); err != nil {
		logger.WithError(err).Error("failed to create S3 bucket")
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() != s3.ErrCodeBucketAlreadyExists && aerr.Code() != s3.ErrCodeBucketAlreadyOwnedByYou {
				return fmt.Errorf("failed to create storage bucket %s: %w", bucket, err)
			}
		}
	}

	// Set bucket tags
	taggingInput := &s3.PutBucketTaggingInput{
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
	if _, err := c.s3Client.PutBucketTaggingWithContext(ctx, taggingInput); err != nil {
		logger.WithError(err).Error("failed to tag S3 bucket")
		return fmt.Errorf("failed to tag S3 bucket %s: %w", bucket, err)
	}

	// Set versioning to enabled
	versioningInput := &s3.PutBucketVersioningInput{
		Bucket: aws.String(bucket),
		VersioningConfiguration: &s3.VersioningConfiguration{
			Status: aws.String(s3.BucketVersioningStatusEnabled),
		},
	}

	if _, err := c.s3Client.PutBucketVersioningWithContext(ctx, versioningInput); err != nil {
		logger.WithError(err).Error("failed to put S3 bucket versioning")
		return fmt.Errorf("failed to S3 bucket versioning %s: %w", bucket, err)
	}

	// TODO: (tuananh) fix this

	// Set bucket lifecycle
	// lifecycleInput := &s3.PutBucketLifecycleConfigurationInput{
	// 	Bucket: aws.String(bucket),
	// 	LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
	// 		Rules: []*s3.LifecycleRule{
	// 			{
	// 				NoncurrentVersionExpiration: &s3.NoncurrentVersionExpiration{
	// 					NewerNoncurrentVersions: aws.Int64(10),
	// 				},
	// 				// Expiration: &s3.LifecycleExpiration{
	// 				// 	ExpiredObjectDeleteMarker: aws.Bool(true),
	// 				// },
	// 				Status: aws.String("Enabled"),
	// 			},
	// 		},
	// 	},
	// }
	// if _, err := c.s3Client.PutBucketLifecycleConfigurationWithContext(ctx, lifecycleInput); err != nil {
	// 	logger.WithError(err).Error("failed to put S3 bucket lifecycle configuration")
	// 	return fmt.Errorf("failed to S3 bucket lifecycle configuration %s: %w", bucket, err)
	// }

	return nil
}
