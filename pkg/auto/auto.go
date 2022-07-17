// Package auto automatically parses himitsu references when imported.
//
//     import (
//       _ "github.com/tuananh/himitsu/pkg/auto"
//     )
//
// Set environment variables on your deployment using the himitsu:// prefix in
// the format:
//
//     himitsu://<bucket>/<secret>?<params>
//
// - "bucket" is the name of the Google Cloud Storage bucket where secrets
// are stored
// - "secret" is the path to the full path to a secret inside the bucket
// - "params" are URL query parameters that configure behavior
//
// Examples:
//
//     himitsu://my-bucket/my-secret
//     himitsu://my-bucket/path/to/secret?destination=tempfile
//     himitsu://my-bucket/path/to/secret?destination=/var/foo/bar
//
// On init, the package queries the list of configured environment variables
// against the metadata service. If environment variables match, their values
// are automatically replaced with the secret value.
//
//
// By default, any errors result in a panic. If you want the function to
// continue executing even if resolution or communication fails, set the
// environment variable `HIMITSU_CONTINUE_ON_ERROR` to `true` or do not use the
// auto package.
//
// To see log output, set `HIMITSU_LOG_LEVEL` to "trace" or "debug".
package auto
