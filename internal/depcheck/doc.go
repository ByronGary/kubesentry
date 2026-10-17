// Package depcheck holds no code: its test checks that the third-party
// clients stay in the packages CLAUDE.md names (client-go in internal/kube,
// pgx in internal/pgstore, the AWS SDK in internal/cloudwatch,
// internal/awsauth, internal/aws/** and internal/llm, the Anthropic SDK in
// internal/llm alone), so everything else stays stdlib and testable without
// a cluster, a database, AWS or a model.
package depcheck
