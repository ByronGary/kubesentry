package kube

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/ByronGary/kubesentry/internal/model"
)

// ParseAWSAuth parses the mapRoles and mapUsers keys of the EKS aws-auth
// ConfigMap. Hand-edited ConfigMaps are often partly broken, so a malformed
// entry is skipped rather than failing the whole read; the returned error
// lists what was skipped and is nil when everything parsed.
func ParseAWSAuth(data map[string]string) (model.AWSAuth, error) {
	var out model.AWSAuth
	var errs []error
	out.MapRoles, errs = parseMappings(mapRolesKey, data[mapRolesKey], "rolearn", "userarn", errs)
	out.MapUsers, errs = parseMappings(mapUsersKey, data[mapUsersKey], "userarn", "rolearn", errs)
	return out, errors.Join(errs...)
}

func parseMappings(key, raw, arnKey, altKey string, errs []error) ([]model.AWSAuthMapping, []error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errs
	}
	js, err := yaml.YAMLToJSON([]byte(raw))
	if err != nil {
		return nil, append(errs, fmt.Errorf("%s: %w", key, err))
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(js, &entries); err != nil {
		return nil, append(errs, fmt.Errorf("%s: not a list", key))
	}
	var out []model.AWSAuthMapping
	for i, e := range entries {
		var m map[string]any
		if err := json.Unmarshal(e, &m); err != nil || m == nil {
			errs = append(errs, fmt.Errorf("%s[%d]: not a mapping", key, i))
			continue
		}
		arn := stringField(m, arnKey)
		if arn == "" {
			arn = stringField(m, altKey)
		}
		if arn == "" {
			errs = append(errs, fmt.Errorf("%s[%d]: no %s", key, i, arnKey))
			continue
		}
		out = append(out, model.AWSAuthMapping{ARN: arn, Username: stringField(m, "username"), Groups: stringList(m["groups"])})
	}
	return out, errs
}

func stringField(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return strings.TrimSpace(s)
}

// stringList accepts a list of strings or a single string; anything else in
// the list is skipped.
func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		if s := strings.TrimSpace(t); s != "" {
			return []string{s}
		}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

// awsAuthFromConfigMap parses the ConfigMap, logging skipped entries.
func awsAuthFromConfigMap(cm *corev1.ConfigMap) model.AWSAuth {
	a, err := ParseAWSAuth(cm.Data)
	if err != nil {
		slog.Warn("aws-auth ConfigMap has malformed entries; they are skipped", "err", err)
	}
	return a
}
