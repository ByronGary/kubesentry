package kube

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ByronGary/kubesentry/internal/model"
)

const certManagerGroupVersion = "cert-manager.io/v1"

func certGVR(resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: resource}
}

// issuerTypes are the spec keys that select an issuer's backend.
var issuerTypes = []string{"acme", "ca", "vault", "selfSigned", "venafi"}

// certManagerResources are the cert-manager.io/v1 resources kubesentry reads,
// in the order their objects appear in model.CertManager.
var certManagerResources = []string{"certificates", "issuers", "clusterissuers", "certificaterequests"}

// CertManager reads cert-manager's Certificates, Issuers, ClusterIssuers and
// CertificateRequests. It reports Installed: false, without an error, when the
// cert-manager.io/v1 API is not served. Secrets are never read.
func (s *Source) CertManager(ctx context.Context) (model.CertManager, error) {
	return s.certManager(ctx, nil)
}

// certManager is CertManager; with a non-nil unavailable map a forbidden
// resource is recorded there instead of failing the read.
func (s *Source) certManager(ctx context.Context, unavailable map[string]string) (model.CertManager, error) {
	if s.dyn == nil {
		return model.CertManager{}, nil
	}
	if _, err := s.cs.Discovery().ServerResourcesForGroupVersion(certManagerGroupVersion); err != nil {
		if apierrors.IsNotFound(err) {
			return model.CertManager{}, nil
		}
		return model.CertManager{}, fmt.Errorf("discover cert-manager: %w", err)
	}
	out := model.CertManager{Installed: true}
	for _, r := range []struct {
		resource string
		each     func(*unstructured.Unstructured)
	}{
		{"certificates", func(u *unstructured.Unstructured) { out.Certificates = append(out.Certificates, convertCertificate(u)) }},
		{"issuers", func(u *unstructured.Unstructured) { out.Issuers = append(out.Issuers, convertIssuer(u, "Issuer")) }},
		{"clusterissuers", func(u *unstructured.Unstructured) {
			out.Issuers = append(out.Issuers, convertIssuer(u, "ClusterIssuer"))
		}},
		{"certificaterequests", func(u *unstructured.Unstructured) { out.Requests = append(out.Requests, convertCertificateRequest(u)) }},
	} {
		err := s.listDynamic(ctx, r.resource, r.each)
		if err != nil && unavailable != nil && apierrors.IsForbidden(err) {
			unavailable[r.resource] = forbiddenReason(err)
			continue
		}
		if err != nil {
			return model.CertManager{}, err
		}
	}
	return out, nil
}

func (s *Source) listDynamic(ctx context.Context, resource string, each func(*unstructured.Unstructured)) error {
	return paginate(resource, func(o metav1.ListOptions) (string, error) {
		l, err := s.dyn.Resource(certGVR(resource)).Namespace(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			each(&l.Items[i])
		}
		return l.GetContinue(), nil
	})
}

func str(u *unstructured.Unstructured, fields ...string) string {
	v, _, _ := unstructured.NestedString(u.Object, fields...)
	return v
}

func timeField(u *unstructured.Unstructured, fields ...string) time.Time {
	t, _ := time.Parse(time.RFC3339, str(u, fields...))
	return t
}

// durationField parses a Go duration string such as "2160h0m0s"; 0 when
// unset or malformed.
func durationField(u *unstructured.Unstructured, fields ...string) time.Duration {
	d, err := time.ParseDuration(str(u, fields...))
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// statusCondition returns the status, reason and message of the named condition.
func statusCondition(u *unstructured.Unstructured, typ string) (status, reason, message string) {
	conds, _ := nestedSlice(u.Object, "status", "conditions")
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok || m["type"] != typ {
			continue
		}
		status, _ = m["status"].(string)
		reason, _ = m["reason"].(string)
		message, _ = m["message"].(string)
		return status, reason, truncate(message)
	}
	return "", "", ""
}

func issuerRef(u *unstructured.Unstructured) (kind, name string) {
	kind, name = str(u, "spec", "issuerRef", "kind"), str(u, "spec", "issuerRef", "name")
	if kind == "" {
		kind = "Issuer"
	}
	return kind, name
}

func convertCertificate(u *unstructured.Unstructured) model.Certificate {
	c := model.Certificate{
		Namespace: u.GetNamespace(), Name: u.GetName(), Created: u.GetCreationTimestamp().Time,
		SecretName: str(u, "spec", "secretName"), CommonName: str(u, "spec", "commonName"),
		NotBefore: timeField(u, "status", "notBefore"), NotAfter: timeField(u, "status", "notAfter"),
		RenewalTime: timeField(u, "status", "renewalTime"),
		Duration:    durationField(u, "spec", "duration"),
		RenewBefore: durationField(u, "spec", "renewBefore"),
	}
	c.DNSNames, _, _ = unstructured.NestedStringSlice(u.Object, "spec", "dnsNames")
	c.IssuerKind, c.IssuerName = issuerRef(u)
	c.Ready, c.Reason, c.Message = statusCondition(u, "Ready")
	return c
}

func convertIssuer(u *unstructured.Unstructured, kind string) model.Issuer {
	is := model.Issuer{Kind: kind, Namespace: u.GetNamespace(), Name: u.GetName(), Type: "unknown", Created: u.GetCreationTimestamp().Time}
	spec, _ := u.Object["spec"].(map[string]any)
	for _, t := range issuerTypes {
		if _, ok := spec[t]; ok {
			is.Type = t
			break
		}
	}
	switch is.Type {
	case "acme":
		is.Server = str(u, "spec", "acme", "server")
	case "vault":
		is.Server = str(u, "spec", "vault", "server")
	}
	is.Ready, is.Reason, is.Message = statusCondition(u, "Ready")
	return is
}

func convertCertificateRequest(u *unstructured.Unstructured) model.CertificateRequest {
	r := model.CertificateRequest{
		Namespace: u.GetNamespace(), Name: u.GetName(), Created: u.GetCreationTimestamp().Time,
		Certificate: u.GetAnnotations()[certificateNameAnnotation],
	}
	r.IssuerKind, r.IssuerName = issuerRef(u)
	r.Ready, r.Reason, r.Message = statusCondition(u, "Ready")
	approved, _, _ := statusCondition(u, "Approved")
	denied, _, _ := statusCondition(u, "Denied")
	r.Approved, r.Denied = approved == "True", denied == "True"
	return r
}
