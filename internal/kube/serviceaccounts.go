package kube

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/ByronGary/kubesentry/internal/model"
)

// irsaRoleAnnotation names the IAM role a ServiceAccount's pods assume (IAM
// roles for service accounts). It links CloudTrail activity by that role to
// the workloads that run as the account.
const irsaRoleAnnotation = "eks.amazonaws.com/role-arn"

var serviceAccountAnnotations = keySet(irsaRoleAnnotation)

// transformServiceAccount keeps the identity and the IRSA role annotation.
// Accounts without one are stored this small too: the informer must hold
// every object to follow the watch, but only annotated ones are converted.
func transformServiceAccount(sa *corev1.ServiceAccount) {
	stripMeta(&sa.ObjectMeta, serviceAccountAnnotations)
	sa.Labels = nil
	sa.OwnerReferences = nil
	sa.Secrets, sa.ImagePullSecrets, sa.AutomountServiceAccountToken = nil, nil, nil
}

// hasIRSARole reports whether the account names an IAM role.
func hasIRSARole(sa *corev1.ServiceAccount) bool {
	return strings.TrimSpace(sa.Annotations[irsaRoleAnnotation]) != ""
}

func convertServiceAccount(sa *corev1.ServiceAccount) model.ServiceAccount {
	return model.ServiceAccount{Namespace: sa.Namespace, Name: sa.Name, RoleARN: strings.TrimSpace(sa.Annotations[irsaRoleAnnotation])}
}

// listServiceAccounts lists the ServiceAccounts with an IRSA role.
func (s *Source) listServiceAccounts(ctx context.Context) ([]model.ServiceAccount, error) {
	var out []model.ServiceAccount
	err := paginate("serviceaccounts", func(o metav1.ListOptions) (string, error) {
		l, err := s.cs.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			if hasIRSARole(&l.Items[i]) {
				out = append(out, convertServiceAccount(&l.Items[i]))
			}
		}
		return l.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
