package util

import (
	"k8s.io/apimachinery/pkg/api/equality"
	"open-cluster-management.io/api/addon/v1alpha1"
)

func EnsureObjectReference(refs []v1alpha1.ObjectReference, obj v1alpha1.ObjectReference) []v1alpha1.ObjectReference {
	for _, ref := range refs {
		if equality.Semantic.DeepEqual(ref, obj) {
			return refs
		}
	}
	return append(refs, obj)
}
