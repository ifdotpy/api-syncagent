/*
Copyright 2025 The KCP Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apiexport

import (
	"fmt"
	"slices"
	"strings"

	"go.uber.org/zap"

	"github.com/kcp-dev/api-syncagent/internal/resources/reconciling"
	syncagentv1alpha1 "github.com/kcp-dev/api-syncagent/sdk/apis/syncagent/v1alpha1"

	kcpapisv1alpha1 "github.com/kcp-dev/sdk/apis/apis/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
)

// permissionClaim is the same as kcp's PermissionClaim, just trimmed down to
// kind, group and identity and more importantly, without all the other fields
// that makes this struct not comparable (i.e. not suitable for a Set).
type permissionClaim struct {
	Group        string
	Resource     string
	IdentityHash string
}

func (c permissionClaim) String() string {
	if c.Group == "" {
		return c.Resource
	}

	return fmt.Sprintf("%s/%s", c.Group, c.Resource)
}

// createAPIExportReconciler creates the reconciler for the APIExport.
// WARNING: The APIExport in this is NOT created by the Sync Agent, it's created
// by a controller in kcp. Make sure you don't create a reconciling conflict!
func (r *Reconciler) createAPIExportReconciler(
	availableResourceSchemas sets.Set[string],
	claimedResourceKinds sets.Set[permissionClaim],
	agentName string,
	apiExportName string,
	recorder record.EventRecorder,
) reconciling.NamedAPIExportReconcilerFactory {
	return func() (string, reconciling.APIExportReconciler) {
		return apiExportName, func(existing *kcpapisv1alpha1.APIExport) (*kcpapisv1alpha1.APIExport, error) {
			if existing.Annotations == nil {
				existing.Annotations = map[string]string{}
			}
			existing.Annotations[syncagentv1alpha1.AgentNameAnnotation] = agentName

			// combine existing schemas with new ones
			newSchemas := mergeResourceSchemas(existing.Spec.LatestResourceSchemas, availableResourceSchemas)
			createSchemaEvents(existing, existing.Spec.LatestResourceSchemas, newSchemas, recorder)

			existing.Spec.LatestResourceSchemas = newSchemas

			// To allow admins to configure additional permission claims, sometimes
			// useful for debugging, we do not override the permission claims, but
			// only ensure the ones originating from the published resources.
			// Matching is done by (Group, Resource) — the identity v1alpha1
			// enforces at the CRD level. If an existing claim for a matching GR
			// already grants wildcard access (All=true with no ResourceSelector),
			// it is broad enough; otherwise the agent upgrades that claim
			// in-place rather than appending a duplicate, which KCP validation
			// would reject.
			type claimKey struct {
				Group    string
				Resource string
			}

			requiredClaims := map[claimKey]permissionClaim{}
			for _, claimed := range claimedResourceKinds.UnsortedList() {
				key := claimKey{Group: claimed.Group, Resource: claimed.Resource}
				if _, exists := requiredClaims[key]; !exists {
					requiredClaims[key] = claimed
				}
			}

			existingByGR := map[claimKey]int{}
			var changedClaims []string
			// Conflicts we couldn't safely resolve. Surfaced after the loop
			// as (a) an aggregated Warning event and (b) a persistent
			// annotation on the APIExport, so the operator sees a durable
			// signal rather than ephemeral events.
			var invalidConflicts, narrowConflicts []string
			for i, claim := range existing.Spec.PermissionClaims {
				key := claimKey{Group: claim.Group, Resource: claim.Resource}
				if _, exists := existingByGR[key]; !exists {
					existingByGR[key] = i
				}

				required, managed := requiredClaims[key]
				if !managed {
					continue
				}
				if claim.All && len(claim.ResourceSelector) == 0 {
					// Already broad enough.
					continue
				}
				if claim.All && len(claim.ResourceSelector) > 0 {
					// Invalid shape: the CRD's XValidation rule requires
					// exactly one of `all` or non-empty `resourceSelector`,
					// not both. This didn't come from a normal kcp API
					// write — likely version skew or a hand-edit. We can't
					// safely "fix" the claim because we don't know which
					// side reflects admin intent; record the conflict so
					// the operator can see it and leave the claim intact.
					invalidConflicts = append(invalidConflicts, required.String())
					continue
				}
				if len(claim.ResourceSelector) > 0 {
					// The existing claim looks admin-authored (narrowed via
					// a ResourceSelector, no All). Do not silently widen it
					// to All=true; the CRD allows only one claim per
					// (Group, Resource), so we also can't append a broader
					// claim. Leave it alone and record the conflict — the
					// sync-agent's operation on this GR may be impaired
					// by the narrower selector, which is an admin choice
					// to honour, not silently override.
					narrowConflicts = append(narrowConflicts, required.String())
					continue
				}

				// Existing claim has neither All=true nor a ResourceSelector —
				// the fingerprint of a v1alpha2-authored claim whose `verbs`
				// got dropped during v1alpha2→v1alpha1 conversion. Upgrade in
				// place so we don't append a duplicate with the same GR.
				existing.Spec.PermissionClaims[i].All = true
				changedClaims = append(changedClaims, required.String())
			}

			// Surface any unresolved conflicts via a persistent annotation
			// on the APIExport (so operators can see the state with a plain
			// kubectl-get / describe, not just ephemeral events) and a
			// single aggregated Warning event per reconcile (so we don't
			// fill a small FakeRecorder buffer in tests or spam real event
			// streams when many claims conflict). Clearing the annotation
			// on resolution forces an Update so the signal disappears.
			updateConflictAnnotation(existing, invalidConflicts, narrowConflicts)
			emitConflictEvents(recorder, existing, r.log, apiExportName, invalidConflicts, narrowConflicts)

			var claimsToAdd []permissionClaim
			for key, claimed := range requiredClaims {
				if _, exists := existingByGR[key]; exists {
					continue
				}
				claimsToAdd = append(claimsToAdd, claimed)
			}
			slices.SortStableFunc(claimsToAdd, func(a, b permissionClaim) int {
				if a.Group != b.Group {
					return strings.Compare(a.Group, b.Group)
				}

				return strings.Compare(a.Resource, b.Resource)
			})

			// add our missing claims
			for _, claimed := range claimsToAdd {
				existing.Spec.PermissionClaims = append(existing.Spec.PermissionClaims, kcpapisv1alpha1.PermissionClaim{
					GroupResource: kcpapisv1alpha1.GroupResource{
						Group:    claimed.Group,
						Resource: claimed.Resource,
					},
					All:          true,
					IdentityHash: claimed.IdentityHash,
				})
				changedClaims = append(changedClaims, claimed.String())
			}

			if len(changedClaims) > 0 {
				slices.Sort(changedClaims)
				recorder.Eventf(existing, corev1.EventTypeNormal, "EnsuringPermissionClaims", "Ensured permission claim(s) for all %s.", strings.Join(changedClaims, ", "))
			}

			// prevent reconcile loops by ensuring a stable order
			slices.SortFunc(existing.Spec.PermissionClaims, func(a, b kcpapisv1alpha1.PermissionClaim) int {
				if a.Group != b.Group {
					return strings.Compare(a.Group, b.Group)
				}

				if a.Resource != b.Resource {
					return strings.Compare(a.Resource, b.Resource)
				}

				return 0
			})

			return existing, nil
		}
	}
}

func mergeResourceSchemas(existing []string, configured sets.Set[string]) []string {
	var result []string

	// first we copy all ARS that are coming from the PublishedResources
	knownResources := sets.New[string]()
	for _, schema := range configured.UnsortedList() {
		result = append(result, schema)
		knownResources.Insert(parseResourceGroup(schema))
	}

	// Now we include all other existing ARS that use unknown resources;
	// this both allows an APIExport to contain "unmanaged" ARS, and also
	// will purposefully leave behind ARS for deleted PublishedResources,
	// allowing cleanup to take place outside of the agent's control.
	for _, schema := range existing {
		if !knownResources.Has(parseResourceGroup(schema)) {
			result = append(result, schema)
		}
	}

	// for stability and beauty, sort the schemas
	slices.SortFunc(result, func(a, b string) int {
		return strings.Compare(parseResourceGroup(a), parseResourceGroup(b))
	})

	return result
}

func createSchemaEvents(obj runtime.Object, oldSchemas, newSchemas []string, recorder record.EventRecorder) {
	oldSet := sets.New(oldSchemas...)
	newSet := sets.New(newSchemas...)

	if change := sets.List(newSet.Difference(oldSet)); len(change) > 0 {
		recorder.Eventf(obj, corev1.EventTypeNormal, "AddingResourceSchemas", "Added new resource schema(s) %s.", strings.Join(change, ", "))
	}

	if change := sets.List(oldSet.Difference(newSet)); len(change) > 0 {
		recorder.Eventf(obj, corev1.EventTypeWarning, "RemovingResourceSchemas", "Removed resource schema(s) %s.", strings.Join(change, ", "))
	}
}

// PermissionClaimConflictsAnnotation lists unresolved PermissionClaim
// conflicts detected by the sync-agent's reconciler. Format:
// "narrow:group/resource,invalid:group/resource,...". The value is bounded
// — pathological conflict counts are truncated with a ",...+N more" suffix
// so the annotation cannot exceed the per-object 256 KiB annotation budget
// (see `k8s.io/apimachinery/pkg/api/validation.TotalAnnotationSizeLimitB`)
// and block APIExport updates. Full detail lives in Warning events and
// logs. Operators can see current state via `kubectl get/describe
// apiexport`; the annotation is cleared when all conflicts resolve.
const PermissionClaimConflictsAnnotation = "syncagent.kcp.io/permission-claim-conflicts"

// maxConflictAnnotationBytes caps the serialized conflict annotation well
// below Kubernetes' per-object 256 KiB annotation budget, leaving room for
// other annotations on the APIExport. 8 KiB accommodates hundreds of
// typical conflict entries; larger conflict sets are truncated with a
// "+N more" marker (full detail is still emitted via Warning events).
const maxConflictAnnotationBytes = 8 * 1024

// updateConflictAnnotation sets (or clears) the permission-claim-conflicts
// annotation on the APIExport based on the current conflict sets.
func updateConflictAnnotation(obj *kcpapisv1alpha1.APIExport, invalid, narrow []string) {
	if len(invalid) == 0 && len(narrow) == 0 {
		delete(obj.Annotations, PermissionClaimConflictsAnnotation)
		return
	}
	entries := make([]string, 0, len(invalid)+len(narrow))
	for _, c := range invalid {
		entries = append(entries, "invalid:"+c)
	}
	for _, c := range narrow {
		entries = append(entries, "narrow:"+c)
	}
	slices.Sort(entries)
	if obj.Annotations == nil {
		obj.Annotations = map[string]string{}
	}
	obj.Annotations[PermissionClaimConflictsAnnotation] = joinBoundedCSV(entries, maxConflictAnnotationBytes)
}

// joinBoundedCSV joins entries with commas, truncating once the total would
// exceed maxBytes and appending a ",...+N more" suffix so operators can see
// there are additional conflicts beyond what fits. Entries must not contain
// commas; caller passes them sorted for stable output.
func joinBoundedCSV(entries []string, maxBytes int) string {
	if len(entries) == 0 {
		return ""
	}
	// Reserve enough headroom for the truncation suffix: ",...+" (5) plus
	// an int big enough for any realistic count plus " more" (5). 32 bytes
	// is plenty (handles counts up to ~10^22).
	const truncSuffixReserve = 32
	var b strings.Builder
	for i, e := range entries {
		sep := 0
		if b.Len() > 0 {
			sep = 1
		}
		// If adding this entry plus a possible truncation suffix would
		// exceed the budget, stop and emit the suffix instead.
		if b.Len()+sep+len(e)+truncSuffixReserve > maxBytes && i < len(entries)-1 {
			remaining := len(entries) - i
			if b.Len() > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "...+%d more", remaining)
			return b.String()
		}
		if sep > 0 {
			b.WriteByte(',')
		}
		b.WriteString(e)
	}
	return b.String()
}

// emitConflictEvents emits at most one aggregated Warning event per conflict
// category per reconcile. Aggregation bounds the number of channel sends so
// a small-buffer FakeRecorder in tests cannot block, and so event streams
// on real clusters don't get flooded when many claims conflict at once.
func emitConflictEvents(recorder record.EventRecorder, obj runtime.Object, log *zap.SugaredLogger, apiExportName string, invalid, narrow []string) {
	if len(invalid) > 0 {
		slices.Sort(invalid)
		recorder.Eventf(obj, corev1.EventTypeWarning,
			"InvalidPermissionClaim",
			"Permission claim(s) for %s have both all=true and resourceSelector set; CRD validation requires exactly one. Fix the claim(s) before the sync-agent can reconcile the APIExport.",
			strings.Join(invalid, ", "))
		log.Warnw(
			"existing PermissionClaim(s) have both All=true and ResourceSelector set (invalid per CRD); leaving intact",
			"apiExport", apiExportName,
			"claims", invalid,
		)
	}
	if len(narrow) > 0 {
		slices.Sort(narrow)
		recorder.Eventf(obj, corev1.EventTypeWarning,
			"NarrowerPermissionClaimPreserved",
			"Permission claim(s) for %s have a narrower ResourceSelector than the sync-agent needs; preserving the admin-authored scope. The sync-agent may not be able to access objects outside these selector(s).",
			strings.Join(narrow, ", "))
		log.Warnw(
			"existing PermissionClaim(s) narrower than sync-agent needs; leaving admin-authored claim(s) intact",
			"apiExport", apiExportName,
			"claims", narrow,
		)
	}
}

func parseResourceGroup(schema string) string {
	gvr, _ := parseSchemaName(schema)
	return gvr.GroupResource().String()
}

// parseSchemaName parses an APIResourceSchema name and returns it in form of
// a GVR. Note: the version in the result will not be a Kubernetes version, but
// the version of the ARS!
func parseSchemaName(name string) (schema.GroupVersionResource, error) {
	// <version>.<resource>.<group>
	parts := strings.SplitN(name, ".", 3)
	if len(parts) != 3 {
		return schema.GroupVersionResource{}, fmt.Errorf("invalid schema name %q, must consist of version.resource.group", name)
	}

	return schema.GroupVersionResource{
		Group:    parts[2],
		Version:  parts[0],
		Resource: parts[1],
	}, nil
}
