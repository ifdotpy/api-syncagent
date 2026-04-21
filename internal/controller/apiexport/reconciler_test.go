/*
Copyright 2026 The KCP Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package apiexport

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"

	kcpapisv1alpha1 "github.com/kcp-dev/sdk/apis/apis/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"
)

// newReconcilerForTest builds a minimal *Reconciler just for driving the
// reconcile closure. Only fields the reconciler touches are populated.
func newReconcilerForTest() *Reconciler {
	return &Reconciler{
		log: zap.NewNop().Sugar(),
	}
}

// drainEvents returns every Event emitted on the FakeRecorder so far as
// strings of the form "<TYPE> <REASON> <MESSAGE>".
func drainEvents(fr *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case e := <-fr.Events:
			events = append(events, e)
		default:
			return events
		}
	}
}

func runReconcileWithBuffer(t *testing.T, bufSize int, required sets.Set[permissionClaim], existing *kcpapisv1alpha1.APIExport) (*kcpapisv1alpha1.APIExport, []string) {
	t.Helper()
	fr := record.NewFakeRecorder(bufSize)
	r := newReconcilerForTest()
	factory := r.createAPIExportReconciler(
		sets.New[string](),
		required,
		"test-agent",
		"test.example.com",
		fr,
	)
	_, reconcile := factory()
	got, err := reconcile(existing)
	if err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}
	return got, drainEvents(fr)
}

func runReconcile(t *testing.T, required sets.Set[permissionClaim], existing *kcpapisv1alpha1.APIExport) (*kcpapisv1alpha1.APIExport, []string) {
	return runReconcileWithBuffer(t, 10, required, existing)
}

// TestCreateAPIExportReconcilerUpgradesEmptyClaimInPlace covers the main bug:
// an existing PermissionClaim for a required (Group, Resource) that has
// neither All=true nor a ResourceSelector — the shape KCP produces when a
// v1alpha2-native claim with verbs:["*"] is read via v1alpha1 conversion —
// must be upgraded in place to All=true, not left in place (which would fail
// KCP validation) and not appended to (which would duplicate the GR and also
// fail KCP validation).
func TestCreateAPIExportReconcilerUpgradesEmptyClaimInPlace(t *testing.T) {
	existing := &kcpapisv1alpha1.APIExport{
		ObjectMeta: metav1.ObjectMeta{Name: "test.example.com"},
		Spec: kcpapisv1alpha1.APIExportSpec{
			PermissionClaims: []kcpapisv1alpha1.PermissionClaim{{
				// Fingerprint of a v1alpha2-written claim read via v1alpha1:
				// no All, no ResourceSelector.
				GroupResource: kcpapisv1alpha1.GroupResource{Resource: "events"},
			}},
		},
	}

	got, _ := runReconcile(t, sets.New(permissionClaim{Resource: "events"}), existing)

	if len(got.Spec.PermissionClaims) != 1 {
		t.Fatalf("expected exactly 1 PermissionClaim for (core, events), got %d: %+v",
			len(got.Spec.PermissionClaims), got.Spec.PermissionClaims)
	}
	want := kcpapisv1alpha1.PermissionClaim{
		GroupResource: kcpapisv1alpha1.GroupResource{Resource: "events"},
		All:           true,
	}
	if !reflect.DeepEqual(got.Spec.PermissionClaims[0], want) {
		t.Errorf("upgraded claim = %+v, want %+v", got.Spec.PermissionClaims[0], want)
	}
	if _, present := got.Annotations[PermissionClaimConflictsAnnotation]; present {
		t.Errorf("no conflicts expected, but conflict annotation is set: %q",
			got.Annotations[PermissionClaimConflictsAnnotation])
	}
}

// TestCreateAPIExportReconcilerUpgradesEmptySliceResourceSelectorInPlace guards
// against treating an empty-but-non-nil ResourceSelector slice differently
// from a nil one. len() on both is 0, so both should upgrade.
func TestCreateAPIExportReconcilerUpgradesEmptySliceResourceSelectorInPlace(t *testing.T) {
	existing := &kcpapisv1alpha1.APIExport{
		ObjectMeta: metav1.ObjectMeta{Name: "test.example.com"},
		Spec: kcpapisv1alpha1.APIExportSpec{
			PermissionClaims: []kcpapisv1alpha1.PermissionClaim{{
				GroupResource:    kcpapisv1alpha1.GroupResource{Resource: "events"},
				ResourceSelector: []kcpapisv1alpha1.ResourceSelector{}, // empty slice, not nil
			}},
		},
	}

	got, _ := runReconcile(t, sets.New(permissionClaim{Resource: "events"}), existing)

	if len(got.Spec.PermissionClaims) != 1 {
		t.Fatalf("expected 1 PermissionClaim, got %d", len(got.Spec.PermissionClaims))
	}
	if !got.Spec.PermissionClaims[0].All {
		t.Errorf("claim with empty-slice ResourceSelector should be upgraded: %+v", got.Spec.PermissionClaims[0])
	}
}

// TestCreateAPIExportReconcilerPreservesAdminAuthoredNarrowClaim guards
// against a silent privilege expansion. If an operator intentionally scoped
// a claim via ResourceSelector, the agent must not silently widen it to
// All=true just because the (Group, Resource) is in the agent's required
// set. The CRD forbids two claims with the same GR, so the agent also must
// not append a broader claim. Correct behaviour: leave the existing claim
// bitwise-intact, set a persistent conflict annotation so the state is
// visible via plain kubectl inspection, and emit a single aggregated
// Warning event.
func TestCreateAPIExportReconcilerPreservesAdminAuthoredNarrowClaim(t *testing.T) {
	original := kcpapisv1alpha1.PermissionClaim{
		GroupResource:    kcpapisv1alpha1.GroupResource{Resource: "events"},
		ResourceSelector: []kcpapisv1alpha1.ResourceSelector{{Name: "scoped-by-admin", Namespace: "ns-a"}},
	}
	existing := &kcpapisv1alpha1.APIExport{
		ObjectMeta: metav1.ObjectMeta{Name: "test.example.com"},
		Spec: kcpapisv1alpha1.APIExportSpec{
			PermissionClaims: []kcpapisv1alpha1.PermissionClaim{*original.DeepCopy()},
		},
	}

	got, events := runReconcile(t, sets.New(permissionClaim{Resource: "events"}), existing)

	if len(got.Spec.PermissionClaims) != 1 {
		t.Fatalf("expected exactly 1 PermissionClaim, got %d: %+v",
			len(got.Spec.PermissionClaims), got.Spec.PermissionClaims)
	}
	if !reflect.DeepEqual(got.Spec.PermissionClaims[0], original) {
		t.Errorf("admin-scoped claim was mutated:\n got: %+v\nwant: %+v", got.Spec.PermissionClaims[0], original)
	}
	wantAnnotation := "narrow:events"
	if got.Annotations[PermissionClaimConflictsAnnotation] != wantAnnotation {
		t.Errorf("conflict annotation = %q, want %q",
			got.Annotations[PermissionClaimConflictsAnnotation], wantAnnotation)
	}
	if !hasEventReason(events, "NarrowerPermissionClaimPreserved") {
		t.Errorf("expected a Warning/NarrowerPermissionClaimPreserved event, got: %v", events)
	}
}

// TestCreateAPIExportReconcilerSurfacesInvalidClaimShape covers an invalid
// existing claim that has both `All=true` AND a non-empty `ResourceSelector`
// (forbidden by the CRD's XValidation). The reconciler must not try to
// "normalize" the data — it can't know the admin's intent — and must not
// silently pass it through as if normal. It must leave the claim intact,
// set a persistent conflict annotation on the APIExport, and emit a
// Warning event.
func TestCreateAPIExportReconcilerSurfacesInvalidClaimShape(t *testing.T) {
	malformed := kcpapisv1alpha1.PermissionClaim{
		GroupResource:    kcpapisv1alpha1.GroupResource{Resource: "events"},
		All:              true,
		ResourceSelector: []kcpapisv1alpha1.ResourceSelector{{Name: "oops"}},
	}
	existing := &kcpapisv1alpha1.APIExport{
		ObjectMeta: metav1.ObjectMeta{Name: "test.example.com"},
		Spec: kcpapisv1alpha1.APIExportSpec{
			PermissionClaims: []kcpapisv1alpha1.PermissionClaim{*malformed.DeepCopy()},
		},
	}

	got, events := runReconcile(t, sets.New(permissionClaim{Resource: "events"}), existing)

	if len(got.Spec.PermissionClaims) != 1 {
		t.Fatalf("expected 1 PermissionClaim, got %d: %+v",
			len(got.Spec.PermissionClaims), got.Spec.PermissionClaims)
	}
	if !reflect.DeepEqual(got.Spec.PermissionClaims[0], malformed) {
		t.Errorf("malformed claim was mutated (it should be left intact so CRD admission rejects):\n got: %+v\nwant: %+v",
			got.Spec.PermissionClaims[0], malformed)
	}
	wantAnnotation := "invalid:events"
	if got.Annotations[PermissionClaimConflictsAnnotation] != wantAnnotation {
		t.Errorf("conflict annotation = %q, want %q",
			got.Annotations[PermissionClaimConflictsAnnotation], wantAnnotation)
	}
	if !hasEventReason(events, "InvalidPermissionClaim") {
		t.Errorf("expected a Warning/InvalidPermissionClaim event, got: %v", events)
	}
}

// TestCreateAPIExportReconcilerClearsStaleConflictAnnotation ensures that
// when previously-recorded conflicts are resolved (e.g. an admin fixed a
// narrow claim to be wildcard), the annotation is removed on the next
// reconcile so operators aren't chasing an alert that no longer applies.
func TestCreateAPIExportReconcilerClearsStaleConflictAnnotation(t *testing.T) {
	existing := &kcpapisv1alpha1.APIExport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test.example.com",
			Annotations: map[string]string{
				PermissionClaimConflictsAnnotation: "narrow:events",
			},
		},
		Spec: kcpapisv1alpha1.APIExportSpec{
			PermissionClaims: []kcpapisv1alpha1.PermissionClaim{{
				GroupResource: kcpapisv1alpha1.GroupResource{Resource: "events"},
				All:           true, // admin fixed it to wildcard
			}},
		},
	}

	got, _ := runReconcile(t, sets.New(permissionClaim{Resource: "events"}), existing)

	if _, present := got.Annotations[PermissionClaimConflictsAnnotation]; present {
		t.Errorf("stale conflict annotation should be cleared once the claim is valid, but got: %q",
			got.Annotations[PermissionClaimConflictsAnnotation])
	}
}

// TestCreateAPIExportReconcilerAggregatesManyConflictsIntoOneEvent is a
// regression test for the event-emission path under load. Previously, we
// emitted one Warning event per conflicting claim inside the loop; with
// client-go's FakeRecorder using a blocking-send buffered channel, a
// reconcile encountering more claims than the buffer size would deadlock.
// The aggregated-event design emits at most one event per reason per
// reconcile, so the test drives many conflicts through a small-buffer
// recorder and just asserts reconcile returns.
func TestCreateAPIExportReconcilerAggregatesManyConflictsIntoOneEvent(t *testing.T) {
	const conflicts = 50
	var required sets.Set[permissionClaim] = sets.New[permissionClaim]()
	var claims []kcpapisv1alpha1.PermissionClaim
	for i := 0; i < conflicts; i++ {
		resource := fmt.Sprintf("r%d", i)
		required.Insert(permissionClaim{Resource: resource})
		// admin-scoped narrow claim for this GR
		claims = append(claims, kcpapisv1alpha1.PermissionClaim{
			GroupResource:    kcpapisv1alpha1.GroupResource{Resource: resource},
			ResourceSelector: []kcpapisv1alpha1.ResourceSelector{{Name: "x"}},
		})
	}
	existing := &kcpapisv1alpha1.APIExport{
		ObjectMeta: metav1.ObjectMeta{Name: "test.example.com"},
		Spec:       kcpapisv1alpha1.APIExportSpec{PermissionClaims: claims},
	}

	// Buffer smaller than the number of conflicts. If we ever regress to
	// per-claim events, reconcile will block forever here and the test
	// will time out.
	got, events := runReconcileWithBuffer(t, 2, required, existing)

	narrowEvents := 0
	for _, e := range events {
		if strings.Contains(e, " NarrowerPermissionClaimPreserved ") {
			narrowEvents++
		}
	}
	if narrowEvents != 1 {
		t.Errorf("expected exactly 1 aggregated NarrowerPermissionClaimPreserved event, got %d: %v",
			narrowEvents, events)
	}
	// Annotation should list every conflict, sorted.
	ann := got.Annotations[PermissionClaimConflictsAnnotation]
	if strings.Count(ann, "narrow:") != conflicts {
		t.Errorf("annotation should list all %d conflicts, got: %q", conflicts, ann)
	}
}

// TestCreateAPIExportReconcilerBoundsConflictAnnotationSize ensures the
// conflict annotation stays comfortably below Kubernetes'
// TotalAnnotationSizeLimitB (256 KiB) even when the conflict set is huge.
// Without the bound, a pathological deployment could write an annotation
// larger than the limit and block every APIExport update at admission —
// turning the observability path into a reconcile blocker.
func TestCreateAPIExportReconcilerBoundsConflictAnnotationSize(t *testing.T) {
	var claims []kcpapisv1alpha1.PermissionClaim
	required := sets.New[permissionClaim]()
	// Enough entries with long-ish resource names to far exceed the cap
	// if we didn't truncate. (1000 × ~50 bytes = ~50 KB, well over 8 KB.)
	const n = 1000
	for i := 0; i < n; i++ {
		resource := fmt.Sprintf("very-long-resource-name-for-bounds-testing-%05d", i)
		required.Insert(permissionClaim{Resource: resource})
		claims = append(claims, kcpapisv1alpha1.PermissionClaim{
			GroupResource:    kcpapisv1alpha1.GroupResource{Resource: resource},
			ResourceSelector: []kcpapisv1alpha1.ResourceSelector{{Name: "x"}},
		})
	}
	existing := &kcpapisv1alpha1.APIExport{
		ObjectMeta: metav1.ObjectMeta{Name: "test.example.com"},
		Spec:       kcpapisv1alpha1.APIExportSpec{PermissionClaims: claims},
	}

	got, _ := runReconcile(t, required, existing)

	ann := got.Annotations[PermissionClaimConflictsAnnotation]
	if len(ann) > maxConflictAnnotationBytes {
		t.Errorf("annotation length %d exceeds cap %d", len(ann), maxConflictAnnotationBytes)
	}
	if !strings.Contains(ann, "more") {
		t.Errorf("annotation should contain a truncation marker for %d conflicts, got: %q (len %d)",
			n, ann[:min(200, len(ann))], len(ann))
	}
}

// TestCreateAPIExportReconcilerAppendsMissingClaim covers the simple case
// where the required GR is not present at all: the agent appends a single
// new {All:true} claim.
func TestCreateAPIExportReconcilerAppendsMissingClaim(t *testing.T) {
	existing := &kcpapisv1alpha1.APIExport{
		ObjectMeta: metav1.ObjectMeta{Name: "test.example.com"},
	}

	got, _ := runReconcile(t, sets.New(permissionClaim{Resource: "events"}), existing)

	if len(got.Spec.PermissionClaims) != 1 {
		t.Fatalf("expected 1 appended PermissionClaim, got %d: %+v",
			len(got.Spec.PermissionClaims), got.Spec.PermissionClaims)
	}

	claim := got.Spec.PermissionClaims[0]
	if claim.Resource != "events" || !claim.All {
		t.Errorf("expected appended {events, All:true}; got %+v", claim)
	}
}

// hasEventReason returns true when any of the FakeRecorder's string-encoded
// events contains the given Reason. FakeRecorder formats events as
// "<TYPE> <REASON> <MESSAGE>".
func hasEventReason(events []string, reason string) bool {
	for _, e := range events {
		if strings.Contains(e, " "+reason+" ") {
			return true
		}
	}
	return false
}
