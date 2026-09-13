/*
Copyright 2026.

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

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	courierv1alpha1 "github.com/paimonsoror/courier/api/v1alpha1"
	"github.com/paimonsoror/courier/internal/request"
	"github.com/paimonsoror/courier/pkg/broker"
	"github.com/paimonsoror/courier/pkg/idp"
)

const (
	finalizerName  = "courier.sororlab.dev/cleanup"
	conditionReady = "Ready"
)

// OAuthClientReconciler translates OAuthClient objects into broker calls.
// All IdP and Vault logic lives in pkg/broker (ADR 0003).
type OAuthClientReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Broker *broker.Broker
	// ResyncPeriod re-converges Ready clients, repairing IdP-side drift.
	ResyncPeriod time.Duration
}

// +kubebuilder:rbac:groups=courier.sororlab.dev,resources=oauthclients,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=courier.sororlab.dev,resources=oauthclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=courier.sororlab.dev,resources=oauthclients/finalizers,verbs=update

// Reconcile converges one OAuthClient.
func (r *OAuthClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var oc courierv1alpha1.OAuthClient
	if err := r.Get(ctx, req.NamespacedName, &oc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	spec := request.ToClientSpec(&oc)

	if !oc.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&oc, finalizerName) {
			return ctrl.Result{}, nil
		}
		if err := r.Broker.Delete(ctx, spec); err != nil {
			r.setReady(&oc, metav1.ConditionFalse, "DeleteFailed", err.Error())
			if uerr := r.Status().Update(ctx, &oc); uerr != nil {
				log.Error(uerr, "update status")
			}
			return ctrl.Result{}, err
		}
		controllerutil.RemoveFinalizer(&oc, finalizerName)
		if err := r.Update(ctx, &oc); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("deleted client and destroyed credentials", "client", spec.Name)
		return ctrl.Result{}, nil
	}

	if err := request.CheckClient(&oc); err != nil {
		// Nothing was created; wait for the spec to change.
		r.setReady(&oc, metav1.ConditionFalse, "InvalidSpec", err.Error())
		return ctrl.Result{}, r.Status().Update(ctx, &oc)
	}

	if controllerutil.AddFinalizer(&oc, finalizerName) {
		if err := r.Update(ctx, &oc); err != nil {
			return ctrl.Result{}, err
		}
	}

	res, err := r.Broker.Ensure(ctx, spec, broker.Prior{Delivered: oc.Status.CredentialsDelivered})
	oc.Status.ObservedGeneration = oc.Generation
	oc.Status.IdentityProvider = r.Broker.IDP.Name()
	if res.Path != "" {
		oc.Status.SecretPath = res.Path
	}
	if err != nil {
		reason := "ReconcileFailed"
		if errors.Is(err, idp.ErrNotManaged) {
			reason = "NameConflict"
		}
		r.setReady(&oc, metav1.ConditionFalse, reason, err.Error())
		if uerr := r.Status().Update(ctx, &oc); uerr != nil {
			log.Error(uerr, "update status")
		}
		if reason == "NameConflict" {
			return ctrl.Result{}, nil // retrying cannot fix a name owned by someone else
		}
		return ctrl.Result{}, err
	}

	oc.Status.ClientID = res.Ref.ClientID
	oc.Status.CredentialsDelivered = true
	if res.SecretIssued {
		now := metav1.Now()
		oc.Status.LastSecretIssued = &now
		log.Info("issued credentials", "client", spec.Name, "clientId", res.Ref.ClientID, "path", res.Path)
	}
	r.setReady(&oc, metav1.ConditionTrue, "Delivered", fmt.Sprintf("credentials are available at %s", res.Path))
	if err := r.Status().Update(ctx, &oc); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.ResyncPeriod}, nil
}

func (r *OAuthClientReconciler) setReady(oc *courierv1alpha1.OAuthClient, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&oc.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: oc.Generation,
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *OAuthClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&courierv1alpha1.OAuthClient{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("oauthclient").
		Complete(r)
}
