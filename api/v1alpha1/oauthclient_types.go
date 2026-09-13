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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// OAuthClientSpec is a request for an OAuth client owned by the team whose
// namespace it lives in.
// +kubebuilder:validation:XValidation:rule="self.clientType == 'confidential' || !self.grantTypes.exists(g, g == 'client_credentials')",message="client_credentials requires clientType confidential"
// +kubebuilder:validation:XValidation:rule="!self.grantTypes.exists(g, g == 'authorization_code') || (has(self.redirectUris) && size(self.redirectUris) > 0)",message="authorization_code requires at least one redirect URI"
type OAuthClientSpec struct {
	// displayName is shown in the identity provider. Defaults to <namespace>/<name>.
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// ownerGroup is the IdP group that owns the client and can read its
	// credentials. It must equal the namespace; empty means the namespace.
	// +optional
	OwnerGroup string `json:"ownerGroup,omitempty"`

	// clientType is public (PKCE, no secret) or confidential (secret delivered to Vault).
	// +kubebuilder:validation:Enum=public;confidential
	ClientType string `json:"clientType"`

	// grantTypes the client may use.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Enum=authorization_code;refresh_token;client_credentials
	// +listType=set
	GrantTypes []string `json:"grantTypes"`

	// redirectUris must be https, except http loopback for public clients.
	// +optional
	// +listType=set
	RedirectURIs []string `json:"redirectUris,omitempty"`

	// scopes requested by the client. Defaults to [openid].
	// +optional
	// +listType=set
	Scopes []string `json:"scopes,omitempty"`

	// allowGroups may sign in through the client. Defaults to the owner group.
	// +optional
	// +listType=set
	AllowGroups []string `json:"allowGroups,omitempty"`
}

// OAuthClientStatus reports what Courier delivered. It never contains the secret.
type OAuthClientStatus struct {
	// observedGeneration is the spec generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// identityProvider is the adapter that manages the client.
	// +optional
	IdentityProvider string `json:"identityProvider,omitempty"`

	// clientId of the client in the identity provider. Not sensitive.
	// +optional
	ClientID string `json:"clientId,omitempty"`

	// secretPath is where the owning team reads the credentials.
	// +optional
	SecretPath string `json:"secretPath,omitempty"`

	// credentialsDelivered is true once credentials were stored and are live.
	// +optional
	CredentialsDelivered bool `json:"credentialsDelivered,omitempty"`

	// lastSecretIssued is when Courier last generated a client secret.
	// +optional
	LastSecretIssued *metav1.Time `json:"lastSecretIssued,omitempty"`

	// conditions: Ready is True when the client exists and credentials are available.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=oac
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.clientType`
// +kubebuilder:printcolumn:name="Client ID",type=string,JSONPath=`.status.clientId`
// +kubebuilder:printcolumn:name="Secret Path",type=string,JSONPath=`.status.secretPath`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OAuthClient requests an OAuth client in the identity provider, with its
// credentials delivered to the owning team's Vault path.
type OAuthClient struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of OAuthClient
	// +required
	Spec OAuthClientSpec `json:"spec"`

	// status defines the observed state of OAuthClient
	// +optional
	Status OAuthClientStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// OAuthClientList contains a list of OAuthClient
type OAuthClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []OAuthClient `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &OAuthClient{}, &OAuthClientList{})
		return nil
	})
}
