package oauthclientscontroller

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	configv1 "github.com/openshift/api/config/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	routev1 "github.com/openshift/api/route/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	fakeoauthclient "github.com/openshift/client-go/oauth/clientset/versioned/fake"
	oauthv1listers "github.com/openshift/client-go/oauth/listers/oauth/v1"
	routev1listers "github.com/openshift/client-go/route/listers/route/v1"
	"github.com/openshift/library-go/pkg/oauth/oauthdiscovery"
	"github.com/openshift/library-go/pkg/operator/events"
)

const (
	masterPublicURL = "oauth-openshift.test.com"
)

var (
	defaultIngress = &configv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.IngressSpec{
			Domain: "test.com",
			ComponentRoutes: []configv1.ComponentRouteSpec{
				{Namespace: "openshift-authentication", Name: "oauth-openshift", Hostname: masterPublicURL},
			},
		},
	}

	ingressEmptyComponentRoutes = &configv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.IngressSpec{
			Domain:          "test.com",
			ComponentRoutes: []configv1.ComponentRouteSpec{},
		},
	}

	ingressEmptyDomain = &configv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec:       configv1.IngressSpec{Domain: ""},
	}

	defaultRoute = &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{Name: "oauth-openshift", Namespace: "openshift-authentication"},
		Spec:       routev1.RouteSpec{Host: masterPublicURL},
		Status: routev1.RouteStatus{
			Ingress: []routev1.RouteIngress{
				{
					Host: masterPublicURL,
					Conditions: []routev1.RouteIngressCondition{
						{Type: routev1.RouteAdmitted, Status: corev1.ConditionTrue},
					},
				},
			},
		},
	}

	routeUnexpectedNamespaceAndName = &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{Name: "not-oauth-openshift", Namespace: "not-openshift-authentication"},
	}
)

type fakeSyncContext struct{}

func (f fakeSyncContext) Queue() workqueue.RateLimitingInterface { return nil }
func (f fakeSyncContext) QueueKey() string                       { return "" }
func (f fakeSyncContext) Recorder() events.Recorder              { return nil }

func newIngressLister(t *testing.T, ingresses ...*configv1.Ingress) configv1listers.IngressLister {
	ingressIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

	for _, ingress := range ingresses {
		if err := ingressIndexer.Add(ingress); err != nil {
			t.Fatalf("got unexpected err when setting up test ingress: %v", err)
		}
	}

	return configv1listers.NewIngressLister(ingressIndexer)
}

func newRouteLister(t *testing.T, routes ...*routev1.Route) routev1listers.RouteLister {
	routeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

	for _, route := range routes {
		if err := routeIndexer.Add(route); err != nil {
			t.Errorf("got unexpected error while setting up test route: %v", err)
		}
	}

	return routev1listers.NewRouteLister(routeIndexer)
}

func newTestOAuthsClientsController(t *testing.T) *oauthsClientsController {
	return &oauthsClientsController{
		oauthClientClient: fakeoauthclient.NewSimpleClientset().OauthV1().OAuthClients(),
		oauthClientLister: oauthv1listers.NewOAuthClientLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})),
		routeLister:       newRouteLister(t, defaultRoute),
		ingressLister:     newIngressLister(t, defaultIngress),
	}
}

func Test_sync(t *testing.T) {
	ctx := context.TODO()
	syncCtx := &fakeSyncContext{}
	c := newTestOAuthsClientsController(t)

	tests := []struct {
		name              string
		withIngressLister configv1listers.IngressLister
		withRouteLister   routev1listers.RouteLister

		wantErr bool
	}{
		{"sync-success-non-empty-hostname", nil, nil, false},
		{"sync-success-empty-hostname", newIngressLister(t, ingressEmptyComponentRoutes), nil, false},
		{"ingress-config-error", newIngressLister(t), nil, true},
		{"canonical-route-host-error", nil, newRouteLister(t, routeUnexpectedNamespaceAndName), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.withIngressLister != nil {
				c.ingressLister = tt.withIngressLister
			}

			if tt.withRouteLister != nil {
				c.routeLister = tt.withRouteLister
			}

			err := c.sync(ctx, syncCtx)
			if (err != nil) != tt.wantErr {
				t.Errorf("got error: %v; want error: %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getIngressConfig(t *testing.T) {
	c := newTestOAuthsClientsController(t)

	tests := []struct {
		name              string
		withIngressLister configv1listers.IngressLister

		wantErr bool
	}{
		{"cluster-ingress-config-valid", nil, false},
		{"cluster-ingress-not-found", newIngressLister(t), true},
		{"cluster-ingress-domain-empty", newIngressLister(t, ingressEmptyDomain), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.withIngressLister != nil {
				c.ingressLister = tt.withIngressLister
			}

			_, err := c.getIngressConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("got error: %v; want error: %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getCanonicalRouteHost(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		newRouteNS   string
		newRouteName string

		expectedHost string
		wantErr      bool
	}{
		{"route-host-found", masterPublicURL, "", "", masterPublicURL, false},
		{"no-ingress-for-host-in-route", "redhat.com", "", "", "", true},
		{"route-not-found", masterPublicURL, "openshift-authentication", "not-oauth-openshift", "", true},
		{"namespace-not-found", masterPublicURL, "not-openshift-authentication", "oauth-openshift", "", true},
	}

	c := newTestOAuthsClientsController(t)

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if tt.newRouteNS != "" && tt.newRouteName != "" {
				c.routeLister = newRouteLister(t, &routev1.Route{
					ObjectMeta: metav1.ObjectMeta{Name: tt.newRouteName, Namespace: tt.newRouteNS},
				})
			}

			gotHost, err := c.getCanonicalRouteHost(tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("got error: %v; want error: %v", err, tt.wantErr)
			}

			if gotHost != tt.expectedHost {
				t.Errorf("unexpected canonical route host; got %v; want %v", gotHost, tt.expectedHost)
			}
		})
	}
}

func Test_ensureBootstrappedOAuthClients(t *testing.T) {
	ctx := context.TODO()

	t.Run("bootstrapped-oauth-clients-succeed", func(t *testing.T) {
		c := newTestOAuthsClientsController(t)

		if err := c.ensureBootstrappedOAuthClients(ctx, masterPublicURL); err != nil {
			t.Errorf("got unexpected error: %v", err)
		}
	})

	t.Run("bootstrapped-oauth-clients-fail", func(t *testing.T) {
		fakeClientset := fakeoauthclient.NewSimpleClientset()
		fakeClientset.PrependReactor("create", "oauthclients", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, nil, fmt.Errorf("%s %s fake error", action.GetVerb(), action.GetResource().Resource)
		})

		c := newTestOAuthsClientsController(t)
		c.oauthClientClient = fakeClientset.OauthV1().OAuthClients()

		if err := c.ensureBootstrappedOAuthClients(ctx, masterPublicURL); err == nil {
			t.Errorf("expected error but got nil")
		}
	})
}

func Test_randomBits(t *testing.T) {
	tests := []struct {
		bits        int
		expectedLen int
	}{
		{0, 0}, {1, 1}, {8, 1}, {16, 2}, {32, 4}, {64, 8}, {128, 16}, {256, 32}, {512, 64},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_bits", tt.bits), func(t *testing.T) {
			if got := randomBits(tt.bits); len(got) != tt.expectedLen {
				t.Errorf("got byte slice with length %d, want %d", len(got), tt.expectedLen)
			}
		})
	}
}

func Test_ensureOAuthClient(t *testing.T) {
	tests := []struct {
		name              string
		oauthClient       oauthv1.OAuthClient
		updateOAuthClient *oauthv1.OAuthClient

		wantCreateErr bool
		wantGetErr    bool
		wantUpdateErr bool
	}{
		{
			name:          "invalid-oauth-client-missing-name-grant-method",
			oauthClient:   oauthv1.OAuthClient{},
			wantCreateErr: true,
		},
		{
			name: "invalid-oauth-client-missing-name",
			oauthClient: oauthv1.OAuthClient{
				GrantMethod: oauthv1.GrantHandlerAuto,
			},
			wantCreateErr: true,
		},
		{
			name: "invalid-oauth-client-missing-grant-method",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta: metav1.ObjectMeta{Name: "invalid-client"},
			},
			wantCreateErr: true,
		},
		{
			name: "valid-oauth-client-already-exists-get-error",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta:  metav1.ObjectMeta{Name: "already-exists-get-error"},
				GrantMethod: oauthv1.GrantHandlerAuto,
			},
			updateOAuthClient: &oauthv1.OAuthClient{
				GrantMethod: oauthv1.GrantHandlerAuto,
			},
			wantGetErr: true,
		},
		{
			name: "valid-oauth-client-already-exists-update-error",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta:  metav1.ObjectMeta{Name: "already-exists-update-error"},
				GrantMethod: oauthv1.GrantHandlerAuto,
			},
			updateOAuthClient: &oauthv1.OAuthClient{
				GrantMethod: oauthv1.GrantHandlerPrompt,
			},
			wantUpdateErr: true,
		},
		{
			name: "openshift-browser-client",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta:            metav1.ObjectMeta{Name: "openshift-browser-client"},
				Secret:                base64.RawURLEncoding.EncodeToString(randomBits(256)),
				RespondWithChallenges: false,
				RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenDisplayURL(masterPublicURL)},
				GrantMethod:           oauthv1.GrantHandlerAuto,
			},
		},
		{
			name: "openshift-challenging-client",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta:            metav1.ObjectMeta{Name: "openshift-challenging-client"},
				Secret:                "",
				RespondWithChallenges: true,
				RedirectURIs:          []string{oauthdiscovery.OpenShiftOAuthTokenImplicitURL(masterPublicURL)},
				GrantMethod:           oauthv1.GrantHandlerAuto,
			},
		},
		{
			name: "openshift-cli-client",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta:   metav1.ObjectMeta{Name: "openshift-cli-client"},
				RedirectURIs: []string{"http://127.0.0.1/callback", "http://[::1]/callback"},
				GrantMethod:  oauthv1.GrantHandlerAuto,
			},
		},
		{
			name: "valid-oauth-client-minimal-client-grant-handler-auto",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta:  metav1.ObjectMeta{Name: "minimal-client-auto"},
				GrantMethod: oauthv1.GrantHandlerAuto,
			},
		},
		{
			name: "valid-oauth-client-minimal-client-grant-handler-prompt",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta:  metav1.ObjectMeta{Name: "minimal-client-prompt"},
				GrantMethod: oauthv1.GrantHandlerPrompt,
			},
		},
		{
			name: "valid-oauth-client-when-already-exists-without-updates",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta:            metav1.ObjectMeta{Name: "already-exists-without-updates"},
				RespondWithChallenges: true,
				RedirectURIs:          []string{"http://127.0.0.1/callback", "http://[::1]/callback"},
				GrantMethod:           oauthv1.GrantHandlerAuto,
				ScopeRestrictions: []oauthv1.ScopeRestriction{
					{ExactValues: []string{"val1"}},
				},
			},
			updateOAuthClient: &oauthv1.OAuthClient{
				RespondWithChallenges: true,
				RedirectURIs:          []string{"http://127.0.0.1/callback", "http://[::1]/callback"},
				GrantMethod:           oauthv1.GrantHandlerAuto,
				ScopeRestrictions: []oauthv1.ScopeRestriction{
					{ExactValues: []string{"val1"}},
				},
			},
		},
		{
			name: "valid-oauth-client-when-already-exists-with-updates",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta:            metav1.ObjectMeta{Name: "already-exists-with-updates"},
				RespondWithChallenges: true,
				RedirectURIs:          []string{"http://127.0.0.1/callback", "http://[::1]/callback"},
				GrantMethod:           oauthv1.GrantHandlerAuto,
				ScopeRestrictions: []oauthv1.ScopeRestriction{
					{ExactValues: []string{"val1"}},
				},
			},
			updateOAuthClient: &oauthv1.OAuthClient{
				RespondWithChallenges: false,
				RedirectURIs:          []string{"http://localhost/callback"},
				GrantMethod:           oauthv1.GrantHandlerPrompt,
				ScopeRestrictions: []oauthv1.ScopeRestriction{
					{ExactValues: []string{"val2"}},
				},
			},
		},
		{
			name: "valid-oauth-client-when-already-exists-with-updated-empty-secret",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta: metav1.ObjectMeta{Name: "already-exists-with-updated-empty-secret"},
				Secret:     "secret",
			},
			updateOAuthClient: &oauthv1.OAuthClient{
				Secret: "",
			},
		},
		{
			name: "valid-oauth-client-when-already-exists-with-updated-new-secret",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta: metav1.ObjectMeta{Name: "already-exists-with-updated-new-secret"},
			},
			updateOAuthClient: &oauthv1.OAuthClient{
				Secret: "secret",
			},
		},
		{
			name: "valid-oauth-client-when-already-exists-with-updated-longer-secret",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta: metav1.ObjectMeta{Name: "already-exists-with-updated-longer-secret"},
				Secret:     "secret",
			},
			updateOAuthClient: &oauthv1.OAuthClient{
				Secret: "secretbutlonger",
			},
		},
		{
			name: "valid-oauth-client-when-already-exists-with-updated-same-length-secret",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta: metav1.ObjectMeta{Name: "already-exists-with-updated-same-length-secret"},
				Secret:     "secret",
			},
			updateOAuthClient: &oauthv1.OAuthClient{
				Secret: "terces",
			},
		},
		{
			name: "valid-oauth-client-when-already-exists-with-updated-shorter-secret",
			oauthClient: oauthv1.OAuthClient{
				ObjectMeta: metav1.ObjectMeta{Name: "already-exists-with-updated-shorter-secret"},
				Secret:     "loooooooooooooongsecret",
			},
			updateOAuthClient: &oauthv1.OAuthClient{
				Secret: "secret",
			},
		},
	}

	var reactorErrorFunc = func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, fmt.Errorf("%s %s fake error", action.GetVerb(), action.GetResource().Resource)
	}

	ctx := context.TODO()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.updateOAuthClient != nil && tt.updateOAuthClient.Secret != "" && len(tt.updateOAuthClient.Secret) <= len(tt.oauthClient.Secret) {
				// TODO: ensureOAuthClient won't update the secret when it's the same length or shorter (but non-empty); skip test until fixed
				t.SkipNow()
			}

			fakeClientset := fakeoauthclient.NewSimpleClientset()

			// necessary reactor for ensureOAuthClient()
			if tt.wantCreateErr {
				fakeClientset.PrependReactor("create", "oauthclients", reactorErrorFunc)
			}

			c := newTestOAuthsClientsController(t)
			c.oauthClientClient = fakeClientset.OauthV1().OAuthClients()

			err := ensureOAuthClient(ctx, c.oauthClientClient, tt.oauthClient)
			if (err != nil) != tt.wantCreateErr {
				t.Fatalf("got error: %v; want error: %v", err, tt.wantCreateErr)
			}

			if err != nil {
				// do not continue the test if creation of the oauth client failed
				return
			}

			assertOAuthClient(ctx, t, c, &tt.oauthClient)

			// necessary reactors for ensureOAuthClient()->RetryOnConflict()
			if tt.wantGetErr {
				fakeClientset.PrependReactor("get", "oauthclients", reactorErrorFunc)
			}

			if tt.wantUpdateErr {
				fakeClientset.PrependReactor("update", "oauthclients", reactorErrorFunc)
			}

			c.oauthClientClient = fakeClientset.OauthV1().OAuthClients()
			if tt.updateOAuthClient != nil {
				tt.updateOAuthClient.Name = tt.oauthClient.Name
				err := ensureOAuthClient(ctx, c.oauthClientClient, *tt.updateOAuthClient)
				if (err != nil) != (tt.wantGetErr || tt.wantUpdateErr) {
					t.Fatalf("got error: %v; want error: %v", err, (tt.wantGetErr || tt.wantUpdateErr))
				}

				if err != nil {
					// do not continue the test if update of the oauth client failed
					return
				}

				assertOAuthClient(ctx, t, c, tt.updateOAuthClient)
			}
		})
	}
}

func assertOAuthClient(ctx context.Context, t *testing.T, c *oauthsClientsController, expected *oauthv1.OAuthClient) {
	got, err := c.oauthClientClient.Get(ctx, expected.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("got unexpected error while getting oauth client %s: %v", expected.Name, err)
	}

	if got.Secret != expected.Secret {
		t.Errorf("Secret got: %v, want :%v", got.Secret, expected.Secret)
	}

	if got.RespondWithChallenges != expected.RespondWithChallenges {
		t.Errorf("RespondWithChallenges got: %v, want :%v", got.RespondWithChallenges, expected.RespondWithChallenges)
	}

	if !reflect.DeepEqual(got.RedirectURIs, expected.RedirectURIs) {
		t.Errorf("RedirectURIs got: %v, want: %v", got.RedirectURIs, expected.RedirectURIs)
	}

	if got.GrantMethod != expected.GrantMethod {
		t.Errorf("GrantMethod got: %v, want :%v", got.GrantMethod, expected.GrantMethod)
	}

	if !reflect.DeepEqual(got.ScopeRestrictions, expected.ScopeRestrictions) {
		t.Errorf("ScopeRestrictions got: %v, want: %v", got.ScopeRestrictions, expected.ScopeRestrictions)
	}
}
