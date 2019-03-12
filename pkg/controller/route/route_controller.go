package route

import (
	"context"
	"time"

	routev1 "github.com/openshift/api/route/v1"
	v1 "github.com/openshift/api/route/v1"
	"github.com/redhat-cop/openshift-cert-controller/pkg/certs"
	certconf "github.com/redhat-cop/openshift-cert-controller/pkg/config"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	timeFormat = "Jan 2 15:04:05 2006"
)

var log = logf.Log.WithName("controller_route")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new Route Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, config certconf.Config) error {
	return add(mgr, newReconciler(mgr, config))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, config certconf.Config) reconcile.Reconciler {

	var provider certs.Provider

	if config.Provider.Ssl == "true" {
		// logrus.Infof("SSL Verified")
		log.Info("SSL Verified")
	} else {
		// logrus.Infof("SSL Not Verified")
		log.Info("SSL Not Verified")
	}

	switch config.Provider.Kind {
	case "none":
		// logrus.Infof("None provider.")
		log.Info("None provider.")
		provider = new(certs.NoneProvider)
	case "self-signed":
		// logrus.Infof("Self Signed provider.")
		log.Info("Self Signed provider.")
		provider = new(certs.SelfSignedProvider)
	case "venafi":
		// logrus.Infof("Venafi Cert provider.")
		provider = new(certs.VenafiProvider)
	default:
		panic("There was a problem detecting which provider to configure. \n" +
			"\tProvider kind `" + config.Provider.Kind + "` is invalid. \n" +
			config.String())
	}

	return &ReconcileRoute{client: mgr.GetClient(), scheme: mgr.GetScheme(), config: config, provider: provider}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("route-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource Route
	err = c.Watch(&source.Kind{Type: &routev1.Route{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner Route
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &routev1.Route{},
	})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileRoute{}

// ReconcileRoute reconciles a Route object
type ReconcileRoute struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	config   certconf.Config
	provider certs.Provider
}

// Reconcile reads that state of the cluster for a Route object and makes changes based on the state read
// and what is in the Route.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileRoute) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Route")

	// Fetch the Route instance
	instance := &routev1.Route{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	if instance.ObjectMeta.Annotations == nil || instance.ObjectMeta.Annotations["openshift.io/cert-ctl-status"] == "" {
		return reconcile.Result{}, nil
	}

	if instance.ObjectMeta.Annotations["openshift.io/cert-ctl-status"] == "new" {
		// Retreive cert from provider
		keyPair, err := r.getCert(instance.Spec.Host)
		var routeCopy *v1.Route
		routeCopy = instance.DeepCopy()
		routeCopy.ObjectMeta.Annotations["openshift.io/cert-ctl-status"] = "no"
		routeCopy.ObjectMeta.Annotations["openshift.io/cert-ctl-expires"] = keyPair.Expiry.Format(timeFormat)

		//var termination string

		var termination v1.TLSTerminationType
		config := instance.Spec.TLS
		if config == nil {
			termination = v1.TLSTerminationEdge
		} else {
			termination = instance.Spec.TLS.Termination
		}

		routeCopy.Spec.TLS = &v1.TLSConfig{
			Termination: termination,
			Certificate: string(keyPair.Cert),
			Key:         string(keyPair.Key),
		}

		err = r.updateRoute(routeCopy)
		if err != nil {
			return reconcile.Result{}, err
		}

		reqLogger.Info("Updated route %v/%v with new certificate",
			instance.ObjectMeta.Namespace,
			instance.ObjectMeta.Name)
	}

	return reconcile.Result{}, nil
}

// newPodForCR returns a busybox pod with the same name/namespace as the cr
func newPodForCR(cr *routev1.Route) *corev1.Pod {
	labels := map[string]string{
		"app": cr.Name,
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name + "-pod",
			Namespace: cr.Namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "busybox",
					Image:   "busybox",
					Command: []string{"sleep", "3600"},
				},
			},
		},
	}
}

func (r *ReconcileRoute) getCert(host string) (certs.KeyPair, error) {
	oneYear, timeErr := time.ParseDuration("8760h")
	if timeErr != nil {
		return certs.KeyPair{}, timeErr
	}

	// Retreive cert from provider
	keyPair, err := r.provider.Provision(
		host,
		time.Now().Format(timeFormat),
		oneYear, false, 2048, "", r.config.Provider.Ssl)
	if err != nil {
		return certs.KeyPair{}, err
	}
	return keyPair, nil
}

// update route def
func (r *ReconcileRoute) updateRoute(route *v1.Route) error {

	err := r.client.Update(context.TODO(), route)

	return err
}
