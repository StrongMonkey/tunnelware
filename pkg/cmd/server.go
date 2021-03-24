package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	url2 "net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/gorilla/mux"
	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/pkg/errors"
	"github.com/rancher/remotedialer"
	cli "github.com/rancher/wrangler-cli"
	"github.com/rancher/wrangler/pkg/apply"
	"github.com/rancher/wrangler/pkg/kubeconfig"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	namespace = "tunnel-system"
)

func NewServerCommand() *cobra.Command {
	server := cli.Command(&Server{}, cobra.Command{
		Short: "Run tunnel server",
	})
	return server
}

type Server struct {
	Listen     string `name:"listen" usage:"Listen address" default:":8123"`
	ID         string `name:"id" usage:"Peer ID"`
	Token      string `name:"token" usage:"Peer Token"`
	Peers      string `name:"peers" usage:"Peers format id:token:url,id:token:url"`
	Debug      bool   `name:"debug" usage:"Enable debug logging"`
	Kubeconfig string `name:"kubeconfig" usage:"Path to kubeconfig"`
}

var (
	clients = map[string]*http.Client{}
	l       sync.Mutex
	counter int64
)

func authorizer(req *http.Request) (string, bool, error) {
	id := req.Header.Get("x-tunnel-id")
	return id, id != "", nil
}

func client(server *Handler, rw http.ResponseWriter, req *http.Request) {
	timeout := req.URL.Query().Get("timeout")
	if timeout == "" {
		timeout = "15"
	}

	host := req.Host
	clientKey := strings.Split(host, ".")[0]
	path := req.URL.Path
	var dialerHost string
	server.db.View(func(txn *badger.Txn) error {
		val, err := txn.Get([]byte(strings.Split(host, ":")[0]))
		if err != nil {
			return err
		}
		return val.Value(func(val []byte) error {
			dialerHost = string(val)
			return nil
		})
	})

	if dialerHost == "" {
		remotedialer.DefaultErrorWriter(rw, req, 500, errors.New("no tunnel found"))
		return
	}

	u, err := url2.Parse(dialerHost)
	if err != nil {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}

	client := getClient(server.Server, clientKey, timeout)

	id := atomic.AddInt64(&counter, 1)
	request := req.Clone(context.Background())
	request.RequestURI = ""
	request.URL.Scheme = u.Scheme
	request.URL.Host = u.Host
	request.URL.Path = path
	logrus.Infof("[%03d] REQ t=%s %s", id, timeout, request.URL.String())

	if req.TLS != nil && u.Scheme == "http" {
		request.Header.Set("X-Forwarded-Proto", "http")
	}

	resp, err := client.Do(request)
	if err != nil {
		logrus.Errorf("[%03d] REQ ERR t=%s %s: %v", id, timeout, request.URL.String(), err)
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}
	defer resp.Body.Close()

	logrus.Infof("[%03d] REQ OK t=%s %s", id, timeout, request.URL.String())
	for k := range resp.Header {
		rw.Header().Add(k, resp.Header.Get(k))
	}
	rw.WriteHeader(resp.StatusCode)
	io.Copy(rw, resp.Body)
	logrus.Infof("[%03d] REQ DONE t=%s %s", id, timeout, request.URL.String())
}

func getClient(server *remotedialer.Server, clientKey, timeout string) *http.Client {
	l.Lock()
	defer l.Unlock()

	key := fmt.Sprintf("%s/%s", clientKey, timeout)
	client := clients[key]
	if client != nil {
		return client
	}

	dialer := server.Dialer(clientKey)
	client = &http.Client{
		Transport: &http.Transport{
			DialContext: dialer,
		},
	}
	if timeout != "" {
		t, err := strconv.Atoi(timeout)
		if err == nil {
			client.Timeout = time.Duration(t) * time.Second
		}
	}

	clients[key] = client
	return client
}

func (s *Server) Run(cmd *cobra.Command, args []string) error {
	if s.Debug {
		logrus.SetLevel(logrus.DebugLevel)
		remotedialer.PrintTunnelData = true
	}

	cfg := kubeconfig.GetInteractiveClientConfig(s.Kubeconfig)
	restConfig, err := cfg.ClientConfig()
	if err != nil {
		return err
	}
	apply, err := apply.NewForConfig(restConfig)
	if err != nil {
		return err
	}

	db, err := badger.Open(badger.DefaultOptions("/tmp/badger"))
	if err != nil {
		logrus.Fatal(err)
	}
	defer db.Close()

	handler := &Handler{
		Server: remotedialer.New(authorizer, remotedialer.DefaultErrorWriter),
		db:     db,
		apply:  apply.WithDynamicLookup().WithListerNamespace(namespace),
	}
	handler.PeerToken = s.Token
	handler.PeerID = s.ID

	for _, peer := range strings.Split(s.Peers, ",") {
		parts := strings.SplitN(strings.TrimSpace(peer), ":", 3)
		if len(parts) != 3 {
			continue
		}
		handler.AddPeer(parts[2], parts[0], parts[1])
	}

	router := mux.NewRouter()
	router.Handle("/connect", handler)
	router.PathPrefix("/").HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		client(handler, rw, req)
	})

	fmt.Println("Listening on ", s.Listen)
	go func() {
		http.ListenAndServe(s.Listen, router)
	}()
	<-cmd.Context().Done()
	return nil
}

type Handler struct {
	*remotedialer.Server
	db    *badger.DB
	apply apply.Apply
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	fqdn := req.URL.Query().Get("fqdn")
	if fqdn == "" {
		remotedialer.DefaultErrorWriter(rw, req, 422, errors.New("no fqdn is provided"))
		return
	}

	forwardAddress := req.URL.Query().Get("forward")
	if forwardAddress == "" {
		remotedialer.DefaultErrorWriter(rw, req, 422, errors.New("no forward address is provided"))
		return
	}

	if err := h.db.Update(func(txn *badger.Txn) error {
		logrus.Debugf("setting %v to %v", fqdn, forwardAddress)
		return txn.Set([]byte(fqdn), []byte(forwardAddress))
	}); err != nil {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}
	if err := h.createIngressAndCertificates(fqdn); err != nil {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}
	defer func() {
		if err := h.deleteIngressAndCertificates(fqdn); err != nil {
			logrus.Error(err)
		}
	}()

	h.Server.ServeHTTP(rw, req)
}

func (h *Handler) createIngressAndCertificates(hostname string) error {
	prefix := networkingv1.PathTypePrefix
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      hostname,
			Namespace: namespace,
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: hostname,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &prefix,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "tunnelware",
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{hostname},
					SecretName: fmt.Sprintf("%s-tls", hostname),
				},
			},
		},
	}
	certificate := &certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      hostname,
			Namespace: namespace,
		},
		Spec: certmanagerv1.CertificateSpec{
			SecretName: fmt.Sprintf("%s-tls", hostname),
			IssuerRef: cmmeta.ObjectReference{
				Name: "letsencrypt-production",
			},
			CommonName: hostname,
			DNSNames:   []string{hostname},
		},
	}
	clientKey := strings.Split(hostname, ".")[0]
	return h.apply.WithSetID(clientKey).ApplyObjects(ingress, certificate)
}

func (h *Handler) deleteIngressAndCertificates(hostname string) error {
	clientKey := strings.Split(hostname, ".")[0]
	return h.apply.WithSetID(clientKey).Apply(nil)
}
