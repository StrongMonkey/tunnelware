package cmd

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	url2 "net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/go-github/v34/github"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/rancher/remotedialer"
	cli "github.com/rancher/wrangler-cli"
	"github.com/rancher/wrangler/pkg/kv"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

func NewServerCommand() *cobra.Command {
	server := cli.Command(&Server{}, cobra.Command{
		Short: "Run tunnel server",
	})
	return server
}

type Server struct {
	Listen string `name:"listen" usage:"Listen address" default:":8123"`
	ID     string `name:"id" usage:"Peer ID"`
	Token  string `name:"token" usage:"Peer Token"`
	Peers  string `name:"peers" usage:"Peers format id:token:url,id:token:url"`
	Debug  bool   `name:"debug" usage:"Enable debug logging"`
}

var (
	clients       = map[string]*http.Client{}
	hostMap       = map[string]string{}
	jwtTokenMap   = map[string]string{}
	l             sync.Mutex
	counter       int64
	jwtPrivateKey *ecdsa.PrivateKey
)

func authorizer(req *http.Request) (string, bool, error) {
	username, forwardPort := kv.Split(req.Header.Get("x-tunnel-id"), ":")
	if username == "" || forwardPort == "" {
		return "", false, nil
	}
	if username == "" {
		return "", false, nil
	}

	jwtToken := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	claim := &Claim{}
	_, err := jwt.ParseWithClaims(jwtToken, claim, func(token *jwt.Token) (interface{}, error) {
		return &jwtPrivateKey.PublicKey, nil
	})
	if err != nil {
		return "", false, err
	}

	if !strings.EqualFold(claim.Username, username) {
		return "", false, fmt.Errorf("not able to establish tunnel using username %v. Not enough permission", username)
	}
	hostMap[username] = forwardPort
	return username, true, nil
}

func client(server *Handler, rw http.ResponseWriter, req *http.Request) {
	timeout := req.URL.Query().Get("timeout")
	if timeout == "" {
		timeout = "15"
	}

	username := strings.Split(strings.Split(req.Host, ":")[0], ".")[0]
	forwardHost := hostMap[username]
	clientKey := username

	if forwardHost == "" {
		remotedialer.DefaultErrorWriter(rw, req, 500, errors.New("no tunnel found"))
		return
	}

	u, err := url2.Parse(forwardHost)
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

	secretPath := os.Getenv("JWT_SECRET_KEY_PATH")
	secret, err := ioutil.ReadFile(secretPath)
	if err != nil {
		panic(err)
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM(secret)
	if err != nil {
		panic(err)
	}
	jwtPrivateKey = privateKey

	handler := &Handler{
		Server: remotedialer.New(authorizer, remotedialer.DefaultErrorWriter),
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
	router.HandleFunc("/connect", handler.onConnect)
	router.HandleFunc("/login/github", handler.githubLogin)
	router.HandleFunc("/github/callback", handler.githubLoginCallback)
	router.HandleFunc("/jwt/{state}", handler.jwtToken)
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
}

func (h *Handler) onConnect(rw http.ResponseWriter, req *http.Request) {
	h.Server.ServeHTTP(rw, req)
}

func (h *Handler) githubLogin(rw http.ResponseWriter, req *http.Request) {
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	state := req.URL.Query().Get("state")

	redirectURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&scope=read:user&state=%s", clientID, fmt.Sprintf("%s/github/callback", os.Getenv("SERVER_ADDRESS")), state)
	http.Redirect(rw, req, redirectURL, 301)
}

type response struct {
	AccessToken string `json:"access_token"`
}

func (h *Handler) githubLoginCallback(rw http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")

	request, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token", nil)
	if err != nil {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}
	query := request.URL.Query()
	query.Add("client_id", clientID)
	query.Add("client_secret", clientSecret)
	query.Add("code", code)
	query.Add("state", state)
	request.URL.RawQuery = query.Encode()
	request.Header.Set("Accept", "application/json")
	fmt.Println(request.URL.String())
	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}

	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		remotedialer.DefaultErrorWriter(rw, req, 500, errors.New(string(respData)))
		return
	}
	githubResp := &response{}
	if err := json.Unmarshal(respData, githubResp); err != nil {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubResp.AccessToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	githubClient := github.NewClient(tc)
	user, _, err := githubClient.Users.Get(ctx, "")
	if err != nil {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}

	if user.Login == nil || *user.Login == "" {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}

	claim := Claim{
		Username: *user.Login,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24 * 365).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES512, claim)
	tokenString, err := token.SignedString(jwtPrivateKey)
	if err != nil {
		remotedialer.DefaultErrorWriter(rw, req, 500, err)
		return
	}
	jwtTokenMap[state] = tokenString
	rw.Write([]byte("Login successfully. Please go back to your terminal and continue"))
	rw.WriteHeader(200)
	return
}

func (h *Handler) jwtToken(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	state := vars["state"]
	jwtToken := jwtTokenMap[state]
	defer delete(jwtTokenMap, state)

	rw.Write([]byte(jwtToken))
	rw.WriteHeader(200)
}
