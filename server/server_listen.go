package chserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/jpillora/chisel/share/settings"
	"golang.org/x/crypto/acme/autocert"
)

//TLSConfig enables configures TLS
type TLSConfig struct {
	Key           string
	Cert          string
	Domains       []string
	CA            string
	RandomKeyCert bool
}

func (s *Server) listener(host, port string) (net.Listener, error) {
	hasDomains := len(s.config.TLS.Domains) > 0
	hasKeyCert := s.config.TLS.Key != "" && s.config.TLS.Cert != ""
	if hasDomains && hasKeyCert {
		return nil, errors.New("cannot use key/cert and domains")
	}
	var tlsConf *tls.Config
	if hasDomains {
		tlsConf = s.tlsLetsEncrypt(s.config.TLS.Domains)
	}
	extra := ""
	if hasKeyCert {
		c, err := s.tlsKeyCert(s.config.TLS.Key, s.config.TLS.Cert, s.config.TLS.CA)
		if err != nil {
			return nil, err
		}
		tlsConf = c
		if port != "443" && hasDomains {
			extra = " (WARNING: LetsEncrypt will attempt to connect to your domain on port 443)"
		}
	} else if s.config.TLS.RandomKeyCert {
		conf, err := GenRandomCert()

		if err != nil {
			return nil, err
		}

		tlsConf = conf
	}
	//tcp listen
	l, err := net.Listen("tcp", host+":"+port)
	if err != nil {
		return nil, err
	}
	//optionally wrap in tls
	proto := "http"
	if tlsConf != nil {
		proto += "s"
		l = tls.NewListener(l, tlsConf)
	}
	if err == nil {
		s.Infof("Listening on %s://%s:%s%s", proto, host, port, extra)
	}
	return l, nil
}

func (s *Server) tlsLetsEncrypt(domains []string) *tls.Config {
	//prepare cert manager
	m := &autocert.Manager{
		Prompt: func(tosURL string) bool {
			s.Infof("Accepting LetsEncrypt TOS and fetching certificate...")
			return true
		},
		Email:      settings.Env("LE_EMAIL"),
		HostPolicy: autocert.HostWhitelist(domains...),
	}
	//configure file cache
	c := settings.Env("LE_CACHE")
	if c == "" {
		h := os.Getenv("HOME")
		if h == "" {
			if u, err := user.Current(); err == nil {
				h = u.HomeDir
			}
		}
		c = filepath.Join(h, ".cache", "chisel")
	}
	if c != "-" {
		s.Infof("LetsEncrypt cache directory %s", c)
		m.Cache = autocert.DirCache(c)
	}
	//return lets-encrypt tls config
	return m.TLSConfig()
}

func (s *Server) tlsKeyCert(key, cert string, ca string) (*tls.Config, error) {
	keypair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	//file based tls config using tls defaults
	c := &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}
	//mTLS requires server's CA
	if ca != "" {
		if err := addCA(ca, c); err != nil {
			return nil, err
		}
		s.Infof("Loaded CA path: %s", ca)
	}
	return c, nil
}

func addCA(ca string, c *tls.Config) error {
	fileInfo, err := os.Stat(ca)
	if err != nil {
		return err
	}
	clientCAPool := x509.NewCertPool()
	if fileInfo.IsDir() {
		//this is a directory holding CA bundle files
		files, err := ioutil.ReadDir(ca)
		if err != nil {
			return err
		}
		//add all cert files from path
		for _, file := range files {
			f := file.Name()
			if err := addPEMFile(filepath.Join(ca, f), clientCAPool); err != nil {
				return err
			}
		}
	} else {
		//this is a CA bundle file
		if err := addPEMFile(ca, clientCAPool); err != nil {
			return err
		}
	}
	//set client CAs and enable cert verification
	c.ClientCAs = clientCAPool
	c.ClientAuth = tls.RequireAndVerifyClientCert
	return nil
}

func addPEMFile(path string, pool *x509.CertPool) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	if !pool.AppendCertsFromPEM(content) {
		return errors.New("Fail to load certificates from : " + path)
	}
	return nil
}

func GenRandomCert() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Generate a pem block with the private key
	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tml := x509.Certificate{
		// you can add any attr that you need
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(5, 0, 0),
		// you have to generate a different serial number each execution
		SerialNumber: big.NewInt(123123),
		Subject: pkix.Name{
			CommonName:   "New Name",
			Organization: []string{"New Org."},
		},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)

	if err != nil {
		return nil, err
	}

	// Generate a pem block with the certificate
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	tls_cert, err := tls.X509KeyPair(certPem, keyPem)

	return &tls.Config{Certificates: []tls.Certificate{tls_cert}}, err
}
