package main

import (
	"crypto/tls"
	"flag"
	"github.com/problame/go-peerauth"
	"io"
	"log"
	"os"
	"time"
)

var args struct {
	gen              string
	genCN            string
	genValidDuration time.Duration
	connect          string
	listen           string
	cert, key        string
	remote           string
}

func main() {

	flag.StringVar(&args.gen, "gen", "", "path to outfile")
	flag.StringVar(&args.genCN, "gen.cn", "", "CN of cert to be generated")
	flag.DurationVar(&args.genValidDuration, "gen.duration", 0, "time the generated cert will be valid (from now on)")
	flag.StringVar(&args.connect, "connect", "", "connect to")
	flag.StringVar(&args.listen, "listen", "", "listen on")
	flag.StringVar(&args.cert, "cert", "", "this node's certificate")
	flag.StringVar(&args.key, "key", "", "this node's private key")
	flag.StringVar(&args.remote, "remote", "", "the remote's certificate")
	flag.Parse()

	if args.gen != "" {
		genArgs := peerauth.GeneratorArgs{
			CommonName: args.genCN,
			NotBefore:  time.Now(),
			NotAfter:   time.Now().Add(args.genValidDuration),
		}
		cert, key, err := peerauth.GenerateFiles(peerauth.RSA096, genArgs, args.gen)
		if err != nil {
			log.Panic(err)
		}

		log.Printf("wrote to %q and %q", cert, key)
		return
	}

	if args.listen != "" {
		conf, err := peerauth.TLSConfigServer(args.cert, args.key, []string{args.remote})
		if err != nil {
			log.Panic(err)
		}
		l, err := tls.Listen("tcp", args.listen, conf)
		if err != nil {
			log.Panic(err)
		}
		defer l.Close()
		for {
			func() {
				log.Println("accepting")
				conn, err := l.Accept()
				if err != nil {
					log.Printf("accept error: %s", err)
					return
				}
				defer conn.Close()
				if err := conn.(*tls.Conn).Handshake(); err != nil {
					log.Print(err)
					return
				}
				st := conn.(*tls.Conn).ConnectionState()
				log.Printf("commonName=%s", st.PeerCertificates[0].Subject.CommonName)
				go io.Copy(conn, os.Stdin)
				io.Copy(os.Stdout, conn)
				log.Println("connection done")
			}()
		}
	}

	if args.connect != "" {
		conf, err := peerauth.TLSConfigClient(args.cert, args.key, args.remote)
		if err != nil {
			log.Panic(err)
		}
		conn, err := tls.Dial("tcp", args.connect, conf)
		if err != nil {
			log.Panic(err)
		}
		log.Println("connected")
		go io.Copy(conn, os.Stdin)
		io.Copy(os.Stdout, conn)
		return

	}

}
