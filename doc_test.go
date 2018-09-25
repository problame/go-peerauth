package peerauth

import (
	"crypto/tls"
	"log"
	"time"
)

func ExampleTLSConfigClient() {
	conf, err := TLSConfigClient("client.crt", "client.key", "server.crt")
	if err != nil {
		log.Panic(err)
	}
	tls.Dial("tcp", "server:12345", conf)
}

func ExampleTLSConfigServer() {
	conf, err := TLSConfigServer("server.crt", "server.key", []string{"client1.crt", "client2.crt"})
	if err != nil {
		log.Panic(err)
	}
	tls.Listen("tcp", ":12345", conf)
}

func ExampleGenerateFiles() {
		genArgs := GeneratorArgs{
			CommonName: "client1",
			NotBefore:  time.Now(),
			NotAfter:   time.Now().Add(365*24*time.Hour),
		}
		cert, key, err := GenerateFiles(RSA096, genArgs, "client1")
		if err != nil {
			log.Panic(err)
		}
		log.Printf("crt: %q", cert)
		log.Printf("key: %q", key)
		// Output: crt: "client1.crt"
		// key: "client1.key"
}