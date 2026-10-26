package rfc2136

import (
	"context"
	"io"
	"log/slog"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/maxfield-allison/dnsweaver/pkg/provider"
)

// Authoritative DNS includes the CNAME in responses to other
// question types and may include the target's matching records in the answer.
func TestProviderListCNAMEAnswers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hosts []string
		want  []string
	}{
		{"alias only", []string{"alias.example.com"}, []string{"alias.example.com CNAME target.example.com"}},
		{"multiple addresses", []string{"target.example.com"}, []string{"target.example.com A 192.0.2.10", "target.example.com A 192.0.2.11", "target.example.com AAAA 2001:db8::1"}},
		{"alias and target both managed", []string{"alias.example.com", "target.example.com"}, []string{"alias.example.com CNAME target.example.com", "target.example.com A 192.0.2.10", "target.example.com A 192.0.2.11", "target.example.com AAAA 2001:db8::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			listener, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var members []dns.RR
			for _, text := range []string{
				"alias.example.com. 300 IN CNAME target.example.com.",
				"target.example.com. 300 IN A 192.0.2.10",
				"target.example.com. 300 IN A 192.0.2.11",
				"target.example.com. 300 IN AAAA 2001:db8::1",
			} {
				rr, err := dns.NewRR(text)
				if err != nil {
					t.Fatal(err)
				}
				members = append(members, rr)
			}
			ready := make(chan struct{})
			server := &dns.Server{
				Listener: listener, Net: "tcp",
				NotifyStartedFunc: func() { close(ready) },
				Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
					reply := new(dns.Msg)
					reply.SetReply(request)
					reply.Authoritative = true
					q := request.Question[0]
					switch q.Name {
					case "_dnsweaver-catalog-0.example.com.":
						reply.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: tc.hosts}}
					case "alias.example.com.":
						reply.Answer = append(reply.Answer, dns.Copy(members[0]))
						for _, rr := range members[1:] {
							if rr.Header().Rrtype == q.Qtype {
								reply.Answer = append(reply.Answer, dns.Copy(rr))
							}
						}
					case "target.example.com.":
						for _, rr := range members[1:] {
							if rr.Header().Rrtype == q.Qtype {
								reply.Answer = append(reply.Answer, dns.Copy(rr))
							}
						}
					}
					if err := w.WriteMsg(reply); err != nil {
						t.Error(err)
					}
				}),
			}
			done := make(chan error, 1)
			go func() { done <- server.ActivateAndServe() }()
			t.Cleanup(func() {
				if err := server.Shutdown(); err != nil {
					t.Error(err)
				}
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			p, err := New("test", &Config{Server: listener.Addr().String(), Zone: "example.com.", UseTCP: true, Timeout: 2, TTL: 300}, WithProviderLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
			if err != nil {
				t.Fatal(err)
			}
			records, err := p.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, record := range records {
				if !provider.IsOwnershipRecord(record.Hostname) {
					got = append(got, record.Hostname+" "+string(record.Type)+" "+record.Target)
				}
			}
			sort.Strings(got)
			sort.Strings(tc.want)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("List() = %v; want %v", got, tc.want)
			}
		})
	}
}
