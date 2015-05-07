package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/flynn/subdomainer/Godeps/_workspace/src/github.com/awslabs/aws-sdk-go/aws"
	"github.com/flynn/subdomainer/Godeps/_workspace/src/github.com/awslabs/aws-sdk-go/gen/route53"
	hh "github.com/flynn/subdomainer/Godeps/_workspace/src/github.com/flynn/flynn/pkg/httphelper"
	"github.com/flynn/subdomainer/Godeps/_workspace/src/github.com/flynn/flynn/pkg/random"
	"github.com/flynn/subdomainer/Godeps/_workspace/src/github.com/julienschmidt/httprouter"
	_ "github.com/flynn/subdomainer/Godeps/_workspace/src/github.com/lib/pq"
	"github.com/flynn/subdomainer/Godeps/_workspace/src/github.com/speps/go-hashids"
	"github.com/flynn/subdomainer/Godeps/_workspace/src/gopkg.in/macaroon.v1"
)

func main() {
	awsCreds, err := aws.EnvCreds()
	if err != nil {
		panic(err)
	}
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}

	router := httprouter.New()
	api := &API{
		db:     db,
		domain: os.Getenv("DOMAIN"),
		domainHash: hashids.NewWithData(&hashids.HashIDData{
			Salt:      os.Getenv("DOMAIN_SALT"),
			Alphabet:  "abcdefghijklmnopqrstuvwxyz0123456789",
			MinLength: 2,
		}),
		zoneID: aws.String(os.Getenv("ZONE_ID")),
		r53:    route53.New(awsCreds, "us-east-1", nil),
	}

	router.POST("/domains", api.AllocateDomain)
	router.PUT("/domains/:id", api.AuthHandler(api.ProvisionDomain))
	router.GET("/domains/:id/status", api.AuthHandler(api.GetStatus))

	http.ListenAndServe(":"+os.Getenv("PORT"), router)
}

type API struct {
	db         *sql.DB
	domain     string
	domainHash *hashids.HashID
	zoneID     aws.StringValue
	r53        *route53.Route53
}

type DomainCreateRes struct {
	Domain string `json:"domain"`
	Token  []byte `json:"token"`
}

func (a *API) AllocateDomain(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	var id int
	if err := a.db.QueryRow("SELECT nextval('domain_seeds')").Scan(&id); err != nil {
		hh.Error(w, err)
		return
	}
	sub, _ := a.domainHash.Encode([]int{id})
	domain := fmt.Sprintf("%s.%s", sub, a.domain)
	key := random.Bytes(sha256.Size)

	var domainID string
	const insert = "INSERT INTO domains (domain, access_key, creator_ip) VALUES ($1, $2, $3) RETURNING domain_id"
	if err := a.db.QueryRow(insert, domain, key, sourceIP(req)).Scan(&domainID); err != nil {
		hh.Error(w, err)
		return
	}

	m, err := macaroon.New(key, domainID, "")
	if err != nil {
		hh.Error(w, err)
		return
	}
	res := &DomainCreateRes{Domain: domain}
	res.Token, err = m.MarshalBinary()
	if err != nil {
		hh.Error(w, err)
		return
	}

	hh.JSON(w, 200, res)
}

func nopChecker(caveat string) error {
	return fmt.Errorf("unexpected caveat %s", caveat)
}

func (a *API) AuthHandler(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		var domainID string
		var key []byte
		const get = "SELECT domain_id, access_key FROM domains WHERE domain = $1"
		if err := a.db.QueryRow(get, params.ByName("id")).Scan(&domainID, &key); err != nil {
			hh.Error(w, err)
			return
		}

		auth := req.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Token ") {
			hh.JSON(w, 401, struct{}{})
			return
		}
		serialized, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Token "))
		if err != nil {
			hh.JSON(w, 400, struct{}{})
			return
		}

		var m macaroon.Macaroon
		if err := m.UnmarshalBinary(serialized); err != nil {
			hh.JSON(w, 400, struct{}{})
			return
		}
		if err := m.Verify(key, nopChecker, nil); err != nil {
			hh.JSON(w, 400, struct{}{})
			return
		}

		h(w, req, params)
	}
}

type ProvisionReq struct {
	Nameservers []string `json:"nameservers"`
}

var nameserverPattern = regexp.MustCompile(`\Ans-\d+\.awsdns-\d+(\.[a-z]{1,3}){1,2}\z`)

func (a *API) ProvisionDomain(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	domain := params.ByName("id")

	var reqData ProvisionReq
	if err := hh.DecodeJSON(req, &reqData); err != nil {
		hh.Error(w, err)
		return
	}
	if len(reqData.Nameservers) < 4 || len(reqData.Nameservers) > 10 {
		// TODO: log it
		hh.JSON(w, 400, struct{}{})
		return
	}
	for _, n := range reqData.Nameservers {
		if !nameserverPattern.MatchString(n) {
			// TODO: log it
			hh.JSON(w, 400, struct{}{})
			return
		}
	}

	nsData, _ := json.Marshal(reqData.Nameservers)
	const nsUpdate = "UPDATE domains SET nameservers = $2 WHERE domain = $1 AND nameservers IS NULL"
	updateRes, err := a.db.Exec(nsUpdate, domain, nsData)
	if err != nil {
		hh.Error(w, err)
		return
	}
	if n, _ := updateRes.RowsAffected(); n != 1 {
		// TODO(titanous): don't error if the nameservers are the same and there is no route
		hh.JSON(w, 400, struct{}{})
		return
	}

	records := make([]route53.ResourceRecord, len(reqData.Nameservers))
	for i, ns := range reqData.Nameservers {
		records[i].Value = aws.String(ns)
	}

	dnsReq := &route53.ChangeResourceRecordSetsRequest{
		HostedZoneID: a.zoneID,
		ChangeBatch: &route53.ChangeBatch{
			Changes: []route53.Change{{
				Action: aws.String(route53.ChangeActionCreate),
				ResourceRecordSet: &route53.ResourceRecordSet{
					Name:            aws.String(domain + "."),
					TTL:             aws.Long(3600),
					Type:            aws.String(route53.RRTypeNs),
					ResourceRecords: records,
				},
			}},
		},
	}
	dnsRes, err := a.r53.ChangeResourceRecordSets(dnsReq)
	if err != nil {
		hh.Error(w, err)
		return
	}

	const updateChange = "UPDATE domains SET external_change_id = $2 WHERE domain = $1"
	if _, err := a.db.Exec(updateChange, domain, dnsRes.ChangeInfo.ID); err != nil {
		hh.Error(w, err)
		return
	}

	hh.JSON(w, 200, struct{}{})
}

type StatusResponse struct {
	Status string `json:"status"`
}

var statusApplied = &StatusResponse{"applied"}
var statusPending = &StatusResponse{"pending"}

func (a *API) GetStatus(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	var changeID *string
	var applied bool
	domain := params.ByName("id")
	const get = "SELECT external_change_id, external_change_applied FROM domains WHERE domain = $1"
	if err := a.db.QueryRow(get, domain).Scan(&changeID, &applied); err != nil {
		hh.Error(w, err)
		return
	}
	if changeID == nil || *changeID == "" {
		hh.JSON(w, 404, struct{}{})
		return
	}
	if applied {
		hh.JSON(w, 200, statusApplied)
		return
	}

	*changeID = strings.TrimPrefix(*changeID, "/change/")
	res, err := a.r53.GetChange(&route53.GetChangeRequest{ID: changeID})
	if err != nil {
		// TODO(titanous): check NoSuchChange
		hh.Error(w, err)
		return
	}

	if *res.ChangeInfo.Status != route53.ChangeStatusInsync {
		hh.JSON(w, 200, statusPending)
		return
	}
	const update = "UPDATE domains SET external_change_applied = true WHERE domain = $1"
	if _, err := a.db.Exec(update, domain); err != nil {
		hh.Error(w, err)
		return
	}
	hh.JSON(w, 200, statusApplied)
}

func sourceIP(req *http.Request) string {
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[len(ips)-1])
	}
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	return ip
}
