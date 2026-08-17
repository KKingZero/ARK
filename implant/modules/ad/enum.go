package ad

import (
	"context"
	"fmt"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/ldapcli"
	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/suggestions"
	ldaplib "github.com/go-ldap/ldap/v3"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&LDAPEnumModule{})
}

type LDAPEnumModule struct{}

func (m *LDAPEnumModule) Name() string        { return "ldap_enum" }
func (m *LDAPEnumModule) Description() string { return "LDAP Active Directory enumeration" }

func (m *LDAPEnumModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	cfg := &pb.LDAPEnumConfig{}
	if err := proto.Unmarshal(config, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal LDAP config: %w", err)
	}

	result, err := runLDAPEnum(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(result)
}

func runLDAPEnum(_ context.Context, cfg *pb.LDAPEnumConfig) (*pb.LDAPEnumResult, error) {
	if cfg.TargetDc == "" {
		return nil, fmt.Errorf("target_dc required")
	}
	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain required")
	}

	opts := ldapcli.DefaultOptions()
	opts.Host = cfg.TargetDc
	opts.Domain = cfg.Domain
	opts.Username = cfg.Username
	opts.Password = cfg.Password
	opts.Hash = cfg.NtlmHash
	conn, err := ldapcli.Bind(opts)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	baseDN := ldapcli.BaseDN(cfg.Domain)
	qt := ldapcli.CanonicalQuery(cfg.QueryType)
	if qt == "" {
		qt = "interesting"
	}
	filter := cfg.CustomFilter
	if filter == "" {
		filter, err = ldapcli.FilterFor(qt, baseDN)
		if err != nil {
			return nil, err
		}
	}
	attrs := cfg.Attributes
	if len(attrs) == 0 {
		attrs = ldapcli.DefaultAttrs[qt]
	}
	entries, err := ldapcli.Search(conn, baseDN, filter, attrs)
	if err != nil {
		return nil, err
	}

	result := &pb.LDAPEnumResult{
		Domain:       cfg.Domain,
		Dc:           cfg.TargetDc,
		QueryType:    qt,
		TotalResults: int32(len(entries)),
	}
	for _, entry := range entries {
		ldapEntry := &pb.LDAPEntry{
			Dn:         entry.DN,
			Attributes: make(map[string]*pb.LDAPValues),
		}
		for _, attr := range entry.Attributes {
			ldapEntry.Attributes[attr.Name] = &pb.LDAPValues{Values: attr.Values}
		}
		result.Entries = append(result.Entries, ldapEntry)
	}
	result.NextSuggestedActions = suggestions.ForLDAPEnum(result)
	return result, nil
}

// BuildLDAPFilter is kept for tests and roast helpers.
func BuildLDAPFilter(queryType, baseDN string) (string, error) {
	return ldapcli.FilterFor(queryType, baseDN)
}

func domainToBaseDN(domain string) string { return ldapcli.BaseDN(domain) }

// EnumKerberoastable queries LDAP for kerberoastable accounts and returns their SPNs.
func EnumKerberoastable(conn *ldaplib.Conn, baseDN string) ([]struct{ SAM, SPN string }, error) {
	entries, err := ldapcli.Search(conn, baseDN, queryFilters["kerberoastable"], []string{"sAMAccountName", "servicePrincipalName"})
	if err != nil {
		return nil, err
	}
	var results []struct{ SAM, SPN string }
	for _, entry := range entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		for _, spn := range entry.GetAttributeValues("servicePrincipalName") {
			results = append(results, struct{ SAM, SPN string }{SAM: sam, SPN: spn})
		}
	}
	return results, nil
}

// EnumASREPRoastable queries LDAP for accounts with DONT_REQ_PREAUTH set.
func EnumASREPRoastable(conn *ldaplib.Conn, baseDN string) ([]string, error) {
	entries, err := ldapcli.Search(conn, baseDN, queryFilters["asrep_roastable"], []string{"sAMAccountName"})
	if err != nil {
		return nil, err
	}
	var users []string
	for _, entry := range entries {
		users = append(users, entry.GetAttributeValue("sAMAccountName"))
	}
	return users, nil
}
