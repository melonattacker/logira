package runs

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
)

type sudoInvoker struct {
	User string
	UID  int
	GID  int
}

func sudoInvokerFromEnv(getenv func(string) string) (sudoInvoker, bool) {
	user := strings.TrimSpace(getenv("SUDO_USER"))
	uidStr := strings.TrimSpace(getenv("SUDO_UID"))
	gidStr := strings.TrimSpace(getenv("SUDO_GID"))
	if user == "" || uidStr == "" || gidStr == "" {
		return sudoInvoker{}, false
	}
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return sudoInvoker{}, false
	}
	gid, err := strconv.Atoi(gidStr)
	if err != nil {
		return sudoInvoker{}, false
	}
	return sudoInvoker{User: user, UID: uid, GID: gid}, true
}

// lookupHomeFromPasswd tries to find the user's home directory from /etc/passwd content.
// It prefers matching by username, but will fall back to matching by uid if needed.
func lookupHomeFromPasswd(user string, uid int, passwd []byte) (string, bool) {
	user = strings.TrimSpace(user)
	if user == "" && uid <= 0 {
		return "", false
	}
	s := bufio.NewScanner(bytes.NewReader(passwd))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:passwd:uid:gid:gecos:dir:shell
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		name := parts[0]
		uidField := parts[2]
		dir := parts[5]

		if user != "" && name == user {
			dir = strings.TrimSpace(dir)
			if dir != "" {
				return dir, true
			}
			return "", false
		}
		if user == "" && uid > 0 {
			if u, err := strconv.Atoi(uidField); err == nil && u == uid {
				dir = strings.TrimSpace(dir)
				if dir != "" {
					return dir, true
				}
				return "", false
			}
		}
	}
	return "", false
}

func readPasswd() ([]byte, error) {
	return os.ReadFile("/etc/passwd")
}
