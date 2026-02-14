package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/melonattacker/logira/internal/model"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("empty value")
	}
	*s = append(*s, v)
	return nil
}

func parseExecDetail(raw json.RawMessage) (model.ExecDetail, error) {
	var out model.ExecDetail
	err := json.Unmarshal(raw, &out)
	return out, err
}

func parseFileDetail(raw json.RawMessage) (model.FileDetail, error) {
	var out model.FileDetail
	err := json.Unmarshal(raw, &out)
	return out, err
}

func parseNetDetail(raw json.RawMessage) (model.NetDetail, error) {
	var out model.NetDetail
	err := json.Unmarshal(raw, &out)
	return out, err
}
