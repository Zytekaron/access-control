package types

import (
	"strconv"
	"strings"
	"time"
)

type JsonTime time.Time

func (j JsonTime) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(time.Time(j).UnixNano()/1000, 10)), nil
}

func (j *JsonTime) UnmarshalJSON(s []byte) error {
	r := strings.Trim(string(s), `"`)

	q, err := strconv.ParseInt(r, 10, 64)
	if err != nil {
		return err
	}

	*j = JsonTime(time.Unix(0, q*1000))
	return nil
}

func (j JsonTime) String() string {
	return time.Time(j).String()
}
