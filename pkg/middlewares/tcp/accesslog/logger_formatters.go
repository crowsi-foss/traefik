package accesslog

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/sirupsen/logrus"
)

const (
	// CommonFormat is the common logging format (CLF).
	CommonFormat string = "common"

	// JSONFormat is the JSON logging format.
	JSONFormat string = "json"
)

// CommonLogFormatter is a logrus.Formatter for TCP access logs.
type CommonLogFormatter struct{}

// Format formats the log entry.
func (f *CommonLogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	b := &bytes.Buffer{}

	b.WriteString(entry.Message)

	keys := make([]string, 0, len(entry.Data))
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		b.WriteString(fmt.Sprintf(" %s=%v", k, entry.Data[k]))
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

// NewLogFormatter creates a new logrus.Formatter.
func NewLogFormatter(format string) (logrus.Formatter, error) {
	switch format {
	case CommonFormat:
		return &CommonLogFormatter{}, nil
	case JSONFormat:
		return &logrus.JSONFormatter{}, nil
	}

	return nil, fmt.Errorf("unsupported format: %s", format)
}
