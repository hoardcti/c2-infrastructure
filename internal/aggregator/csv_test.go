package aggregator

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/google/go-cmp/cmp"
)

// TestReadCSVRows checks that the header is dropped, quoted fields and CRLF line endings are
// read, and rows with the wrong number of columns are skipped with a warning.
func TestReadCSVRows(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name string
		body string
		want [][]string
		// wantLog is a warning the logs must contain, if any.
		wantLog string
	}{
		{name: "rows", body: "a,b\n1,2\n\"x,y\",z\n", want: [][]string{{"1", "2"}, {"x,y", "z"}}},
		{name: "crlf line endings", body: "a,b\r\n1,2\r\n", want: [][]string{{"1", "2"}}},
		// Stray quotes inside unquoted fields are kept as text rather than failing the feed.
		{name: "stray quote", body: "a,b\n1\"2,3\n", want: [][]string{{"1\"2", "3"}}},
		{name: "header only", body: "a,b\n", want: [][]string{}},
		{name: "empty body"},
		{
			name:    "short row skipped",
			body:    "a,b\n1\n2,3\n",
			want:    [][]string{{"2", "3"}},
			wantLog: `level=WARN msg="skipping malformed CSV row" source=test row_number=2 column_count=1`,
		},
		// The header's own column count doesn't matter.
		{name: "short header", body: "header\n1,2\n", want: [][]string{{"1", "2"}}},
	}

	for _, testCase := range testCases {
		// The function literal is a closure over testCase. Each loop iteration has its own
		// testCase, so the parallel subtests never share one.
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			aggregator, logs := newTestAggregator(subtest, &http.Client{})

			got, err := aggregator.readCSVRows(subtest.Context(), "test", strings.NewReader(testCase.body), 2)
			if nil != err {
				subtest.Fatalf("readCSVRows(%q) error = %v, want nil", testCase.body, err)
			}

			if diff := cmp.Diff(testCase.want, got); "" != diff {
				subtest.Errorf("readCSVRows(%q) mismatch (-want +got):\n%s", testCase.body, diff)
			}

			if !strings.Contains(logs.String(), testCase.wantLog) {
				subtest.Errorf("readCSVRows(%q) logs = %q, want them to contain %q", testCase.body, logs, testCase.wantLog)
			}
		})
	}
}

// TestReadCSVRowsReadError checks that a body that can't be read fails the feed.
func TestReadCSVRowsReadError(test *testing.T) {
	test.Parallel()

	aggregator, _ := newTestAggregator(test, &http.Client{})
	readErr := errors.New("connection reset")

	if _, err := aggregator.readCSVRows(test.Context(), "test", iotest.ErrReader(readErr), 2); !errors.Is(err, readErr) {
		test.Errorf("readCSVRows() of a failing body error = %v, want %v", err, readErr)
	}
}
