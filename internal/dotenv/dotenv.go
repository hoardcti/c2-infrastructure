// Package dotenv loads KEY=VALUE pairs from a .env file into the process
// environment, standing in for python-dotenv's load_dotenv().
package dotenv

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"strings"
)

// Load reads the .env file at path and sets each variable that is not
// already present in the environment. A missing file is not an error,
// matching load_dotenv() which silently does nothing in that case.
func Load(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if nil != err {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := parseLine(scanner.Text())

		// Skip blanks, comments and malformed lines
		if false == ok {
			continue
		}

		// Existing environment variables win, as with load_dotenv(override=False)
		if _, exists := os.LookupEnv(key); exists {
			continue
		}

		if err := os.Setenv(key, value); nil != err {
			return err
		}
	}

	return scanner.Err()
}

// parseLine extracts a key and value from a single .env line. It supports an
// optional "export " prefix, single or double quoted values, and trailing
// comments on unquoted values.
func parseLine(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)

	if "" == line || strings.HasPrefix(line, "#") {
		return "", "", false
	}

	line = strings.TrimPrefix(line, "export ")

	key, value, found := strings.Cut(line, "=")
	if false == found {
		return "", "", false
	}

	key = strings.TrimSpace(key)
	if "" == key {
		return "", "", false
	}

	value = strings.TrimSpace(value)

	if 2 <= len(value) && ('"' == value[0] || '\'' == value[0]) && value[0] == value[len(value)-1] {
		return key, value[1 : len(value)-1], true
	}

	// Strip inline comments from unquoted values
	if i := strings.Index(value, " #"); -1 != i {
		value = strings.TrimSpace(value[:i])
	}

	return key, value, true
}
