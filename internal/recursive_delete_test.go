package internal

import (
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeleteEmptyDirs(t *testing.T) {
	root := t.TempDir()
	sub1 := filepath.Join(root, "sub1")
	require.Nil(t, os.Mkdir(sub1, 0o750))
	require.Nil(t, os.Mkdir(filepath.Join(sub1, "sub1a"), 0o750))
	require.Nil(t, os.Mkdir(filepath.Join(sub1, "sub1b"), 0o750))

	sub2 := filepath.Join(root, "sub2")
	require.Nil(t, os.Mkdir(sub2, 0o750))
	require.Nil(t, ioutil.WriteFile(filepath.Join(sub2, "foo.txt"), []byte("test"), 0o700))
	require.Nil(t, os.Mkdir(filepath.Join(sub2, "sub2a"), 0o750))
	require.Nil(t, os.Mkdir(filepath.Join(sub2, "sub2b"), 0o750))

	require.Nil(t, DeleteEmptyDirs(root))

	var found []string
	err := filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		found = append(found, path)
		return nil
	})
	require.Nil(t, err)

	expected := []string{
		root,
		filepath.Join(root, "sub2"),
		filepath.Join(root, "sub2", "foo.txt"),
	}
	require.Equal(t, expected, found)

	// make sure an empty root doesn't get deleted
	root = t.TempDir()
	require.Nil(t, DeleteEmptyDirs(root))
	_, err = os.Stat(root)
	require.Nil(t, err)
}
