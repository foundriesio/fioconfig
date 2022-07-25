package internal

import (
	"os"
	"path/filepath"
)

// Recurse to the leaf directories looking for empty directories to delete
// and then work our way back up deleting everything that becomes empy during
// the process.
func deleteEmptyDirs(path string) (bool, error) {
	node, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer node.Close()
	children, err := node.ReadDir(-1)
	if err != nil {
		return false, err
	}
	isEmpty := true
	for _, child := range children {
		if child.IsDir() {
			childPath := filepath.Join(path, child.Name())
			empty, err := deleteEmptyDirs(childPath)
			if err != nil {
				return false, err
			} else if !empty {
				isEmpty = false
			} else {
				if err := os.Remove(childPath); err != nil {
					return false, err
				}
			}
		} else {
			isEmpty = false
		}
	}
	return isEmpty, nil
}

func DeleteEmptyDirs(path string) error {
	_, err := deleteEmptyDirs(path)
	return err
}
