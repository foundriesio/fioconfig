package sotatoml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAppConfig(t *testing.T) {
	usrLib := t.TempDir()
	varSota := t.TempDir() + "/sota.toml"
	mainContent := `[main]
foo = "bar"`
	etc := t.TempDir()

	usrLibOver := `[main]
usrlib = "readonlyTest"
bar = "usr"`

	etcOver := `[main]
bar = "etc"`

	z50Over := `[updates]
key = "val"`

	require.Nil(t, os.WriteFile(varSota, []byte(mainContent), 0o744))
	require.Nil(t, os.WriteFile(filepath.Join(usrLib, "z-1.toml"), []byte(usrLibOver), 0o744))
	require.Nil(t, os.WriteFile(filepath.Join(etc, "z-1.toml"), []byte(etcOver), 0o744))
	require.Nil(t, os.WriteFile(filepath.Join(etc, "z-50-fioctl.toml"), []byte(z50Over), 0o744))

	cfg, err := NewAppConfig([]string{usrLib, varSota, etc})
	require.Nil(t, err)
	require.Equal(t, "sota.toml", cfg.cfgs[2].name)
	require.Equal(t, "z-1.toml", cfg.cfgs[1].name)
	require.Equal(t, etc+"/z-1.toml", cfg.cfgs[1].path)

	require.Equal(t, "bar", cfg.Get("main.foo"))
	require.Equal(t, "etc", cfg.Get("main.bar"))
	require.Equal(t, "", cfg.Get("main.doesnotexist"))
	require.Equal(t, "val", cfg.Get("updates.key"))

	// Test write functionality
	keyvals := map[string]string{
		"main.foo": "written",
	}
	require.Nil(t, cfg.UpdateKeys(keyvals))

	cfg2, err := NewAppConfig([]string{usrLib, varSota, etc})
	require.Nil(t, err)
	require.Equal(t, "written", cfg2.cfgs[2].tree.Get("main.foo").(string))
	require.Equal(t, "written", cfg2.Get("main.foo"))

	keyvals = map[string]string{
		"main.bar": "mainbar",
	}
	require.Nil(t, cfg.UpdateKeys(keyvals))

	cfg2, err = NewAppConfig([]string{usrLib, varSota, etc})
	require.Nil(t, err)
	require.Equal(t, "mainbar", cfg2.cfgs[1].tree.Get("main.bar").(string))
	require.Equal(t, "mainbar", cfg2.Get("main.bar"))

	// We must reject a change to z-50-fioctl.toml
	keyvals = map[string]string{
		"updates.key": "this must fail",
	}
	require.NotNil(t, cfg.UpdateKeys(keyvals))

	// We must reject a keyval that does not exist - this api is for *updates* only
	keyvals = map[string]string{
		"updates.not_exist": "this must fail",
	}
	err = cfg.UpdateKeys(keyvals)
	require.NotNil(t, err)
	require.Equal(t, ErrNoWritableFound, err)

	// Fail if the file can't be written to
	cfg2, err = NewAppConfig([]string{usrLib})
	require.Nil(t, err)
	keyvals = map[string]string{
		"main.usrlib": "this is a read-only directory",
	}
	require.Nil(t, os.Chmod(usrLib, 0o500))
	defer func() {
		_ = os.Chmod(usrLib, 0o777)
	}()
	err = cfg2.UpdateKeys(keyvals)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unable to write to file:")

	// Show we can find a file that we can fail back to config file that we
	// can write to. We first have to rename - the usrlib file so that
	// "sota.toml" will override it
	require.Nil(t, os.Chmod(usrLib, 0o700))
	require.Nil(t, os.Rename(filepath.Join(usrLib, "z-1.toml"), filepath.Join(usrLib, "r-1.toml")))
	require.Nil(t, os.Chmod(usrLib, 0o500))
	cfg2, err = NewAppConfig([]string{varSota, usrLib})
	require.Nil(t, err)
	keyvals["main.usrlib"] = "this should work"
	err = cfg2.UpdateKeys(keyvals)
	require.Nil(t, err)
	cfg2, err = NewAppConfig([]string{varSota, usrLib})
	require.Nil(t, err)
	require.Equal(t, "this should work", cfg2.Get("main.usrlib"))
}

func TestIsWritable(t *testing.T) {
	tmpDir := t.TempDir()
	require.True(t, isWritable(filepath.Join(tmpDir, "foo.toml")))
	require.Nil(t, os.Chmod(tmpDir, 0o400))
	require.False(t, isWritable(filepath.Join(tmpDir, "foo.toml")))
}
