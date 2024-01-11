package internal

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
	require.Nil(t, cfg.updateKeys(keyvals))

	cfg2, err := NewAppConfig([]string{usrLib, varSota, etc})
	require.Nil(t, err)
	require.Equal(t, "written", cfg2.cfgs[2].tree.Get("main.foo").(string))
	require.Equal(t, "written", cfg2.Get("main.foo"))

	keyvals = map[string]string{
		"main.bar": "mainbar",
	}
	require.Nil(t, cfg.updateKeys(keyvals))

	cfg2, err = NewAppConfig([]string{usrLib, varSota, etc})
	require.Nil(t, err)
	require.Equal(t, "mainbar", cfg2.cfgs[1].tree.Get("main.bar").(string))
	require.Equal(t, "mainbar", cfg2.Get("main.bar"))

	keyvals = map[string]string{
		"updates.key": "this must fail",
	}
	require.NotNil(t, cfg.updateKeys(keyvals))
}
