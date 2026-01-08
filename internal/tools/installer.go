package tools

import (
	"fmt"
	"os/exec"
)

type Installer struct{ c *Checker }

func NewInstaller() *Installer { return &Installer{c: NewChecker()} }

func (i *Installer) GetGoTools() []Tool       { return GoTools() }
func (i *Installer) GetPythonTools() []Tool   { return PythonTools() }
func (i *Installer) GetRustTools() []Tool     { return RustTools() }
func (i *Installer) GetWordlists() []Wordlist { return GetWordlists() }

func (i *Installer) InstallWordlist(wl Wordlist) error {
	return DownloadWordlist(wl)
}

func (i *Installer) InstallGoTool(t Tool) error {
	if i.c.IsInstalled(t.Binary) || t.InstallCmd == "" {
		return nil
	}
	if out, err := exec.Command("go", "install", t.InstallCmd).CombinedOutput(); err != nil {
		return fmt.Errorf("%s", out)
	}
	return nil
}

func (i *Installer) InstallPythonTool(t Tool) error {
	if i.c.IsInstalled(t.Binary) {
		return nil
	}
	if i.c.IsInstalled("pipx") {
		if out, err := exec.Command("pipx", "install", t.InstallCmd).CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	}
	if i.c.IsInstalled("pip3") {
		if out, err := exec.Command("pip3", "install", "--user", t.InstallCmd).CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	}
	return fmt.Errorf("pipx/pip3 not found")
}

func (i *Installer) InstallRustTool(t Tool) error {
	if i.c.IsInstalled(t.Binary) {
		return nil
	}
	if !i.c.IsInstalled("cargo") {
		return fmt.Errorf("cargo not found")
	}
	if out, err := exec.Command("cargo", "install", t.InstallCmd).CombinedOutput(); err != nil {
		return fmt.Errorf("%s", out)
	}
	return nil
}
