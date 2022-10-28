// SPDX-License-Identifier: Apache-2.0

package sysaccess

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/digitalocean/droplet-agent/internal/log"
	"github.com/digitalocean/droplet-agent/internal/sysutil"
)

type authorizedKeysFileUpdater interface {
	updateAuthorizedKeysFile(osUsername string, managedKeys []*SSHKey) error
}

type updaterImpl struct {
	sshMgr *SSHManager

	keysFileLocks sync.Map
}

func (u *updaterImpl) updateAuthorizedKeysFile(osUsername string, managedKeys []*SSHKey) error {
	osUser, err := u.sshMgr.sysMgr.GetUserByName(osUsername)
	if err != nil {
		return err
	}
	authorizedKeysFile := u.sshMgr.authorizedKeysFile(osUser)
	log.Info("Auth keys file is " + authorizedKeysFile)

	// We must make sure we are exclusively accessing the authorized_keys file
	keysFileLockRaw, _ := u.keysFileLocks.LoadOrStore(authorizedKeysFile, &sync.Mutex{})
	keysFileLock := keysFileLockRaw.(*sync.Mutex)
	keysFileLock.Lock()
	defer keysFileLock.Unlock()

	dir := filepath.Dir(authorizedKeysFile)
	log.Debug("ensuring dir [%s] exists for user [%s] [%s]", dir, osUser.Name, authorizedKeysFile)
	if err = u.sshMgr.sysMgr.MkDirIfNonExist(dir, osUser, 0700); err != nil {
		return err
	}
	fileExist := true
	localKeysRaw, err := u.sshMgr.sysMgr.ReadFile(authorizedKeysFile)
	if err != nil {
		log.Debug(err.Error())
		if !os.IsNotExist(err) {
			return fmt.Errorf("%w %v", ErrReadAuthorizedKeysFileFailed, err)
		}
		fileExist = false
	}
	localKeys := make([]string, 0)
	if localKeysRaw != nil {
		localKeys = strings.Split(strings.TrimRight(string(localKeysRaw), "\n"), "\n")
	}
	updatedKeys := u.sshMgr.prepareAuthorizedKeys(localKeys, managedKeys)
	if err = u.do(authorizedKeysFile, osUser, updatedKeys, fileExist); err != nil {
		return err
	}
	return nil
}

func (u *updaterImpl) do(authorizedKeysFile string, user *sysutil.User, lines []string, srcFileExist bool) (retErr error) {
	log.Debug("updating [%s]", authorizedKeysFile)
	notSoTmpFile, err := u.sshMgr.sysMgr.CreateFileForWrite(authorizedKeysFile, user, 0600)
	if err != nil {
		return fmt.Errorf("%w: failed to open authorizedKeysFile: %v", ErrWriteAuthorizedKeysFileFailed, err)
	}

	for _, l := range lines {
		_, _ = fmt.Fprintf(notSoTmpFile, "%s\n", l)
	}

	notSoTmpFile.Close()

	return nil
}
