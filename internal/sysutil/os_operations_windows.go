// SPDX-License-Identifier: Apache-2.0

//go:build windows
// +build windows

package sysutil

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func newOSOperator() osOperator {
	return &osOperatorImpl{
		readFileFn: ioutil.ReadFile,
		osStatFn:   os.Stat,
		osMkDir:    os.MkdirAll,
		osChown:    os.Chown,
		osOpenFile: func(name string, flag int, perm os.FileMode) (io.WriteCloser, error) {
			return os.OpenFile(name, flag, perm)
		},
		osRemove: os.Remove,
	}
}

const (
	passwdIdxName    = 0
	passwdIdxUID     = 2
	passwdIdxGID     = 3
	passwdIdxHomeDir = 5
	passwdIdxShell   = 6
)

type osOperatorImpl struct {
	readFileFn func(filename string) ([]byte, error)
	osStatFn   func(name string) (os.FileInfo, error)
	osMkDir    func(path string, perm os.FileMode) error
	osChown    func(name string, uid, gid int) error
	osOpenFile func(name string, flag int, perm os.FileMode) (io.WriteCloser, error)
	osRemove   func(name string) error
}

func (o *osOperatorImpl) getpwnam(username string) (*User, error) {
	return &User{
		Name:    username,
		UID:     0,
		GID:     0,
		HomeDir: "C:/Users/" + username,
		Shell:   "",
	}, nil
}

func (o *osOperatorImpl) mkdir(dir string, user *User, perm os.FileMode) error {
	if _, err := o.osStatFn(dir); err != nil {
		if os.IsNotExist(err) {
			if err = o.osMkDir(dir, perm); err != nil {
				return fmt.Errorf("%w: mkdir failed: %v", ErrMakeDirFailed, err)
			}
		} else {
			return fmt.Errorf("%w: os.Stat failed: %v", ErrMakeDirFailed, err)
		}
	}
	return nil
}

func (o *osOperatorImpl) createFileForWrite(file string, user *User, perm os.FileMode) (io.WriteCloser, error) {
	f, err := o.osOpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return nil, fmt.Errorf("%w: open file failed: %v", ErrCreateFileFailed, err)
	}

	return f, nil
}
