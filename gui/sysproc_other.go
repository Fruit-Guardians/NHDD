//go:build !windows

package main

import "syscall"

func hiddenWindowSysProcAttr() *syscall.SysProcAttr {
	return nil
}
