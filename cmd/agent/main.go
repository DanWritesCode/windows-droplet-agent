// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/digitalocean/droplet-agent/internal/config"
	"github.com/digitalocean/droplet-agent/internal/log"
	"github.com/digitalocean/droplet-agent/internal/metadata"
	"github.com/digitalocean/droplet-agent/internal/metadata/actioner"
	"github.com/digitalocean/droplet-agent/internal/metadata/updater"
	"github.com/digitalocean/droplet-agent/internal/metadata/watcher"
	"github.com/digitalocean/droplet-agent/internal/sysaccess"
)

func main() {
	log.Info("Launching %s", config.AppFullName)
	cfg := config.Init()

	log.Info("Config Loaded. Agent Starting (version:%s)", cfg.Version)

	if cfg.DebugMode {
		log.EnableDebug()
		log.Info("Debug mode enabled")
	}
	if cfg.UseSyslog {
		if err := log.UseSysLog(); err != nil {
			log.Error("failed to use syslog, using default logger instead. Error:%v", err)
		}
	}
	sshMgrOpts := []sysaccess.SSHManagerOpt{sysaccess.WithoutManagingDropletKeys()}
	if cfg.CustomSSHDPort != 0 {
		sshMgrOpts = append(sshMgrOpts, sysaccess.WithCustomSSHDPort(cfg.CustomSSHDPort))
	}
	if cfg.CustomSSHDCfgFile != "" {
		sshMgrOpts = append(sshMgrOpts, sysaccess.WithCustomSSHDCfg(cfg.CustomSSHDCfgFile))
	}
	sshMgr, err := sysaccess.NewSSHManager(sshMgrOpts...)
	if err != nil {
		log.Fatal("failed to initialize SSHManager: %v", err)
	}

	doManagedKeysActioner := actioner.NewDOManagedKeysActioner(sshMgr)
	metadataWatcher := newMetadataWatcher(&watcher.Conf{SSHPort: sshMgr.SSHDPort()})
	metadataWatcher.RegisterActioner(doManagedKeysActioner)
	infoUpdater := updater.NewAgentInfoUpdater()

	// monitor sshd_config
	go mustMonitorSSHDConfig(sshMgr)

	// Launch background jobs
	bgJobsCtx, bgJobsCancel := context.WithCancel(context.Background())
	go bgJobsRemoveExpiredDOTTYKeys(bgJobsCtx, sshMgr, cfg.AuthorizedKeysCheckInterval)

	// handle shutdown
	go handleShutdown(bgJobsCancel, metadataWatcher, infoUpdater, sshMgr)

	// report agent status and ssh info
	go updateMetadata(infoUpdater, &metadata.Metadata{
		DOTTYStatus: metadata.RunningStatus,
		SSHInfo:     &metadata.SSHInfo{Port: sshMgr.SSHDPort()},
	}, true)

	// launch the watcher
	if err := metadataWatcher.Run(); err != nil {
		log.Fatal("Failed to run watcher... %v", err)
	} else {
		log.Info("Watcher finished")
	}
}

func handleShutdown(bgJobsCancel context.CancelFunc, metadataWatcher watcher.MetadataWatcher, infoUpdater updater.AgentInfoUpdater, sshMgr *sysaccess.SSHManager) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)

	c := <-signalChan
	updateMetadata(infoUpdater, &metadata.Metadata{DOTTYStatus: metadata.StoppedStatus}, false)
	switch c {
	case syscall.SIGINT, syscall.SIGTERM:
		log.Info("[%s] Shutting down", config.AppShortName)
		bgJobsCancel()
		metadataWatcher.Shutdown()
		_ = sshMgr.Close()
	case syscall.SIGQUIT:
		log.Info("[%s] Forced to quit! You may lose jobs in progress", config.AppShortName)
	default:
		log.Error("unsupported signal, %d", c)
		os.Exit(1)
	}
}

func updateMetadata(infoUpdater updater.AgentInfoUpdater, md *metadata.Metadata, retry bool) {
	fn := func() error { return infoUpdater.Update(md) }
	sleepTime := time.Second * 5

	if !retry {
		err := fn()
		if err != nil {
			log.Error("error updating droplet metadata: %s", err)
		}
		return
	}

	for {
		log.Debug("updating metadata")
		err := fn()
		if err == nil {
			jsonMD, _ := json.Marshal(md)
			log.Info("droplet metadata updated to [%s]", string(jsonMD))
			return
		}

		time.Sleep(sleepTime)
		log.Error("error updating droplet metadata: %s, retrying", err)
	}
}

func mustMonitorSSHDConfig(sshMgr *sysaccess.SSHManager) {
	_, err := sshMgr.WatchSSHDConfig()
	if err != nil {
		log.Fatal("Failed to watch for sshd_config changes. error: %v", err)
	}

}
