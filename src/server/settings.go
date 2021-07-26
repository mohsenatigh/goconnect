package server

import (
	"encoding/json"
	"goconnect/common"
)

type sSettings struct {
	//
	SSLVpn struct {
		Enable                  bool     `json:"enable"`
		InboundManagement       bool     `json:"inbound_management"`
		Certificate             string   `json:"certificate" validate:"omitempty,max=1024"`
		KeyFile                 string   `json:"key" validate:"omitempty,max=1024"`
		ServerAddress           string   `json:"server_address" validate:"tcp_addr"`
		DPDInterval             uint32   `json:"dpd_interval" validate:"min=1,max=60"`
		NetMask                 string   `json:"net_mask" validate:"ip"`
		SplitTunnels            []string `json:"split_tunnels" validate:"routes"`
		DNSServers              []string `json:"dns_servers" validate:"iplist"`
		UseLocalDNSServer       bool     `json:"use_local_dns_server"`
		TunnelDNS               bool     `json:"tunnel_dns"`
		Debug                   bool     `json:"debug"`
		KeepAliveInterval       uint32   `json:"keepalive_interval" validate:"min=10,max=600"`
		IdelTimeout             uint32   `json:"idle_timeout" validate:"min=600,max=86400"`
		RekeyInterval           uint32   `json:"rekey_interval" validate:"min=180,max=86400"`
		Mtu                     uint32   `json:"mtu" validate:"min=1100,max=1500"`
		InactiveSessionsTimeOut uint32   `json:"inactive_sessions_timeout" validate:"min=10,max=3600"`
	} `json:"sslvpn"`

	//
	TUN struct {
		Name       string   `json:"name" validate:"alphanum,min=4,max=40"`
		IPList     []string `json:"ip_list" validate:"routes"`
		Routes     []string `json:"routes" validate:"routes"`
		Mtu        uint16   `json:"mtu" validate:"min=1100,max=1500"`
		Enable     bool     `json:"enable"`
		UpScript   []string `json:"up_commands"`
		DownScript []string `json:"down_commands"`
	} `json:"tun"`

	//
	IPPool struct {
		Start string `json:"start" validate:"ip"`
		End   string `json:"end" validate:"ip"`
	} `json:"ip_pool"`

	//
	Authentication struct {
		DummyAuthConfigPath string `json:"dummy_auth_config_path" validate:"max=1024"`
		EnableDummyAuth     bool   `json:"enable_dummy"`
	} `json:"authentication"`

	//
	Log struct {
		LogFile string `json:"log_file" validate:"max=1024"`
	} `json:"log"`

	//
	DB struct {
		Driver string `json:"driver" validate:"max=1024"`
		Params string `json:"params" validate:"max=1024"`
	} `json:"db"`

	//
	FlowManager struct {
		HashSlots        uint32 `json:"hash_slots" validate:"min=100,max=10240000"`
		InactiveLifeTime uint32 `json:"inactive_life_time" validate:"min=30,max=4000"`
		MaximumFlowCount uint32 `json:"maximum_flow_count" validate:"min=10000,max=10240000"`
	} `json:"flow_manager"`

	//
	Command struct {
		Enable               bool     `json:"enable"`
		Certificate          string   `json:"certificate" validate:"omitempty,max=1024"`
		KeyFile              string   `json:"key" validate:"omitempty,max=1024"`
		StaticDataPath       string   `json:"static_data" validate:"omitempty,max=1024"`
		ServeStaticContents  bool     `json:"serve_static_contents"`
		BindAddress          string   `json:"bind_address" validate:"omitempty,tcp_addr"`
		ValidClients         []string `json:"valid_clients" validate:"omitempty,iplist"`
		MaintenanceHook      bool     `json:"maintenance_hook"`
		AuthTokenMaxLifeTime uint32   `json:"token_life_time" validate:"min=60,max=3600"`
	} `json:"command"`
}

//---------------------------------------------------------------------------------------

type sSettingsInitparams struct {
	FileName string
	Util     common.IUtils
}

//---------------------------------------------------------------------------------------
type cSettings struct {
	settings sSettings
	params   sSettingsInitparams
}

//---------------------------------------------------------------------------------------

func (thisPt *cSettings) checkSettings() error {
	return thisPt.params.Util.ValidateStruct(thisPt.settings)
}

//---------------------------------------------------------------------------------------

func (thisPt *cSettings) fillDefault() {
	thisPt.settings.Authentication.DummyAuthConfigPath = "/tmp/dummy_auth.bin"

	//flow manager
	thisPt.settings.FlowManager.HashSlots = 64000
	thisPt.settings.FlowManager.InactiveLifeTime = 600
	thisPt.settings.FlowManager.MaximumFlowCount = 512000

	//tun
	thisPt.settings.TUN.Enable = true
	thisPt.settings.TUN.Name = "goconnect"
	thisPt.settings.TUN.Mtu = 1430
	thisPt.settings.TUN.IPList = []string{"172.16.0.1/24"}

	//ssl
	thisPt.settings.SSLVpn.Mtu = 1430
	thisPt.settings.SSLVpn.DPDInterval = 10
	thisPt.settings.SSLVpn.IdelTimeout = 3600
	thisPt.settings.SSLVpn.InactiveSessionsTimeOut = 300
	thisPt.settings.SSLVpn.KeepAliveInterval = 10
	thisPt.settings.SSLVpn.Enable = true
	thisPt.settings.SSLVpn.NetMask = "255.255.255.0"
	thisPt.settings.SSLVpn.ServerAddress = "0.0.0.0:443"
	thisPt.settings.SSLVpn.RekeyInterval = 3600
	thisPt.settings.SSLVpn.TunnelDNS = true
	thisPt.settings.SSLVpn.Debug = false
	thisPt.settings.SSLVpn.InboundManagement = false

	//ippool
	thisPt.settings.IPPool.Start = "172.16.0.2"
	thisPt.settings.IPPool.End = "172.16.0.254"

	//DB
	thisPt.settings.DB.Driver = "sqlite3"
	thisPt.settings.DB.Params = "/var/log/goconnect.db"

	//authentication
	thisPt.settings.Authentication.EnableDummyAuth = true

	//commander
	thisPt.settings.Command.BindAddress = "127.0.0.1:4443"
	thisPt.settings.Command.Certificate = ""
	thisPt.settings.Command.KeyFile = ""
	thisPt.settings.Command.Enable = true
	thisPt.settings.Command.ServeStaticContents = true
	thisPt.settings.Command.StaticDataPath = "ui/"
	thisPt.settings.Command.ValidClients = []string{"127.0.0.1"}
	thisPt.settings.Command.AuthTokenMaxLifeTime = 1800

}

//---------------------------------------------------------------------------------------

func (thisPt *cSettings) getSettings() *sSettings {
	return &thisPt.settings
}

//---------------------------------------------------------------------------------------

func (thisPt *cSettings) init(info sSettingsInitparams) error {

	//
	thisPt.params = info

	//fill default
	thisPt.fillDefault()

	//load base settings
	if len(info.FileName) > 0 {
		data, err := thisPt.params.Util.LoadJsonFile(info.FileName)
		if err != nil {
			return err
		}

		if err = json.Unmarshal([]byte(data), &thisPt.settings); err != nil {
			return err
		}
	}

	if err := thisPt.checkSettings(); err != nil {
		return err
	}

	return nil
}

//---------------------------------------------------------------------------------------
